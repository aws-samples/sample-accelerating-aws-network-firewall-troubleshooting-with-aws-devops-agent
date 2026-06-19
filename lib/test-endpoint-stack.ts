/**
 * TestEndpointStack — a self-contained, internet-facing test endpoint the
 * scenario probes target, so the sample depends on NO external/real domains.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Why this exists
 * ────────────────────────────────────────────────────────────────────────────
 * The three break-fix scenarios each need a probe target that is reachable at
 * baseline and only fails when the firewall drops it. Previously those targets
 * were real public AWS endpoints (a documentation domain, the Amazon Keyspaces
 * TLS endpoint on 9142, etc.). This stack replaces them with endpoints THIS
 * deployment creates, so:
 *   - nothing is hardcoded: the probe + the firewall SNI rule both reference the
 *     deploy-generated Network Load Balancer DNS name (a CloudFormation token),
 *     so there is no literal domain string anywhere; and
 *   - the demo runs against live, self-owned URLs.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Topology (a SECOND, isolated VPC — 10.1.0.0/16)
 * ────────────────────────────────────────────────────────────────────────────
 *   - 2 public subnets (the NLBs live here), 2 private subnets (the target
 *     instance lives here, no public IP), an IGW, and one NAT gateway so the
 *     private instance can reach SSM / package mirrors at boot.
 *   - NLB-A ("app" endpoint): internet-facing, TCP listeners on 80, 443, 9142.
 *     Scenarios 1 (HTTPS SNI), 2 (raw TCP 9142), and 3 (HTTPS) all target this.
 *   - NLB-B ("control" endpoint): internet-facing, TCP listener on 443 only. The
 *     page-only control probe targets this. It is a SEPARATE hostname so the
 *     Scenario 1 SNI drop (which matches the app endpoint's DNS name) never
 *     takes the control probe down.
 *   - 1 target instance behind both NLBs running a tiny stdlib server: HTTPS on
 *     443 (self-signed), HTTP on 80, a raw TCP accept on 9142, and `/healthz`.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Security posture (no internet-wide exposure)
 * ────────────────────────────────────────────────────────────────────────────
 * Network Load Balancers preserve the client source IP, and all probe traffic
 * leaves the main VPC through its two NAT gateway Elastic IPs. The target
 * instance security group therefore allows 80/443/9142 ONLY from those two NAT
 * EIPs (/32) — not `0.0.0.0/0`. So although the NLBs are internet-facing
 * (required for the traffic to egress the firewall, hit the internet, and return),
 * nothing on the internet other than this solution's egress IPs can get a
 * response. As defence in depth the HTTPS server also requires a shared-secret
 * header that only the probes send. The instance has no public IP and is
 * SSM-managed, matching the main workload's posture.
 */
import * as cdk from "aws-cdk-lib";
import { Tags } from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as elbtargets from "aws-cdk-lib/aws-elasticloadbalancingv2-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";

export const PROJECT_TAG_KEY = "Project";
export const PROJECT_TAG_VALUE = "nf-devops-agent";

/**
 * Secrets Manager secret holding the probe shared-secret (the `X-Probe-Secret`
 * header value). Randomly generated at deploy — never hardcoded. The test
 * endpoint server, the workload health-check daemon, and the verify CLI all read
 * it by this name at runtime so they agree without a predictable literal.
 */
export const PROBE_SECRET_NAME = "nf-devops-agent-probe-secret";

/** Ports the test endpoint serves. 443 = HTTPS SNI (S1/S3), 9142 = raw TCP (S2), 80 = HTTP. */
const PORT_HTTP = 80;
const PORT_HTTPS = 443;
const PORT_TCP9142 = 9142;

/** Props for {@link TestEndpointStack}. */
export interface TestEndpointStackProps extends cdk.StackProps {
  /**
   * The main VPC's NAT gateway public IPs. The target instance security group
   * is scoped to exactly these /32 addresses, so only this solution's egress can
   * reach the endpoint.
   */
  readonly natEipAddresses: string[];
}

/**
 * The internet-facing test endpoint. Exposes the two NLB DNS names so the
 * firewall stack (SNI rule) and the workload stack (probes) can reference them
 * as tokens — no literal domain anywhere.
 */
export class TestEndpointStack extends cdk.Stack {
  /** DNS name of the "app" NLB (Scenarios 1/2/3 target this). */
  public readonly appEndpointDns: string;
  /** DNS name of the "control" NLB (the page-only control probe targets this). */
  public readonly controlEndpointDns: string;

  constructor(scope: Construct, id: string, props: TestEndpointStackProps) {
    super(scope, id, props);

    if (!props.natEipAddresses || props.natEipAddresses.length === 0) {
      throw new Error("TestEndpointStack requires at least one NAT EIP to scope ingress to.");
    }

    // ── Isolated VPC (10.1.0.0/16): public subnets for the NLBs, private for the
    //    target instance, one NAT gateway so the private instance can reach SSM. ──
    const vpc = new ec2.Vpc(this, "TestEndpointVpc", {
      ipAddresses: ec2.IpAddresses.cidr("10.1.0.0/16"),
      maxAzs: 2,
      natGateways: 1,
      subnetConfiguration: [
        { name: "public", subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
        { name: "private", subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS, cidrMask: 24 },
      ],
    });

    // ── Target instance security group: ingress ONLY from the solution's NAT
    //    EIPs on 80/443/9142. No 0.0.0.0/0. ──
    const targetSg = new ec2.SecurityGroup(this, "TargetSg", {
      vpc,
      description: "Test endpoint target: ingress only from the solution NAT gateway EIPs",
      allowAllOutbound: true,
    });
    for (const ip of props.natEipAddresses) {
      for (const port of [PORT_HTTP, PORT_HTTPS, PORT_TCP9142]) {
        targetSg.addIngressRule(
          ec2.Peer.ipv4(`${ip}/32`),
          ec2.Port.tcp(port),
          `Probe traffic from solution NAT EIP on ${port}`,
        );
      }
    }
    // NLB health checks originate from within the endpoint VPC subnets; allow the
    // VPC CIDR on the same ports so the target health checks pass.
    for (const port of [PORT_HTTP, PORT_HTTPS, PORT_TCP9142]) {
      targetSg.addIngressRule(
        ec2.Peer.ipv4(vpc.vpcCidrBlock),
        ec2.Port.tcp(port),
        `NLB health checks (in-VPC) on ${port}`,
      );
    }

    // ── Probe shared-secret: randomly generated into Secrets Manager at deploy
    //    (never hardcoded). The server fetches it at boot. ──
    const probeSecret = new secretsmanager.Secret(this, "ProbeSecret", {
      secretName: PROBE_SECRET_NAME,
      description: "Shared secret for the test endpoint probe header (generated at deploy).",
      generateSecretString: {
        passwordLength: 32,
        excludePunctuation: true,
        requireEachIncludedType: false,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ── Target instance: SSM-managed, no public IP, runs the tiny server. ──
    const role = new iam.Role(this, "TargetRole", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      description: "SSM-managed role for the test endpoint target instance",
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore"),
      ],
    });
    // The server reads the probe secret from Secrets Manager at boot.
    probeSecret.grantRead(role);

    const userData = ec2.UserData.forLinux();
    userData.addCommands(...this.buildServerUserData(cdk.Stack.of(this).region));

    const instance = new ec2.Instance(this, "TargetInstance", {
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      securityGroup: targetSg,
      role,
      userData,
      requireImdsv2: true,
    });

    const instanceTarget = new elbtargets.InstanceTarget(instance);

    // ── NLB-A ("app"): listeners on 80, 443, 9142 ──
    const appNlb = new elbv2.NetworkLoadBalancer(this, "AppNlb", {
      vpc,
      internetFacing: true,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
    });
    this.addTcpListener(appNlb, "App80", PORT_HTTP, instanceTarget, vpc);
    this.addTcpListener(appNlb, "App443", PORT_HTTPS, instanceTarget, vpc);
    this.addTcpListener(appNlb, "App9142", PORT_TCP9142, instanceTarget, vpc);

    // ── NLB-B ("control"): listener on 443 only ──
    const controlNlb = new elbv2.NetworkLoadBalancer(this, "ControlNlb", {
      vpc,
      internetFacing: true,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
    });
    this.addTcpListener(controlNlb, "Control443", PORT_HTTPS, instanceTarget, vpc);

    this.appEndpointDns = appNlb.loadBalancerDnsName;
    this.controlEndpointDns = controlNlb.loadBalancerDnsName;

    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);

    new cdk.CfnOutput(this, "AppEndpointDns", {
      value: this.appEndpointDns,
      description: "Test endpoint (app) NLB DNS name — Scenario 1/2/3 probe target",
    });
    new cdk.CfnOutput(this, "ControlEndpointDns", {
      value: this.controlEndpointDns,
      description: "Test endpoint (control) NLB DNS name — page-only control probe target",
    });
  }

  /**
   * Add a TCP listener forwarding to the instance on the same port. Health
   * checks run against the plain HTTP port (80, path `/healthz`) rather than the
   * listener port: a bare-TCP health probe against the HTTPS (443) port never
   * completes the TLS handshake and would stall the server's SSL accept loop, and
   * a TCP probe against 9142 is fine but using one consistent HTTP health check
   * keeps target health meaningful (the server is up iff 80/healthz answers).
   */
  private addTcpListener(
    nlb: elbv2.NetworkLoadBalancer,
    id: string,
    port: number,
    target: elbtargets.InstanceTarget,
    vpc: ec2.IVpc,
  ): void {
    nlb.addListener(`${id}Listener`, {
      port,
      protocol: elbv2.Protocol.TCP,
      defaultTargetGroups: [
        new elbv2.NetworkTargetGroup(this, `${id}Tg`, {
          vpc,
          port,
          protocol: elbv2.Protocol.TCP,
          targets: [target],
          healthCheck: {
            protocol: elbv2.Protocol.HTTP,
            port: String(PORT_HTTP),
            path: "/healthz",
            healthyHttpCodes: "200",
          },
          deregistrationDelay: cdk.Duration.seconds(10),
        }),
      ],
    });
  }

  /**
   * Build the target server: a single Python stdlib process that serves HTTPS on
   * 443 (self-signed cert generated at boot), HTTP on 80, a raw TCP accept on
   * 9142, and `/healthz`. The HTTPS handler requires the shared-secret header
   * (X-Probe-Secret) for non-health paths. The secret is read at boot from
   * Secrets Manager into a 0600 file the server reads — never hardcoded.
   */
  private buildServerUserData(region: string): string[] {
    const server = `#!/usr/bin/env python3
import http.server, ssl, socket, threading
CERT = "/opt/testsrv/cert.pem"
KEY = "/opt/testsrv/key.pem"
SECRET_FILE = "/opt/testsrv/secret"
try:
    with open(SECRET_FILE) as f:
        SECRET = f.read().strip()
except Exception:
    SECRET = ""

class H(http.server.BaseHTTPRequestHandler):
    def _ok(self, body=b"ok"):
        self.send_response(200); self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length",str(len(body))); self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == "/healthz":
            return self._ok(b"healthy")
        # Non-health paths require the shared secret (defence in depth).
        if not SECRET or self.headers.get("X-Probe-Secret") != SECRET:
            self.send_response(403); self.end_headers(); return
        self._ok(b"test-endpoint")
    def log_message(self, *a):
        pass

def serve_http(port, tls):
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    httpd.serve_forever()

def serve_tcp9142():
    # Raw TCP accept loop: a connection that completes the handshake is enough
    # for the Scenario 2 probe (it only measures connect success vs timeout).
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 9142)); s.listen(128)
    while True:
        try:
            c, _ = s.accept(); c.close()
        except Exception:
            pass

threading.Thread(target=serve_http, args=(80, False), daemon=True).start()
threading.Thread(target=serve_tcp9142, daemon=True).start()
serve_http(443, True)
`;
    const b64 = Buffer.from(server, "utf8").toString("base64");
    return [
      "set -euxo pipefail",
      "mkdir -p /opt/testsrv",
      // Self-signed cert (the probes use curl -k; the firewall inspects SNI
      // regardless of cert validity, and we only measure connect vs timeout).
      'openssl req -x509 -newkey rsa:2048 -nodes -keyout /opt/testsrv/key.pem ' +
        '-out /opt/testsrv/cert.pem -days 365 -subj "/CN=test-endpoint" >/dev/null 2>&1',
      // Fetch the probe shared-secret from Secrets Manager into a 0600 file
      // (generated at deploy, never hardcoded). Retried in case the role/secret
      // is not ready yet; systemd restarts the server until the file is present.
      "for i in 1 2 3 4 5 6; do " +
        `S=$(aws secretsmanager get-secret-value --secret-id ${PROBE_SECRET_NAME} --region ${region} --query SecretString --output text 2>/dev/null || true); ` +
        'if [ -n "$S" ]; then printf "%s" "$S" > /opt/testsrv/secret; break; fi; sleep 5; done',
      "chmod 600 /opt/testsrv/secret || true",
      `echo ${b64} | base64 -d > /opt/testsrv/server.py`,
      "cat > /etc/systemd/system/testsrv.service <<'UNIT'\n" +
        "[Unit]\nDescription=NF sample test endpoint server\nAfter=network-online.target\nWants=network-online.target\n\n" +
        "[Service]\nExecStart=/usr/bin/python3 /opt/testsrv/server.py\nRestart=always\nRestartSec=5\n\n" +
        "[Install]\nWantedBy=multi-user.target\nUNIT",
      "systemctl daemon-reload",
      "systemctl enable --now testsrv.service",
    ];
  }
}
