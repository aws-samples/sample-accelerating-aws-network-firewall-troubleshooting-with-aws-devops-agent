/**
 * CDK assertion tests for `lib/workload-stack.ts` (task 11.2).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These tests synthesize the `WorkloadStack` (which consumes the VPC and a
 * protected subnet from a `NetworkStack` constructed in the same app) and assert
 * the SSM-only reachability posture of the single EC2 test workload:
 *   - exactly one EC2 instance,
 *   - NO SSH key pair (`KeyName` absent),
 *   - NO public IP (no EIP, no `AssociatePublicIpAddress: true`),
 *   - the instance role carries the `AmazonSSMManagedInstanceCore` managed
 *     policy (the SSM-agent baseline), and
 *   - an egress-only security group (allow-all egress, NO ingress).
 *
 * Validates: Requirements 1.1 (the test workload placed in the protected subnet)
 * and 9.4 (the workload stays reachable via SSM so the verify probe can run even
 * while firewall egress is deliberately broken — which requires the SSM role and
 * the egress-only / no-public-IP / no-key-pair posture).
 */

import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { readFileSync } from "fs";
import { join as pathJoin } from "path";
import { NetworkStack } from "../lib/network-stack";
import {
  WorkloadStack,
  WORKLOAD_METRIC_NAMESPACE,
  SCENARIO_METRICS,
  STATUS_PAGE_PORT,
} from "../lib/workload-stack";

/** A pinned environment so VPC AZ selection is deterministic during synth. */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

describe("WorkloadStack CDK assertions", () => {
  let template: Template;

  beforeAll(() => {
    const app = new cdk.App();
    // The workload stack only depends on the network stack (workload -> network).
    const network = new NetworkStack(app, "TestNetwork", { env: ENV });
    const workload = new WorkloadStack(app, "TestWorkload", {
      env: ENV,
      vpc: network.vpc,
      protectedSubnet: network.protectedSubnets[0],
      firewallName: "nf-devops-agent",
    });
    template = Template.fromStack(workload);
  });

  it("synthesizes exactly one EC2 instance", () => {
    template.resourceCountIs("AWS::EC2::Instance", 1);
  });

  it("provisions the instance with NO SSH key pair (SSM-only access)", () => {
    // The instance must be reachable only via SSM — assert KeyName is absent.
    template.hasResourceProperties(
      "AWS::EC2::Instance",
      Match.objectLike({ KeyName: Match.absent() })
    );
  });

  it("provisions the instance with NO public IP", () => {
    // The protected subnet is isolated, so there is no Elastic IP...
    template.resourceCountIs("AWS::EC2::EIP", 0);

    // ...and the instance/launch never associates a public IP. Inspect the
    // instance resource(s) and assert no NetworkInterface opts into a public IP.
    const instances = template.findResources("AWS::EC2::Instance");
    for (const id of Object.keys(instances)) {
      const props = instances[id].Properties ?? {};
      // Top-level associate flag must not be true.
      expect(props.AssociatePublicIpAddress).not.toBe(true);
      // Nor on any inline network interface.
      const nics: Array<Record<string, unknown>> = props.NetworkInterfaces ?? [];
      for (const nic of nics) {
        expect(nic.AssociatePublicIpAddress).not.toBe(true);
      }
    }
  });

  it("attaches the AmazonSSMManagedInstanceCore managed policy to the instance role", () => {
    // Find the IAM role(s) and assert one carries the SSM-agent baseline policy.
    // ManagedPolicyArns synthesizes as a Fn::Join referencing the AWS-managed
    // policy ".../iam::aws:policy/AmazonSSMManagedInstanceCore".
    const roles = template.findResources("AWS::IAM::Role");
    const ssmRoles = Object.keys(roles).filter((id) => {
      const managed = roles[id].Properties?.ManagedPolicyArns;
      return (
        managed !== undefined &&
        JSON.stringify(managed).includes("AmazonSSMManagedInstanceCore")
      );
    });
    expect(ssmRoles.length).toBeGreaterThanOrEqual(1);

    // The role must be assumable by EC2 (the instance profile principal).
    const ssmRoleProps = roles[ssmRoles[0]].Properties;
    expect(JSON.stringify(ssmRoleProps.AssumeRolePolicyDocument)).toContain(
      "ec2.amazonaws.com"
    );
  });

  it("creates a single egress-only security group (allow-all egress, NO ingress)", () => {
    // The workload security group permits all outbound (SSM 443 to the interface
    // endpoints + probe egress through the firewall) and has NO inbound rules.
    const sgs = template.findResources("AWS::EC2::SecurityGroup");
    expect(Object.keys(sgs).length).toBe(1);

    const sgProps = sgs[Object.keys(sgs)[0]].Properties ?? {};
    // Egress present (the allow-all-outbound default rule).
    expect(sgProps.SecurityGroupEgress).toBeDefined();
    const egress = JSON.stringify(sgProps.SecurityGroupEgress);
    expect(egress).toContain("0.0.0.0/0");

    // No ingress: the property is either absent or an empty array.
    const ingress = sgProps.SecurityGroupIngress;
    if (ingress !== undefined) {
      expect(Array.isArray(ingress)).toBe(true);
      expect(ingress).toHaveLength(0);
    }
  });

  it("asserts the egress-only posture via Match (no ingress on the SG)", () => {
    // Stronger Match-based assertion: a security group exists with egress rules
    // present and no ingress rules property at all.
    template.hasResourceProperties(
      "AWS::EC2::SecurityGroup",
      Match.objectLike({
        SecurityGroupEgress: Match.anyValue(),
        SecurityGroupIngress: Match.absent(),
      })
    );
  });

  it("grants the instance role a scoped cloudwatch:PutMetricData (NfAgent/Workload namespace only)", () => {
    // The inline policy that backs `instanceRole.addToPolicy(...)` synthesizes as
    // an AWS::IAM::Policy. Find the one whose document allows PutMetricData and
    // constrains it to the workload namespace via StringEquals on
    // cloudwatch:namespace.
    const policies = template.findResources("AWS::IAM::Policy");
    const scoped = Object.keys(policies).filter((id) => {
      const doc = JSON.stringify(
        policies[id].Properties?.PolicyDocument ?? {}
      );
      return (
        doc.includes("cloudwatch:PutMetricData") &&
        doc.includes("StringEquals") &&
        doc.includes("cloudwatch:namespace") &&
        doc.includes(WORKLOAD_METRIC_NAMESPACE)
      );
    });
    expect(scoped.length).toBeGreaterThanOrEqual(1);

    // Belt-and-suspenders: assert the concrete namespace value too.
    const scopedDoc = JSON.stringify(
      policies[scoped[0]].Properties.PolicyDocument
    );
    expect(scopedDoc).toContain("cloudwatch:PutMetricData");
    expect(scopedDoc).toContain("NfAgent/Workload");
    expect(scopedDoc).toContain(WORKLOAD_METRIC_NAMESPACE);
  });

  it("grants the instance role a scoped cloudwatch:DescribeAlarms (Alarm-* only)", () => {
    // The daemon reads the live alarm state each cycle so the page mirrors what
    // DevOps Agent sees; that needs DescribeAlarms scoped to the scenario alarms.
    const policies = template.findResources("AWS::IAM::Policy");
    const scoped = Object.keys(policies).filter((id) => {
      const doc = JSON.stringify(policies[id].Properties?.PolicyDocument ?? {});
      return doc.includes("cloudwatch:DescribeAlarms") && doc.includes("Alarm-*");
    });
    expect(scoped.length).toBeGreaterThanOrEqual(1);
  });

  it("drives the page from the live alarm state (reads DescribeAlarms each cycle)", () => {
    const instances = template.findResources("AWS::EC2::Instance");
    const ids = Object.keys(instances);
    const udStr = JSON.stringify(instances[ids[0]].Properties?.UserData);

    // The daemon reads the three scenario alarms and renders the cards from that
    // state (so a fix applied any way clears the page), not the raw probe.
    expect(udStr).toContain("describe-alarms");
    expect(udStr).toContain("read_alarm_states");
    expect(udStr).toContain("Alarm-1");
    expect(udStr).toContain("Alarm-2");
    expect(udStr).toContain("Alarm-3");
  });

  it("grants the instance role scoped secretsmanager write to the webhook-credentials secret", () => {
    // The webhook-config form writes the DevOps Agent webhook URL + secret into
    // Secrets Manager; the role needs Put/Get/Describe scoped to that secret.
    const policies = template.findResources("AWS::IAM::Policy");
    const scoped = Object.keys(policies).filter((id) => {
      const doc = JSON.stringify(policies[id].Properties?.PolicyDocument ?? {});
      return (
        doc.includes("secretsmanager:PutSecretValue") &&
        doc.includes("secretsmanager:GetSecretValue") &&
        doc.includes("nf-devops-agent-webhook-credentials")
      );
    });
    expect(scoped.length).toBeGreaterThanOrEqual(1);
  });

  it("generates a status server with a login form session auth and a webhook-config endpoint", () => {
    const assetPath = pathJoin(__dirname, "..", "assets", "status-page", "statuspage.py");
    const page = readFileSync(assetPath, "utf8");
    // Styled login form + signed session cookie (no basic-auth popup) + the
    // /config form + the Secrets Manager write path.
    expect(page).toContain("def render_login");
    expect(page).toContain("nfsession");
    expect(page).toContain('action="/login"');
    expect(page).toContain("def render_config");
    expect(page).toContain("def write_webhook_secret");
    expect(page).toContain("put-secret-value");
    expect(page).toContain("/healthz"); // still unauthenticated for the ALB
    // The old browser basic-auth popup must be gone.
    expect(page).not.toContain("WWW-Authenticate");
  });

  it("writes the status-server config (auth creds + webhook secret name) in UserData", () => {
    const instances = template.findResources("AWS::EC2::Instance");
    const ids = Object.keys(instances);
    const udStr = JSON.stringify(instances[ids[0]].Properties?.UserData);
    expect(udStr).toContain("/opt/nf-agent/config.json");
  });

  it("provisions a generated status-page login password in Secrets Manager (not hard-coded)", () => {
    // The login password is randomly generated into Secrets Manager at deploy,
    // never baked into user data or emitted as a plaintext output.
    template.hasResourceProperties(
      "AWS::SecretsManager::Secret",
      Match.objectLike({
        Name: "nf-devops-agent-statuspage-login",
        GenerateSecretString: Match.objectLike({ PasswordLength: 20 }),
      }),
    );
    // No plaintext password is fetched into config.json in user data anymore;
    // the server reads it from Secrets Manager at runtime instead.
    const instances = template.findResources("AWS::EC2::Instance");
    const udStr = JSON.stringify(instances[Object.keys(instances)[0]].Properties?.UserData);
    expect(udStr).not.toContain("jq --arg p");
  });

  it("reads the status-page login password from Secrets Manager at runtime (not from disk)", () => {
    // The status server fetches the password into memory at startup via the AWS
    // CLI and never persists it to the local config file.
    const assetPath = pathJoin(__dirname, "..", "assets", "status-page", "statuspage.py");
    const page = readFileSync(assetPath, "utf8");
    expect(page).toContain("_fetch_login_password");
    expect(page).toContain("LOGIN_PASSWORD");
    expect(page).toContain("statusPageSecretName");
    // The password is never read from or written to the on-disk config file.
    expect(page).not.toContain('c.get("password"');
  });

  it("installs the health-check daemon via instance UserData", () => {
    // Linux UserData renders as { "Fn::Base64": "<script>" } where the inner
    // value may be a plain string or an Fn::Join of strings/tokens. Stringifying
    // the whole UserData object is robust to either shape.
    const instances = template.findResources("AWS::EC2::Instance");
    const ids = Object.keys(instances);
    expect(ids.length).toBe(1);

    const ud = instances[ids[0]].Properties?.UserData;
    expect(ud).toBeDefined();
    const udStr = JSON.stringify(ud);

    // The systemd unit name + the metric publish command + the namespace.
    expect(udStr).toContain("nf-agent-healthcheck");
    expect(udStr).toContain("put-metric-data");
    expect(udStr).toContain("NfAgent/Workload");
  });

  it("UserData is consistent with the exported namespace and scenario metric names", () => {
    const instances = template.findResources("AWS::EC2::Instance");
    const ids = Object.keys(instances);
    const udStr = JSON.stringify(instances[ids[0]].Properties?.UserData);

    // The namespace export must appear verbatim in the rendered script.
    expect(udStr).toContain(WORKLOAD_METRIC_NAMESPACE);

    // Every per-scenario metric name the daemon publishes must appear.
    for (const metricName of Object.values(SCENARIO_METRICS)) {
      expect(udStr).toContain(metricName);
    }
    // Explicit sanity check on the three known names.
    expect(udStr).toContain("DomainReachabilityFailures");
    expect(udStr).toContain("StatelessRuleFailures");
    expect(udStr).toContain("AsymmetricFlowFailures");
  });

  it("installs the status-page web server + its systemd unit via UserData", () => {
    const instances = template.findResources("AWS::EC2::Instance");
    const ids = Object.keys(instances);
    const udStr = JSON.stringify(instances[ids[0]].Properties?.UserData);

    // The status-page server + AWS icons are too large to inline, so they ship
    // as a CDK S3 asset that user data downloads and unzips into /opt/nf-agent.
    // User data therefore references the systemd unit + the downloaded server
    // path and the status JSON, but not the page body itself.
    expect(udStr).toContain("nf-agent-statuspage");
    expect(udStr).toContain("/opt/nf-agent/statuspage.py");
    expect(udStr).toContain("/opt/nf-agent/status.json");
    // It downloads + unzips the status-page asset.
    expect(udStr).toContain("/tmp/nf-status-page.zip");
    expect(udStr).toContain("unzip");
  });

  it("generates the status-page server asset with the topology + port + icons", () => {
    // The generated asset file (written at synth time) holds the page server,
    // including the listen port, the egress-path topology, and the AWS icon
    // module import.
    const assetPath = pathJoin(__dirname, "..", "assets", "status-page", "statuspage.py");
    const page = readFileSync(assetPath, "utf8");
    expect(page).toContain(String(STATUS_PAGE_PORT));
    expect(page).toContain("VPC egress path");
    expect(page).toContain("import nf_icons");
  });

  it("includes a control probe and collateral-aware status fields in UserData", () => {
    const instances = template.findResources("AWS::EC2::Instance");
    const ids = Object.keys(instances);
    const udStr = JSON.stringify(instances[ids[0]].Properties?.UserData);

    // The control probe (page-only, no metric) and the control_failing flag the
    // status page uses to distinguish a subnet-wide outage from an isolated
    // per-scenario rule failure must both appear in the rendered user data.
    expect(udStr).toContain("probe_control");
    expect(udStr).toContain("control_failing");
    // The control probe must NOT publish a CloudWatch metric (it calls
    // probe_control, which has no put_metric call), so there is no fourth metric
    // name beyond the three scenario metrics.
    expect(udStr).toContain("CONTROL_URL");
  });
});
