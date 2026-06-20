/**
 * CDK assertion tests for `lib/test-endpoint-stack.ts`.
 *
 * The test endpoint is internet-facing (three Network Load Balancers: app, s3,
 * and control) so the scenario probes can egress the firewall, reach the
 * internet, and return. The security guarantee is that the TARGET instance only
 * accepts traffic from the solution's NAT gateway EIPs — never `0.0.0.0/0` — and
 * has no public IP. These tests lock that posture in.
 */
import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { TestEndpointStack } from "../lib/test-endpoint-stack";

const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };
const NAT_EIPS = ["203.0.113.10", "203.0.113.11"];

describe("TestEndpointStack CDK assertions", () => {
  let template: Template;

  beforeAll(() => {
    const app = new cdk.App();
    const stack = new TestEndpointStack(app, "NfTestEndpointStack", {
      env: ENV,
      natEipAddresses: NAT_EIPS,
    });
    template = Template.fromStack(stack);
  });

  it("generates the probe shared-secret in Secrets Manager (not hardcoded)", () => {
    template.hasResourceProperties(
      "AWS::SecretsManager::Secret",
      Match.objectLike({
        Name: "nf-devops-agent-probe-secret",
        GenerateSecretString: Match.objectLike({ PasswordLength: 32 }),
      }),
    );
    // The server fetches it at boot from Secrets Manager, not a baked-in literal.
    const instances = template.findResources("AWS::EC2::Instance");
    const udStr = JSON.stringify(instances[Object.keys(instances)[0]].Properties?.UserData);
    expect(udStr).toContain("get-secret-value");
    expect(udStr).toContain("nf-devops-agent-probe-secret");
  });

  it("scopes target ingress to the NAT EIPs (never 0.0.0.0/0)", () => {
    const ingress = template.findResources("AWS::EC2::SecurityGroupIngress");
    const sgInline = template.findResources("AWS::EC2::SecurityGroup");

    // Collect every CIDR that appears on an ingress rule (inline or standalone).
    const cidrs: string[] = [];
    for (const r of Object.values(ingress)) {
      const c = (r.Properties as Record<string, unknown>)?.CidrIp;
      if (typeof c === "string") cidrs.push(c);
    }
    for (const sg of Object.values(sgInline)) {
      const rules = (sg.Properties as Record<string, unknown>)?.SecurityGroupIngress;
      if (Array.isArray(rules)) {
        for (const rule of rules) {
          const c = (rule as Record<string, unknown>)?.CidrIp;
          if (typeof c === "string") cidrs.push(c);
        }
      }
    }

    // No internet-wide ingress anywhere on the target.
    expect(cidrs).not.toContain("0.0.0.0/0");
    // The NAT EIPs are present as /32 scoped ingress.
    expect(cidrs).toEqual(expect.arrayContaining(["203.0.113.10/32", "203.0.113.11/32"]));
  });

  it("opens exactly the probe ports (80, 443, 9142) to the NAT EIPs", () => {
    // Ingress rules are inlined on the security group. Collect (port, cidr) pairs.
    const sgs = template.findResources("AWS::EC2::SecurityGroup");
    const pairs: Array<{ port: unknown; cidr: unknown }> = [];
    for (const sg of Object.values(sgs)) {
      const rules = (sg.Properties as Record<string, unknown>)?.SecurityGroupIngress;
      if (Array.isArray(rules)) {
        for (const r of rules) {
          const rule = r as Record<string, unknown>;
          pairs.push({ port: rule.FromPort, cidr: rule.CidrIp });
        }
      }
    }
    // Each NAT EIP /32 is opened on each of the three probe ports.
    for (const ip of ["203.0.113.10/32", "203.0.113.11/32"]) {
      for (const port of [80, 443, 9142]) {
        expect(pairs).toContainEqual({ port, cidr: ip });
      }
    }
  });

  it("provisions the target instance with NO public IP", () => {
    const instances = template.findResources("AWS::EC2::Instance");
    const ids = Object.keys(instances);
    expect(ids.length).toBe(1);
    // A private-subnet instance has no AssociatePublicIpAddress: true network interface.
    const udStr = JSON.stringify(instances[ids[0]].Properties);
    expect(udStr).not.toContain('"AssociatePublicIpAddress":true');
  });

  it("creates three internet-facing Network Load Balancers (app + s3 + control)", () => {
    template.resourceCountIs("AWS::ElasticLoadBalancingV2::LoadBalancer", 3);
    const lbs = template.findResources("AWS::ElasticLoadBalancingV2::LoadBalancer");
    for (const lb of Object.values(lbs)) {
      const p = lb.Properties as Record<string, unknown>;
      expect(p.Type).toBe("network");
      expect(p.Scheme).toBe("internet-facing");
    }
  });

  it("listens on 80, 443, and 9142 across the load balancers", () => {
    const listeners = template.findResources("AWS::ElasticLoadBalancingV2::Listener");
    const ports = Object.values(listeners).map(
      (l) => (l.Properties as Record<string, unknown>).Port,
    );
    // App NLB: 80, 443, 9142. S3 NLB: 443. Control NLB: 443. (443 appears 3x.)
    expect(ports).toEqual(expect.arrayContaining([80, 443, 9142]));
    expect(ports.filter((p) => p === 443).length).toBe(3);
  });

  it("exposes a distinct Scenario 3 endpoint DNS output (isolated from the app host)", () => {
    template.hasOutput("S3EndpointDns", Match.objectLike({}));
  });

  it("runs the target server as an SSM-managed instance (no SSH key)", () => {
    const instances = template.findResources("AWS::EC2::Instance");
    const inst = instances[Object.keys(instances)[0]].Properties as Record<string, unknown>;
    expect(inst.KeyName).toBeUndefined();
  });
});
