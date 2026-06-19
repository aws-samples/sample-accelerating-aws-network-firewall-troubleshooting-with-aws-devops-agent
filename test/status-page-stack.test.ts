/**
 * CDK assertion tests for `lib/status-page-stack.ts` (Task 8 — live status page).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These tests synthesize the `StatusPageStack` (which consumes the VPC + public
 * subnets from a `NetworkStack` and the workload instance + its security group
 * from a `WorkloadStack`, all constructed in the same app) and assert the
 * public status-page posture:
 *   - exactly one internet-facing Application Load Balancer,
 *   - an HTTP :80 listener forwarding to a target group on the status-page port,
 *   - an ALB security group allowing inbound :80, and
 *   - the cross-stack `SecurityGroupIngress` that opens the WORKLOAD security
 *     group to the ALB security group on the status-page port (created in THIS
 *     stack so no dependency cycle forms).
 *
 * It also confirms the whole multi-stack app still synthesizes with the new
 * stack wired in (no cyclic dependency).
 */
import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { NetworkStack } from "../lib/network-stack";
import { WorkloadStack, STATUS_PAGE_PORT } from "../lib/workload-stack";
import { StatusPageStack } from "../lib/status-page-stack";

/** A pinned environment so VPC AZ selection is deterministic during synth. */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

function buildStatusPage() {
  const app = new cdk.App();
  const network = new NetworkStack(app, "TestNetwork", { env: ENV });
  const workload = new WorkloadStack(app, "TestWorkload", {
    env: ENV,
    vpc: network.vpc,
    protectedSubnet: network.protectedSubnets[0],
    firewallName: "nf-devops-agent",
  });
  const statusPage = new StatusPageStack(app, "TestStatusPage", {
    env: ENV,
    vpc: network.vpc,
    publicSubnets: network.publicSubnets,
    workloadInstance: workload.instance,
    workloadSecurityGroup: workload.securityGroup,
    allowedCidr: "0.0.0.0/0",
  });
  return { app, network, workload, statusPage };
}

describe("StatusPageStack CDK assertions", () => {
  let template: Template;

  beforeAll(() => {
    template = Template.fromStack(buildStatusPage().statusPage);
  });

  it("provisions exactly one internet-facing Application Load Balancer", () => {
    template.resourceCountIs("AWS::ElasticLoadBalancingV2::LoadBalancer", 1);
    template.hasResourceProperties(
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
      Match.objectLike({ Scheme: "internet-facing", Type: "application" }),
    );
  });

  it("adds an HTTP :80 listener", () => {
    template.hasResourceProperties(
      "AWS::ElasticLoadBalancingV2::Listener",
      Match.objectLike({ Port: 80, Protocol: "HTTP" }),
    );
  });

  it("targets the workload on the status-page port with a /healthz health check", () => {
    template.hasResourceProperties(
      "AWS::ElasticLoadBalancingV2::TargetGroup",
      Match.objectLike({
        Port: STATUS_PAGE_PORT,
        Protocol: "HTTP",
        HealthCheckPath: "/healthz",
      }),
    );
  });

  it("restricts the ALB security group inbound HTTP :80 to the CloudFront prefix list (not the open internet)", () => {
    // The ALB SG ingress on tcp/80 is sourced from the Amazon CloudFront
    // origin-facing managed prefix list, so the ALB is not reachable directly
    // from 0.0.0.0/0. (Browsers reach the page over the HTTPS CloudFront URL.)
    // CDK renders a prefix-list source as a standalone SecurityGroupIngress.
    template.hasResourceProperties(
      "AWS::EC2::SecurityGroupIngress",
      Match.objectLike({ FromPort: 80, ToPort: 80, IpProtocol: "tcp", SourcePrefixListId: "pl-3b927c52" }),
    );
    // Nothing may allow 0.0.0.0/0 on port 80, inline or standalone.
    const inlineSgs = template.findResources("AWS::EC2::SecurityGroup");
    for (const sg of Object.values(inlineSgs)) {
      const ingress = (sg as { Properties?: { SecurityGroupIngress?: Array<Record<string, unknown>> } })
        .Properties?.SecurityGroupIngress ?? [];
      for (const rule of ingress) {
        if (rule.FromPort === 80 && rule.CidrIp === "0.0.0.0/0") {
          throw new Error("ALB SG must not allow 0.0.0.0/0 on port 80 (inline)");
        }
      }
    }
    const standaloneIngress = template.findResources("AWS::EC2::SecurityGroupIngress");
    for (const ing of Object.values(standaloneIngress)) {
      const p = (ing as { Properties?: Record<string, unknown> }).Properties ?? {};
      if (p.FromPort === 80 && p.CidrIp === "0.0.0.0/0") {
        throw new Error("ALB SG must not allow 0.0.0.0/0 on port 80 (standalone)");
      }
    }
  });

  it("opens the workload SG to the ALB SG on the status-page port (standalone ingress, no cycle)", () => {
    // The cross-stack rule is a standalone SecurityGroupIngress referencing the
    // ALB SG as the source on the status-page port.
    template.hasResourceProperties(
      "AWS::EC2::SecurityGroupIngress",
      Match.objectLike({
        IpProtocol: "tcp",
        FromPort: STATUS_PAGE_PORT,
        ToPort: STATUS_PAGE_PORT,
        SourceSecurityGroupId: Match.anyValue(),
      }),
    );
  });

  it("fronts the ALB with a CloudFront distribution that redirects viewers to HTTPS", () => {
    template.resourceCountIs("AWS::CloudFront::Distribution", 1);
    template.hasResourceProperties(
      "AWS::CloudFront::Distribution",
      Match.objectLike({
        DistributionConfig: Match.objectLike({
          DefaultCacheBehavior: Match.objectLike({
            ViewerProtocolPolicy: "redirect-to-https",
          }),
        }),
      }),
    );
  });

  it("the full multi-stack app synthesizes with the status-page stack wired in (no cyclic dependency)", () => {
    const { app } = buildStatusPage();
    // synth() throws if a cross-stack dependency cycle exists.
    expect(() => app.synth()).not.toThrow();
  });
});
