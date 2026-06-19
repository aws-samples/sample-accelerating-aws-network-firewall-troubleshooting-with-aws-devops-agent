/**
 * CDK assertion tests for `lib/network-stack.ts` (task 6.2).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These tests synthesize the `NetworkStack` in isolation (it references no other
 * stack — see the CHICKEN-AND-EGG CONTRACT in `network-stack.ts`) and assert the
 * `Sample_VPC`, its three subnet tiers across two AZs, the two NAT gateways, the
 * internet gateway, and the SSM interface endpoints appear in the synthesized
 * CloudFormation template as expected.
 *
 * Validates: Requirements 1.1 (VPC + firewall/protected subnets + route tables)
 * and 1.5 (egress routed through the firewall: the protected tier is ISOLATED
 * with no `0.0.0.0/0` route, the firewall tier egresses via NAT, the public tier
 * via the IGW — the routing fabric the firewall stack completes).
 */

import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { NetworkStack } from "../lib/network-stack";
import { baseline, desired, toContext } from "../src/scenarioctl/state";

/** A pinned environment so VPC AZ selection is deterministic during synth. */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

describe("NetworkStack CDK assertions", () => {
  let template: Template;

  beforeAll(() => {
    const app = new cdk.App();
    const stack = new NetworkStack(app, "TestNetworkStack", {
      env: ENV,
      scenarioContext: toContext(baseline()),
    });
    template = Template.fromStack(stack);
  });

  it("synthesizes exactly one VPC with the 10.0.0.0/16 CIDR", () => {
    template.resourceCountIs("AWS::EC2::VPC", 1);
    template.hasResourceProperties("AWS::EC2::VPC", {
      CidrBlock: "10.0.0.0/16",
    });
  });

  it("synthesizes eight subnets — public/firewall/protected/alb across two AZs", () => {
    // Four tiers across two AZs: public, firewall, protected, and the dedicated
    // out-of-band ALB tier (added so the status-page ALB bypasses the firewall
    // return route).
    template.resourceCountIs("AWS::EC2::Subnet", 8);
  });

  it("synthesizes two NAT gateways (one per AZ)", () => {
    template.resourceCountIs("AWS::EC2::NatGateway", 2);
  });

  it("synthesizes a single internet gateway", () => {
    template.resourceCountIs("AWS::EC2::InternetGateway", 1);
  });

  it("routes the public tier to the IGW and the firewall tier to a NAT gateway (R1.5 fabric)", () => {
    // Public subnets: default route -> internet gateway.
    template.hasResourceProperties("AWS::EC2::Route", {
      DestinationCidrBlock: "0.0.0.0/0",
      GatewayId: Match.anyValue(),
    });
    // Firewall subnets (PRIVATE_WITH_EGRESS): default route -> NAT gateway.
    template.hasResourceProperties("AWS::EC2::Route", {
      DestinationCidrBlock: "0.0.0.0/0",
      NatGatewayId: Match.anyValue(),
    });
  });

  it("leaves the protected tier without a 0.0.0.0/0 route so egress must traverse the firewall (R1.5)", () => {
    // The protected subnets are PRIVATE_ISOLATED: the network stack deliberately
    // omits their default route (the firewall stack adds 0.0.0.0/0 -> NF
    // endpoint). The public, firewall, AND the dedicated ALB tier (all 2 AZs)
    // each own a default route here, so there are exactly six 0.0.0.0/0 routes
    // at this stage (the protected tier still has none).
    const defaultRoutes = template.findResources("AWS::EC2::Route", {
      Properties: { DestinationCidrBlock: "0.0.0.0/0" },
    });
    expect(Object.keys(defaultRoutes)).toHaveLength(6);
  });

  it("synthesizes the SSM interface endpoints plus the CloudWatch monitoring endpoint", () => {
    const interfaceEndpoints = template.findResources("AWS::EC2::VPCEndpoint", {
      Properties: { VpcEndpointType: "Interface" },
    });
    const endpointNames = Object.keys(interfaceEndpoints);
    // At least four interface endpoints exist (ssm, ssmmessages, ec2messages,
    // and monitoring)...
    expect(endpointNames.length).toBeGreaterThanOrEqual(4);

    // ...covering ssm, ssmmessages, ec2messages, and monitoring. The ServiceName
    // is a Fn::Join token of the form ".../com.amazonaws.<region>.<suffix>";
    // assert each expected suffix appears in some endpoint's ServiceName join
    // parts. The monitoring endpoint keeps the daemon's PutMetricData path up
    // even when a scenario drops all firewall egress (Scenario 3).
    const serviceBlobs = endpointNames.map((name) =>
      JSON.stringify(interfaceEndpoints[name].Properties.ServiceName)
    );
    for (const suffix of [".ssm", ".ssmmessages", ".ec2messages", ".monitoring"]) {
      expect(serviceBlobs.some((blob) => blob.includes(suffix))).toBe(true);
    }
  });

  it("places the interface endpoints' service names with the three SSM suffixes via Match", () => {
    // Stronger per-service assertion: each expected SSM service has an Interface
    // endpoint whose ServiceName resolves to the matching AWS service name. With
    // a pinned env the ServiceName synthesizes to a literal string rather than a
    // Fn::Join token.
    for (const suffix of ["ssm", "ssmmessages", "ec2messages"]) {
      template.hasResourceProperties(
        "AWS::EC2::VPCEndpoint",
        Match.objectLike({
          VpcEndpointType: "Interface",
          ServiceName: `com.amazonaws.us-east-1.${suffix}`,
        })
      );
    }
  });
});

describe("NetworkStack CDK assertions — Scenario 3 (asymmetricRoute) context", () => {
  it("synthesizes the same resource counts under the asymmetricRoute context", () => {
    // The routing flip for Scenario 3 is consumed by the firewall stack (it only
    // changes which AZ's firewall endpoint the protected egress route targets,
    // and those routes are added downstream). The network stack template should
    // therefore be unaffected in its resource counts.
    const app = new cdk.App();
    const stack = new NetworkStack(app, "TestNetworkStackAsymmetric", {
      env: ENV,
      scenarioContext: toContext(desired("3")),
    });
    const template = Template.fromStack(stack);

    template.resourceCountIs("AWS::EC2::VPC", 1);
    template.resourceCountIs("AWS::EC2::Subnet", 8);
    template.resourceCountIs("AWS::EC2::NatGateway", 2);
    template.resourceCountIs("AWS::EC2::InternetGateway", 1);

    const interfaceEndpoints = template.findResources("AWS::EC2::VPCEndpoint", {
      Properties: { VpcEndpointType: "Interface" },
    });
    expect(Object.keys(interfaceEndpoints).length).toBeGreaterThanOrEqual(3);

    // Confirm the stack records the asymmetric routing contract (Scenario 3).
    expect(stack.asymmetricRoute).toBe(true);
  });
});
