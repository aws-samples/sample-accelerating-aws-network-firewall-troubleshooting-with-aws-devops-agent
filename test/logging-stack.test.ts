/**
 * CDK assertion tests for `lib/logging-stack.ts` (task 8.2).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * The `LoggingStack` does NOT require the whole firewall stack — it takes the
 * firewall ARN (and an optional firewall name + resolved scenario context) as
 * props. These tests therefore construct the stack directly with a literal
 * firewall ARN and a pinned environment for determinism, then synthesize
 * `Template.fromStack(logging)`.
 *
 * Two destinations are exercised:
 *   - Default (cloudwatch, R2.5): both log types target the two SEPARATE
 *     CloudWatch log groups `/nf-devops-agent/alert` (ALERT only, R2.1)
 *     and `/nf-devops-agent/flow` (FLOW only, separate group, R2.2).
 *   - S3 (R2.6): both log types target the always-provisioned bucket (R2.4)
 *     with `alert`/`flow` prefixes instead.
 *
 * The S3 bucket is ALWAYS provisioned (R2.4) regardless of the active
 * destination, with `autoDeleteObjects: true` + `RemovalPolicy.DESTROY` so the
 * teardown sweep removes it cleanly.
 *
 * Validates: Requirements 2.1 (dedicated ALERT log group), 2.2 (separate FLOW
 * log group), 2.4 (S3 bucket always provisioned with auto-delete + DESTROY),
 * and 2.6 (S3 destination delivers both log types to the bucket).
 */

import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { LoggingStack } from "../lib/logging-stack";
import { ScenarioContext, baseline, toContext } from "../src/scenarioctl/state";

/** A pinned environment so synthesis is deterministic. */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

/** A literal firewall ARN — the logging config only needs the ARN, not the stack. */
const FIREWALL_ARN =
  "arn:aws:network-firewall:us-east-1:123456789012:firewall/nf-devops-agent";

/** The fixed log group names the stack provisions. */
const ALERT_LOG_GROUP_NAME = "/nf-devops-agent/alert";
const FLOW_LOG_GROUP_NAME = "/nf-devops-agent/flow";

/** Build an app + logging stack for a resolved scenario context and synthesize it. */
function templateFor(ctx: ScenarioContext): Template {
  const app = new cdk.App();
  const logging = new LoggingStack(app, "TestLoggingStack", {
    env: ENV,
    firewallArn: FIREWALL_ARN,
    firewallName: "nf-devops-agent",
    scenarioContext: ctx,
  });
  return Template.fromStack(logging);
}

/** A single synthesized logging destination config (PascalCase, as it appears in CFN). */
interface SynthLogDestinationConfig {
  LogType: string;
  LogDestinationType: string;
  // The inner `LogDestination` map keys pass through verbatim (logGroup/bucketName/prefix).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  LogDestination: Record<string, any>;
}

/**
 * Extract the single `LoggingConfiguration`'s `LogDestinationConfigs` array from
 * a synthesized template (robust to the logical id CDK assigns the resource).
 */
function logDestinationConfigsOf(template: Template): SynthLogDestinationConfig[] {
  const resources = template.findResources("AWS::NetworkFirewall::LoggingConfiguration");
  const keys = Object.keys(resources);
  if (keys.length !== 1) {
    throw new Error(`Expected exactly one LoggingConfiguration, found ${keys.length}`);
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const props = resources[keys[0]].Properties as any;
  return props.LoggingConfiguration.LogDestinationConfigs as SynthLogDestinationConfig[];
}

describe("LoggingStack CDK assertions — default cloudwatch destination (R2.1/R2.2/R2.4/R2.5)", () => {
  let template: Template;

  beforeAll(() => {
    template = templateFor(toContext(baseline()));
  });

  it("creates exactly two distinct CloudWatch log groups (R2.1 ALERT, R2.2 FLOW)", () => {
    template.resourceCountIs("AWS::Logs::LogGroup", 2);
    // The two groups are named distinctly: one dedicated to ALERT, one to FLOW.
    template.hasResourceProperties("AWS::Logs::LogGroup", {
      LogGroupName: ALERT_LOG_GROUP_NAME,
    });
    template.hasResourceProperties("AWS::Logs::LogGroup", {
      LogGroupName: FLOW_LOG_GROUP_NAME,
    });
  });

  it("provisions exactly one S3 bucket that is destroyed on teardown (R2.4)", () => {
    template.resourceCountIs("AWS::S3::Bucket", 1);
    // autoDeleteObjects + RemovalPolicy.DESTROY render as Delete on the
    // top-level DeletionPolicy / UpdateReplacePolicy of the bucket resource.
    template.hasResource("AWS::S3::Bucket", {
      DeletionPolicy: "Delete",
      UpdateReplacePolicy: "Delete",
    });
    // autoDeleteObjects also wires the custom resource that empties the bucket.
    template.resourceCountIs("Custom::S3AutoDeleteObjects", 1);
  });

  it("targets BOTH log types at the matching CloudWatch log groups by default (R2.5)", () => {
    const configs = logDestinationConfigsOf(template);
    // Exactly two entries: one ALERT, one FLOW.
    expect(configs).toHaveLength(2);

    template.hasResourceProperties("AWS::NetworkFirewall::LoggingConfiguration", {
      FirewallArn: FIREWALL_ARN,
      LoggingConfiguration: Match.objectLike({
        LogDestinationConfigs: Match.arrayWith([
          Match.objectLike({
            LogType: "ALERT",
            LogDestinationType: "CloudWatchLogs",
            LogDestination: Match.objectLike({ logGroup: ALERT_LOG_GROUP_NAME }),
          }),
          Match.objectLike({
            LogType: "FLOW",
            LogDestinationType: "CloudWatchLogs",
            LogDestination: Match.objectLike({ logGroup: FLOW_LOG_GROUP_NAME }),
          }),
        ]),
      }),
    });

    // No S3 destination is wired when cloudwatch is active.
    expect(configs.every((c) => c.LogDestinationType === "CloudWatchLogs")).toBe(true);
  });
});

describe("LoggingStack CDK assertions — S3 destination (R2.4/R2.6)", () => {
  let template: Template;

  beforeAll(() => {
    // Take the baseline context and flip only the log destination to S3.
    template = templateFor({ ...toContext(baseline()), logDestination: "s3" });
  });

  it("still provisions the two log groups and the one S3 bucket (R2.4)", () => {
    // The bucket is ALWAYS provisioned; the log groups exist regardless of the
    // active destination so the operator can switch without redeploying.
    template.resourceCountIs("AWS::Logs::LogGroup", 2);
    template.resourceCountIs("AWS::S3::Bucket", 1);
    template.hasResource("AWS::S3::Bucket", {
      DeletionPolicy: "Delete",
      UpdateReplacePolicy: "Delete",
    });
  });

  it("delivers BOTH log types to the S3 bucket with alert/flow prefixes (R2.6)", () => {
    const configs = logDestinationConfigsOf(template);
    expect(configs).toHaveLength(2);

    template.hasResourceProperties("AWS::NetworkFirewall::LoggingConfiguration", {
      FirewallArn: FIREWALL_ARN,
      LoggingConfiguration: Match.objectLike({
        LogDestinationConfigs: Match.arrayWith([
          Match.objectLike({
            LogType: "ALERT",
            LogDestinationType: "S3",
            LogDestination: Match.objectLike({ prefix: "alert" }),
          }),
          Match.objectLike({
            LogType: "FLOW",
            LogDestinationType: "S3",
            LogDestination: Match.objectLike({ prefix: "flow" }),
          }),
        ]),
      }),
    });

    // Both entries target S3 (not CloudWatch) and reference the bucket by name.
    expect(configs.every((c) => c.LogDestinationType === "S3")).toBe(true);
    expect(configs.every((c) => "bucketName" in c.LogDestination)).toBe(true);
  });
});
