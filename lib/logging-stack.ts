/**
 * LoggingStack — the AWS Network Firewall logging configuration plus its two
 * log destinations (Requirement 2).
 *
 * Network Firewall emits two log types — ALERT and FLOW — and this stack wires
 * both to an Amazon CloudWatch Logs destination by default, or to an Amazon
 * Simple Storage Service (Amazon S3) bucket when the
 * `logDestination` context value is `s3`. Per the design's "Logging design":
 *
 *   - Two SEPARATE CloudWatch log groups: `/nf-devops-agent/alert` (ALERT
 *     only, R2.1) and `/nf-devops-agent/flow` (FLOW only, separate group,
 *     R2.2).
 *   - One S3 bucket ALWAYS provisioned (R2.4) regardless of the active
 *     destination, so the agent-iam stack (task 10) can scope S3 read access and
 *     the operator can switch destinations without redeploying new buckets.
 *   - A `CfnLoggingConfiguration` (L1 — Network Firewall has no L2 construct)
 *     associated with the firewall by ARN, carrying TWO `logDestinationConfigs`
 *     entries (one ALERT, one FLOW). When `logDestination === "cloudwatch"`
 *     (the default, R2.5) both target the matching log group; when
 *     `logDestination === "s3"` both target the bucket with `alert`/`flow`
 *     prefixes instead (R2.6).
 *
 * R2.3 (alert log entries identify the matched rule group/rule id and the
 * 5-tuple — src/dst IP, src/dst port, protocol) needs NO code here: that schema
 * is inherent to the Network Firewall ALERT log format, so enabling ALERT
 * logging (the ALERT `logDestinationConfigs` entry below) is sufficient.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Requires the FirewallStack.
 * ────────────────────────────────────────────────────────────────────────────
 * The `CfnLoggingConfiguration` must reference the firewall by ARN, so this
 * stack takes `firewallArn` (and optionally `firewallName`) as props rather than
 * the whole firewall stack, for testability — its test (task 8.2) constructs
 * network + firewall + logging in one app and passes the firewall ARN in. The
 * only cross-stack dependency direction is logging -> firewall.
 *
 * Downstream consumer: the agent-iam stack (task 10) reads `alertLogGroupArn`,
 * `flowLogGroupArn`, and `bucketArn` (the last only when `logDestination === "s3"`)
 * to build the least-privilege read policy; `bin/app.ts` (task 12) also surfaces
 * the log group names/ARNs as stack outputs (R1.4).
 */
import * as cdk from "aws-cdk-lib";
import { RemovalPolicy, Tags } from "aws-cdk-lib";
import * as logs from "aws-cdk-lib/aws-logs";
import * as networkfirewall from "aws-cdk-lib/aws-networkfirewall";
import * as s3 from "aws-cdk-lib/aws-s3";
import { Construct } from "constructs";

import { PROJECT_TAG_KEY, PROJECT_TAG_VALUE } from "./network-stack";
import { LogDestination, ScenarioContext } from "../src/scenarioctl/state";

/**
 * Fixed CloudWatch log group names for this sample (single deployment per
 * account/region). Distinct prefixes keep ALERT and FLOW in separate groups
 * (R2.1/R2.2) and let the `CfnLoggingConfiguration` reference each group by a
 * deterministic name rather than a synth-time token.
 */
const ALERT_LOG_GROUP_NAME = "/nf-devops-agent/alert";
const FLOW_LOG_GROUP_NAME = "/nf-devops-agent/flow";

/** S3 key prefixes used only when `logDestination === "s3"` (R2.6). */
const ALERT_S3_PREFIX = "alert";
const FLOW_S3_PREFIX = "flow";

/**
 * Props for {@link LoggingStack}. Accepts the firewall ARN (required by the
 * logging configuration) directly rather than the whole firewall stack, plus
 * the resolved scenario context. When `scenarioContext` is omitted the stack
 * falls back to reading `logDestination` from CDK context (default
 * `cloudwatch`).
 */
export interface LoggingStackProps extends cdk.StackProps {
  /** The firewall ARN (from `firewall.firewallArn`) the logging config associates with. */
  readonly firewallArn: string;
  /** The firewall's name (from `firewall.firewallName`). Optional — for the logging config's `firewallName`. */
  readonly firewallName?: string;
  /** Resolved scenario context (from `state.ts` `toContext`). Optional — falls back to CDK context. */
  readonly scenarioContext?: ScenarioContext;
}

/**
 * Resolve the active log destination: prefer the resolved prop, fall back to CDK
 * context, then default `cloudwatch`. Only `s3` (string-equality tolerant)
 * selects S3; every other value is treated as `cloudwatch` (R2.5).
 */
function resolveLogDestination(value: unknown): LogDestination {
  return value === "s3" ? "s3" : "cloudwatch";
}

/**
 * The Network Firewall logging stack. Exposes the two log groups, their ARNs,
 * the S3 bucket, the bucket ARN, and the resolved log destination that the
 * agent-iam stack (task 10) and the app outputs (task 12) consume.
 */
export class LoggingStack extends cdk.Stack {
  /** The ALERT-only CloudWatch log group (R2.1). */
  public readonly alertLogGroup: logs.LogGroup;
  /** The FLOW-only CloudWatch log group, separate from ALERT (R2.2). */
  public readonly flowLogGroup: logs.LogGroup;
  /** The ALERT log group ARN (for the agent-iam read policy). */
  public readonly alertLogGroupArn: string;
  /** The FLOW log group ARN (for the agent-iam read policy). */
  public readonly flowLogGroupArn: string;
  /** The always-provisioned S3 log destination bucket (R2.4). */
  public readonly bucket: s3.Bucket;
  /** The S3 log destination bucket ARN (for the agent-iam read policy when `logDestination === "s3"`). */
  public readonly bucketArn: string;
  /** The resolved active log destination (`cloudwatch` default / `s3`). */
  public readonly logDestination: LogDestination;
  /** The L1 logging configuration associated with the firewall. */
  public readonly loggingConfiguration: networkfirewall.CfnLoggingConfiguration;

  constructor(scope: Construct, id: string, props: LoggingStackProps) {
    super(scope, id, props);

    // ── Resolve the active log destination (prop first, then context, then default) ──
    const ctx = props.scenarioContext;
    this.logDestination = resolveLogDestination(
      ctx?.logDestination ?? this.node.tryGetContext("logDestination"),
    );

    // ── Two SEPARATE CloudWatch log groups (R2.1 ALERT, R2.2 FLOW) ──
    // Short retention + DESTROY removal so teardown (R10) sweeps them cleanly.
    this.alertLogGroup = new logs.LogGroup(this, "AlertLogGroup", {
      logGroupName: ALERT_LOG_GROUP_NAME,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    this.flowLogGroup = new logs.LogGroup(this, "FlowLogGroup", {
      logGroupName: FLOW_LOG_GROUP_NAME,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // ── S3 log destination, ALWAYS provisioned (R2.4) ──
    // autoDeleteObjects + DESTROY so teardown removes it even with log objects
    // present (R10.1); public access fully blocked and TLS enforced.
    //
    // Encryption: this sample uses Amazon S3-managed keys (SSE-S3), which keeps
    // Network Firewall S3 log delivery and the auto-delete helper working with
    // no extra key policy. For production, prefer a customer-managed AWS KMS key
    // (BucketEncryption.KMS) for an auditable key trail — note that you must then
    // grant the Network Firewall delivery service and any readers kms:GenerateDataKey
    // / kms:Decrypt on that key. See SECURITY.md.
    this.bucket = new s3.Bucket(this, "LogBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      autoDeleteObjects: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // ── CfnLoggingConfiguration (L1) — one ALERT entry + one FLOW entry ──
    // CloudWatch (default, R2.5): each entry targets its matching log group by
    // name. S3 (R2.6): each entry targets the bucket with an alert/flow prefix.
    const isS3 = this.logDestination === "s3";
    const alertDestinationConfig: networkfirewall.CfnLoggingConfiguration.LogDestinationConfigProperty = isS3
      ? {
          logType: "ALERT",
          logDestinationType: "S3",
          logDestination: { bucketName: this.bucket.bucketName, prefix: ALERT_S3_PREFIX },
        }
      : {
          logType: "ALERT",
          logDestinationType: "CloudWatchLogs",
          logDestination: { logGroup: ALERT_LOG_GROUP_NAME },
        };
    const flowDestinationConfig: networkfirewall.CfnLoggingConfiguration.LogDestinationConfigProperty = isS3
      ? {
          logType: "FLOW",
          logDestinationType: "S3",
          logDestination: { bucketName: this.bucket.bucketName, prefix: FLOW_S3_PREFIX },
        }
      : {
          logType: "FLOW",
          logDestinationType: "CloudWatchLogs",
          logDestination: { logGroup: FLOW_LOG_GROUP_NAME },
        };

    this.loggingConfiguration = new networkfirewall.CfnLoggingConfiguration(this, "LoggingConfiguration", {
      firewallArn: props.firewallArn,
      ...(props.firewallName ? { firewallName: props.firewallName } : {}),
      loggingConfiguration: {
        logDestinationConfigs: [alertDestinationConfig, flowDestinationConfig],
      },
    });

    // The logging configuration references the destinations by fixed name (not a
    // token), so add explicit dependencies on the active destination(s) to keep
    // AWS CloudFormation's create order correct.
    if (isS3) {
      this.loggingConfiguration.node.addDependency(this.bucket);
    } else {
      this.loggingConfiguration.node.addDependency(this.alertLogGroup);
      this.loggingConfiguration.node.addDependency(this.flowLogGroup);
    }

    // ── Exported props ──
    this.alertLogGroupArn = this.alertLogGroup.logGroupArn;
    this.flowLogGroupArn = this.flowLogGroup.logGroupArn;
    this.bucketArn = this.bucket.bucketArn;

    // Tag every resource in the stack for the teardown sweep (Requirement 10).
    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);
  }
}
