/**
 * Least-privilege DevOps Agent IAM policy builder (pure, side-effect-free).
 *
 * Ported from the now-deleted Python `scenarioctl/policy.py` with its semantics
 * preserved (see PORTING-NOTES.md section 2). The builder emits a plain AWS
 * Identity and Access Management (IAM)
 * policy document; the `agent-iam` stack maps each statement into an
 * `iam.PolicyStatement`, so the document under property-based test is exactly
 * what is attached to the `Agent_IAM_Role`.
 *
 * Least-privilege contract (R4): every emitted `Action` is drawn from the same
 * literal tuples that compose {@link ALLOWED_ACTIONS}, so the builder can never
 * emit an action wildcard (`"*"`, `service:*`) or any mutating verb (R4.4,
 * R4.6). The only wildcard the builder emits is a *resource* wildcard on the AWS
 * Network Firewall list statement, which R4.6 permits.
 */

import { LogDestination } from "./state";

/** IAM policy document version pinned by the design. */
const POLICY_VERSION = "2012-10-17" as const;

/**
 * AWS Network Firewall describe actions, scoped to this deployment's firewall,
 * policy, and rule-group ARNs (R4.1).
 */
const NF_DESCRIBE_ACTIONS = [
  "network-firewall:DescribeFirewall",
  "network-firewall:DescribeFirewallPolicy",
  "network-firewall:DescribeRuleGroup",
] as const;

/**
 * AWS Network Firewall list actions. These are not resource-scopable, so the
 * statement is constrained to exactly these three actions on resource `"*"`
 * (R4.2).
 */
const NF_LIST_ACTIONS = [
  "network-firewall:ListFirewalls",
  "network-firewall:ListFirewallPolicies",
  "network-firewall:ListRuleGroups",
] as const;

/** Amazon CloudWatch Logs read actions, scoped to the alert/flow log groups (R4.3). */
const LOGS_READ_ACTIONS = ["logs:GetLogEvents", "logs:FilterLogEvents"] as const;

/** Amazon Simple Storage Service (Amazon S3) read actions, granted only when the log destination is S3 (R4.5). */
const S3_READ_ACTIONS = ["s3:GetObject", "s3:ListBucket"] as const;

/**
 * The exact, complete allowlist of actions the Agent role may be granted: the
 * union of the four enumerated action groups above. Every `Action` emitted by
 * {@link buildAgentPolicy} is a literal member of this set (R4.6).
 */
export const ALLOWED_ACTIONS: ReadonlySet<string> = new Set<string>([
  ...NF_DESCRIBE_ACTIONS,
  ...NF_LIST_ACTIONS,
  ...LOGS_READ_ACTIONS,
  ...S3_READ_ACTIONS,
]);

/** Resource ARNs and configuration that scope the generated policy document. */
export interface PolicyInputs {
  /** ARN of the deployment's `Network_Firewall`. */
  readonly firewallArn: string;
  /** ARN of the deployment's `Firewall_Policy`. */
  readonly policyArn: string;
  /** ARNs of the deployment's stateless + stateful rule groups. */
  readonly ruleGroupArns: readonly string[];
  /** ARN of the CloudWatch Logs group receiving Network Firewall alert logs. */
  readonly alertLogGroupArn: string;
  /** ARN of the CloudWatch Logs group receiving Network Firewall flow logs. */
  readonly flowLogGroupArn: string;
  /** Active log destination; controls whether the S3 read statement is emitted. */
  readonly logDestination: LogDestination;
  /** ARN of the S3 log bucket; required (non-empty) when `logDestination === "s3"`. */
  readonly s3BucketArn: string | null;
}

/** A single IAM statement. `Sid` is preserved from the ported Python document. */
export interface PolicyStatementJson {
  readonly Sid?: string;
  readonly Effect: "Allow";
  readonly Action: readonly string[];
  readonly Resource: readonly string[];
}

/** A complete IAM policy document. */
export interface PolicyDocumentJson {
  readonly Version: "2012-10-17";
  readonly Statement: readonly PolicyStatementJson[];
}

/**
 * Resource list for a log-group statement: the group ARN itself and its
 * `:log-stream:*` so the read actions cover the group's streams (R4.3).
 */
function logGroupResources(logGroupArn: string): string[] {
  return [logGroupArn, `${logGroupArn}:log-stream:*`];
}

/**
 * Build the least-privilege Agent IAM policy document from a deployment's
 * resource ARNs.
 *
 * Always emits three statements (NF describe, NF list, CloudWatch Logs read) and
 * adds a fourth S3 read statement only when `logDestination === "s3"`. Every
 * `Action` is drawn from the literal tuples that compose {@link ALLOWED_ACTIONS},
 * so no action wildcard or mutating verb can be emitted (R4.4, R4.6).
 *
 * @throws if `logDestination` is not `"cloudwatch"` or `"s3"`.
 * @throws if `logDestination === "s3"` but `s3BucketArn` is missing or empty.
 */
export function buildAgentPolicy(inputs: PolicyInputs): PolicyDocumentJson {
  if (inputs.logDestination !== "cloudwatch" && inputs.logDestination !== "s3") {
    throw new Error(`Unknown logDestination: ${String(inputs.logDestination)}`);
  }

  const statements: PolicyStatementJson[] = [
    {
      Sid: "NetworkFirewallDescribe",
      Effect: "Allow",
      Action: [...NF_DESCRIBE_ACTIONS],
      Resource: [inputs.firewallArn, inputs.policyArn, ...inputs.ruleGroupArns],
    },
    {
      Sid: "NetworkFirewallList",
      Effect: "Allow",
      Action: [...NF_LIST_ACTIONS],
      // Acknowledged exception (R4.6): AWS Network Firewall List* actions are not
      // resource-scopable per the AWS API, so Resource must be "*". This is a
      // resource wildcard, not an action wildcard — the actions are read-only
      // List* operations, and Describe* above is scoped to the specific firewall,
      // policy, and rule-group ARNs. Documented in SECURITY.md.
      Resource: ["*"],
    },
    {
      Sid: "CloudWatchLogsRead",
      Effect: "Allow",
      Action: [...LOGS_READ_ACTIONS],
      Resource: [
        ...logGroupResources(inputs.alertLogGroupArn),
        ...logGroupResources(inputs.flowLogGroupArn),
      ],
    },
  ];

  if (inputs.logDestination === "s3") {
    if (!inputs.s3BucketArn) {
      throw new Error(
        's3BucketArn is required when logDestination === "s3"',
      );
    }
    statements.push({
      Sid: "S3LogDestinationRead",
      Effect: "Allow",
      Action: [...S3_READ_ACTIONS],
      Resource: [inputs.s3BucketArn, `${inputs.s3BucketArn}/*`],
    });
  }

  return {
    Version: POLICY_VERSION,
    Statement: statements,
  };
}
