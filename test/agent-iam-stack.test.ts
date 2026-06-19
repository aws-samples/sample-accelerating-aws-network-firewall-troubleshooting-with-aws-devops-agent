/**
 * CDK assertion tests for `lib/agent-iam-stack.ts` (task 10.2).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * The `AgentIamStack` does NOT require the whole firewall/logging stacks — it
 * takes literal resource ARNs plus the active `logDestination` (and an optional
 * `s3BucketArn`) as props. These tests therefore construct the stack directly
 * with synthetic ARNs and a pinned environment for determinism, synthesize the
 * single `AWS::IAM::Policy` resource, and read its `PolicyDocument.Statement`
 * array directly so the assertions are robust to the logical ids CDK assigns.
 *
 * The stack maps each statement returned by the property-tested
 * {@link buildAgentPolicy} 1:1 into an `iam.PolicyStatement`, so the synthesized
 * document is exactly the least-privilege document those PBTs validate. These
 * assertions re-confirm the least-privilege contract at the *synthesized CFN*
 * layer:
 *   - No action wildcard anywhere (`"*"` or `service:*`) (R4.6).
 *   - The resource-`"*"` statement carries ONLY the three NF list actions —
 *     a resource wildcard, which R4.6 permits, never an action wildcard (R4.6).
 *   - No S3 action when `logDestination === "cloudwatch"`; the S3 read actions
 *     scoped to the bucket appear ONLY under `logDestination === "s3"` (R4.5).
 *   - Every emitted action is a member of the exported `ALLOWED_ACTIONS` set.
 *
 * Validates: Requirements 4.5 (S3 read actions only under the S3 destination,
 * scoped to the bucket) and 4.6 (no wildcard action grant; resource wildcard
 * only on the NF list actions).
 */

import * as cdk from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { AgentIamStack } from "../lib/agent-iam-stack";
import { ALLOWED_ACTIONS } from "../src/scenarioctl/policy";
import { LogDestination } from "../src/scenarioctl/state";

/** A pinned environment so synthesis is deterministic. */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

// ── Synthetic ARNs for this deployment (no live resources needed) ──
const FIREWALL_ARN =
  "arn:aws:network-firewall:us-east-1:123456789012:firewall/test";
const POLICY_ARN =
  "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/test";
const RULE_GROUP_ARNS = [
  "arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/rg1",
  "arn:aws:network-firewall:us-east-1:123456789012:stateless-rulegroup/rg2",
];
const ALERT_LOG_GROUP_ARN =
  "arn:aws:logs:us-east-1:123456789012:log-group:/nf-devops-agent/alert";
const FLOW_LOG_GROUP_ARN =
  "arn:aws:logs:us-east-1:123456789012:log-group:/nf-devops-agent/flow";
const S3_BUCKET_ARN = "arn:aws:s3:::nf-agent-logs";

/** The three NF list actions allowed on the resource-`"*"` statement (R4.2/R4.6). */
const NF_LIST_ACTIONS = [
  "network-firewall:ListFirewalls",
  "network-firewall:ListFirewallPolicies",
  "network-firewall:ListRuleGroups",
];

/** A synthesized IAM statement (PascalCase, as it appears in the CFN PolicyDocument). */
interface SynthStatement {
  Sid?: string;
  Effect: string;
  Action: string | string[];
  Resource: string | string[];
}

/** Normalize a string-or-array field into an array (Action/Resource may render either way). */
function toArray(value: string | string[] | undefined): string[] {
  if (value === undefined) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

/** Matches a service-scoped action wildcard like `network-firewall:*` or `s3:*`. */
const SERVICE_ACTION_WILDCARD = /^[a-z0-9-]+:\*$/;

/**
 * Synthesize an `AgentIamStack` for the given destination and extract the single
 * IAM policy's `PolicyDocument.Statement` array. Reading the document directly
 * (rather than via `hasResourceProperties`) lets the assertions iterate every
 * action/resource for the negative wildcard checks.
 */
function statementsFor(
  logDestination: LogDestination,
  s3BucketArn: string | null,
): SynthStatement[] {
  const app = new cdk.App();
  const stack = new AgentIamStack(app, "TestAgentIamStack", {
    env: ENV,
    firewallArn: FIREWALL_ARN,
    policyArn: POLICY_ARN,
    ruleGroupArns: RULE_GROUP_ARNS,
    alertLogGroupArn: ALERT_LOG_GROUP_ARN,
    flowLogGroupArn: FLOW_LOG_GROUP_ARN,
    logDestination,
    s3BucketArn,
  });

  const template = Template.fromStack(stack);
  const policies = template.findResources("AWS::IAM::Policy");
  const keys = Object.keys(policies);
  if (keys.length !== 1) {
    throw new Error(`Expected exactly one AWS::IAM::Policy, found ${keys.length}`);
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const props = policies[keys[0]].Properties as any;
  return props.PolicyDocument.Statement as SynthStatement[];
}

/** Flatten every statement's Action field into a single list of action strings. */
function allActions(statements: SynthStatement[]): string[] {
  return statements.flatMap((s) => toArray(s.Action));
}

describe("AgentIamStack CDK assertions — cloudwatch destination (R4.6, R4.5)", () => {
  let statements: SynthStatement[];

  beforeAll(() => {
    // cloudwatch destination: bucket ARN is irrelevant (no S3 statement emitted).
    statements = statementsFor("cloudwatch", null);
  });

  it("grants NO action wildcard anywhere — neither `\"*\"` nor `service:*` (R4.6)", () => {
    const actions = allActions(statements);
    expect(actions.length).toBeGreaterThan(0);
    for (const action of actions) {
      expect(action).not.toBe("*");
      expect(action).not.toMatch(SERVICE_ACTION_WILDCARD);
    }
  });

  it("limits the resource-`\"*\"` statement to EXACTLY the three NF list actions (R4.6)", () => {
    // The only resource wildcard R4.6 permits is the NF list statement.
    const wildcardStatements = statements.filter((s) => {
      const resources = toArray(s.Resource);
      return resources.length === 1 && resources[0] === "*";
    });

    // There must be exactly one resource-wildcard statement (the NF list one).
    expect(wildcardStatements).toHaveLength(1);

    const wildcardActions = toArray(wildcardStatements[0].Action);
    // Every action on the wildcard statement is one of the three NF list actions...
    for (const action of wildcardActions) {
      expect(NF_LIST_ACTIONS).toContain(action);
    }
    // ...and it carries no other action (set equality, order-independent).
    expect(new Set(wildcardActions)).toEqual(new Set(NF_LIST_ACTIONS));
  });

  it("grants NO S3 action when the destination is cloudwatch (R4.5)", () => {
    const actions = allActions(statements);
    expect(actions.some((a) => a.startsWith("s3:"))).toBe(false);
  });

  it("draws every granted action from the ALLOWED_ACTIONS allowlist (R4.6)", () => {
    for (const action of allActions(statements)) {
      expect(ALLOWED_ACTIONS.has(action)).toBe(true);
    }
  });
});

describe("AgentIamStack CDK assertions — S3 destination (R4.5, R4.6)", () => {
  let statements: SynthStatement[];

  beforeAll(() => {
    statements = statementsFor("s3", S3_BUCKET_ARN);
  });

  it("grants EXACTLY s3:GetObject and s3:ListBucket scoped to the bucket (R4.5)", () => {
    // Find the statement carrying the S3 read actions.
    const s3Statements = statements.filter((s) =>
      toArray(s.Action).some((a) => a.startsWith("s3:")),
    );
    expect(s3Statements).toHaveLength(1);

    const s3Actions = toArray(s3Statements[0].Action);
    expect(new Set(s3Actions)).toEqual(new Set(["s3:GetObject", "s3:ListBucket"]));

    // Scoped to the bucket ARN and its objects (bucket + bucket/*), nothing else.
    const s3Resources = toArray(s3Statements[0].Resource);
    expect(new Set(s3Resources)).toEqual(
      new Set([S3_BUCKET_ARN, `${S3_BUCKET_ARN}/*`]),
    );
  });

  it("STILL grants no action wildcard with the S3 statement present (R4.6)", () => {
    const actions = allActions(statements);
    expect(actions.length).toBeGreaterThan(0);
    for (const action of actions) {
      expect(action).not.toBe("*");
      expect(action).not.toMatch(SERVICE_ACTION_WILDCARD);
    }
  });

  it("draws every granted action (including S3) from the ALLOWED_ACTIONS allowlist (R4.6)", () => {
    for (const action of allActions(statements)) {
      expect(ALLOWED_ACTIONS.has(action)).toBe(true);
    }
  });
});
