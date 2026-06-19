/**
 * AgentIamStack — the least-privilege `Agent_IAM_Role` for AWS DevOps Agent
 * (Requirement 4).
 *
 * This stack creates a single AWS Identity and Access Management (IAM) role whose attached policy is built by the
 * pure, property-tested {@link buildAgentPolicy} (`src/scenarioctl/policy.ts`).
 * Each `PolicyStatementJson` the builder returns is mapped 1:1 into an
 * `iam.PolicyStatement` and attached to the role, so the document validated by
 * the policy property tests (Properties 1–3) is **exactly** the document
 * deployed onto the role — there is no second hand-written policy to drift
 * (design "Agent IAM role (least privilege)").
 *
 * Least-privilege contract carried over from the builder (R4):
 *   - AWS Network Firewall describe (R4.1) scoped to this deployment's firewall/policy/rule-group ARNs.
 *   - NF list (R4.2) constrained to exactly three actions on resource `"*"`
 *     (a *resource* wildcard, which R4.6 permits — not an *action* wildcard).
 *   - Amazon CloudWatch Logs read (R4.3) scoped to the alert/flow log groups + streams.
 *   - Amazon Simple Storage Service (Amazon S3) read (R4.5) emitted ONLY when `logDestination === "s3"`, scoped to the
 *     log bucket.
 *   - No create/update/delete/associate/tag action and no action wildcard
 *     (R4.4, R4.6) — guaranteed by the builder's allowlist.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Requires the FirewallStack and the LoggingStack.
 * ────────────────────────────────────────────────────────────────────────────
 * This stack consumes resource ARNs (not whole stacks) for testability — its
 * test (task 10.2) passes literal ARN strings so it synthesizes standalone:
 *   - from the firewall stack: `firewallArn`, `policyArn`, `ruleGroupArns`,
 *   - from the logging stack:  `alertLogGroupArn`, `flowLogGroupArn`,
 *     `logDestination`, and `bucketArn` (consumed as `s3BucketArn`, required
 *     when `logDestination === "s3"`).
 * `bin/app.ts` (task 12) wires those props from `firewall.*` and `logging.*`.
 *
 * Trust policy (who may assume the role):
 *   The exact principal for AWS DevOps Agent is configured per Agent Space and
 *   is NOT a well-known constant, so it is **overridable**. Resolution order:
 *     1. the `devOpsAgentPrincipalArn` prop, then
 *     2. the `devopsAgentPrincipal` CDK context value, then
 *     3. a documented placeholder (`AccountRootPrincipal`) so the stack always
 *        synthesizes.
 *   The operator MUST set `devopsAgentPrincipal` (context or prop) to the real
 *   Agent Space role/principal ARN (or the DevOps Agent service principal) for a
 *   production deployment — the default account-root principal is a placeholder
 *   that keeps the trust policy valid, not a least-privilege trust target.
 */
import * as cdk from "aws-cdk-lib";
import { Tags } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

import { PROJECT_TAG_KEY, PROJECT_TAG_VALUE } from "./network-stack";
import { buildAgentPolicy, PolicyStatementJson } from "../src/scenarioctl/policy";
import { LogDestination } from "../src/scenarioctl/state";

/**
 * CDK context key the operator sets to the real AWS DevOps Agent principal (an
 * Agent Space role ARN or the agent service principal). When unset the stack
 * falls back to {@link AgentIamStack} placeholder trust principal.
 */
const DEVOPS_AGENT_PRINCIPAL_CONTEXT_KEY = "devopsAgentPrincipal";

/**
 * Props for {@link AgentIamStack}. Accepts the deployment's resource ARNs (not
 * the whole firewall/logging stacks) so it synthesizes from literal strings in
 * tests; `bin/app.ts` passes the matching firewall/logging stack props.
 */
export interface AgentIamStackProps extends cdk.StackProps {
  /** Firewall ARN (from `firewall.firewallArn`). Scopes the NF describe statement (R4.1). */
  readonly firewallArn: string;
  /** Firewall policy ARN (from `firewall.policyArn`). Scopes the NF describe statement (R4.1). */
  readonly policyArn: string;
  /** Rule-group ARNs (from `firewall.ruleGroupArns`). Scope the NF describe statement (R4.1). */
  readonly ruleGroupArns: string[];
  /** ALERT log group ARN (from `logging.alertLogGroupArn`). Scopes the logs read statement (R4.3). */
  readonly alertLogGroupArn: string;
  /** FLOW log group ARN (from `logging.flowLogGroupArn`). Scopes the logs read statement (R4.3). */
  readonly flowLogGroupArn: string;
  /** Active log destination (from `logging.logDestination`). Gates the S3 read statement (R4.5). */
  readonly logDestination: LogDestination;
  /**
   * S3 log bucket ARN (from `logging.bucketArn`). REQUIRED when
   * `logDestination === "s3"` — the policy builder throws otherwise; ignored
   * (no S3 statement emitted) when `logDestination === "cloudwatch"`.
   */
  readonly s3BucketArn?: string | null;
  /**
   * Optional override for the AWS DevOps Agent trust principal. An IAM principal
   * ARN (e.g. an Agent Space role) or an AWS service principal (e.g.
   * `something.amazonaws.com`). Falls back to the `devopsAgentPrincipal` context
   * value, then to a placeholder account-root principal.
   */
  readonly devOpsAgentPrincipalArn?: string;
}

/**
 * Resolve the trust principal for the role. A value that looks like a service
 * principal (`*.amazonaws.com`, no `arn:`) becomes an `iam.ServicePrincipal`; a
 * value starting with `arn:` becomes an `iam.ArnPrincipal`; an empty/absent
 * value becomes the placeholder `iam.AccountRootPrincipal` so the stack always
 * synthesizes with a valid trust policy.
 */
function resolveTrustPrincipal(value: string | undefined): iam.IPrincipal {
  const trimmed = (value ?? "").trim();
  if (trimmed === "") {
    // Documented placeholder: keeps the trust policy valid for synth/deploy.
    // The operator overrides this with the real Agent Space principal.
    return new iam.AccountRootPrincipal();
  }
  if (trimmed.startsWith("arn:")) {
    return new iam.ArnPrincipal(trimmed);
  }
  if (trimmed.endsWith(".amazonaws.com")) {
    return new iam.ServicePrincipal(trimmed);
  }
  // Any other non-empty value is treated as an ARN-style principal.
  return new iam.ArnPrincipal(trimmed);
}

/**
 * The Agent IAM stack. Exposes {@link role} and {@link roleArn} for stack
 * outputs (task 12) and for the operator to wire into the Agent Space.
 */
export class AgentIamStack extends cdk.Stack {
  /** The least-privilege role AWS DevOps Agent assumes to investigate incidents. */
  public readonly role: iam.Role;
  /** The role ARN — surfaced as a CfnOutput and configured in the Agent Space. */
  public readonly roleArn: string;

  constructor(scope: Construct, id: string, props: AgentIamStackProps) {
    super(scope, id, props);

    // ── Resolve the trust principal (prop first, then context, then placeholder) ──
    const principalValue =
      props.devOpsAgentPrincipalArn ??
      (this.node.tryGetContext(DEVOPS_AGENT_PRINCIPAL_CONTEXT_KEY) as string | undefined);
    const trustPrincipal = resolveTrustPrincipal(principalValue);

    // Warn at synth/deploy time when the placeholder is in use: the role then
    // trusts the entire account root. The role is read-only, so the blast radius
    // is limited, but operators should scope trust to the real Agent Space
    // principal. Set `devopsAgentPrincipal` (context) or `devOpsAgentPrincipalArn`.
    if (!principalValue || principalValue.trim() === "") {
      cdk.Annotations.of(this).addWarning(
        "AWS DevOps Agent trust principal is not set, so the agent role trusts the " +
          "account root (placeholder). Set the 'devopsAgentPrincipal' context value to " +
          "the real DevOps Agent Space principal ARN to scope trust for production.",
      );
    }

    // ── The role: AWS DevOps Agent assumes it to read firewall config + logs ──
    this.role = new iam.Role(this, "AgentRole", {
      assumedBy: trustPrincipal,
      description:
        "Least-privilege role for AWS DevOps Agent: read-only Network Firewall describe/list, " +
        "CloudWatch Logs read, and (S3 log destination only) S3 read",
    });

    // ── Build the policy with the SAME pure builder the PBTs validate ──
    // Pass the bucket ARN through unchanged: when logDestination === "s3" the
    // builder requires it (and throws if null); when "cloudwatch" the S3
    // statement is not emitted and the value is ignored.
    const policyDocument = buildAgentPolicy({
      firewallArn: props.firewallArn,
      policyArn: props.policyArn,
      ruleGroupArns: props.ruleGroupArns,
      alertLogGroupArn: props.alertLogGroupArn,
      flowLogGroupArn: props.flowLogGroupArn,
      logDestination: props.logDestination,
      s3BucketArn: props.s3BucketArn ?? null,
    });

    // ── Map each returned statement 1:1 into an iam.PolicyStatement ──
    // This is the single-source-of-truth guarantee: the deployed policy is
    // exactly the property-tested document (design "Agent IAM role").
    const statements = policyDocument.Statement.map((stmt: PolicyStatementJson) =>
      new iam.PolicyStatement({
        sid: stmt.Sid,
        effect: iam.Effect.ALLOW,
        actions: [...stmt.Action],
        resources: [...stmt.Resource],
      }),
    );

    this.role.attachInlinePolicy(
      new iam.Policy(this, "AgentPolicy", {
        policyName: "nf-devops-agent-read-only",
        statements,
      }),
    );

    // ── Exported props ──
    this.roleArn = this.role.roleArn;

    // Tag every resource in the stack for the teardown sweep (Requirement 10).
    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);
  }
}
