/**
 * AgentSpaceStack — automates the one-time AWS DevOps Agent onboarding that this
 * sample previously left as a manual console/CLI step.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * What this stack creates (and why it is isolated)
 * ────────────────────────────────────────────────────────────────────────────
 * This is a **standalone** stack with NO cross-stack references into the rest of
 * the app, so it deploys and tears down independently of the ten firewall/
 * incident-response stacks and never changes their synthesized templates. It
 * provisions exactly what the AWS CDK onboarding guide provisions for a single
 * monitoring account (see the guide linked in the README):
 *
 *   1. Agent-space service role — assumed by the DevOps Agent service
 *      (`aidevops.amazonaws.com`) to monitor this account. It carries the
 *      AWS-managed `AIDevOpsAgentAccessPolicy` plus a narrow inline permission to
 *      create the Resource Explorer service-linked role. This is the access the
 *      DevOps Agent service itself requires; it is intentionally the broad
 *      managed policy the guide prescribes, NOT the least-privilege read-only
 *      role in `NfAgentIamStack` (that role remains as a scoped reference and is
 *      untouched here).
 *   2. Operator-app role — carries the AWS-managed
 *      `AIDevOpsOperatorAppAccessPolicy` for the operator app.
 *   3. Agent space (`AWS::DevOpsAgent::AgentSpace`) with the operator app enabled.
 *   4. AWS "monitor" association (`AWS::DevOpsAgent::Association`) linking THIS
 *      account to the agent space so the agent can investigate its resources.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Scope boundary (kept manual on purpose)
 * ────────────────────────────────────────────────────────────────────────────
 * Creating the agent **webhook** and wiring it to the alarm pipeline stays a
 * manual reader step (the "Configure webhook" form on the status page), exactly
 * as documented in the README. This stack only guarantees the agent space
 * itself exists as part of the deploy; it does not create or configure the
 * webhook.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Region availability
 * ────────────────────────────────────────────────────────────────────────────
 * AWS DevOps Agent is only available in the Regions in {@link DEVOPS_AGENT_SUPPORTED_REGIONS}.
 * `bin/app.ts` guards on this list before instantiating the stack and prints a
 * clear message (with the opt-out flag) when the configured region is not
 * supported, so a deploy in an unsupported region fails fast at synth rather
 * than with an opaque "resource type not found" CloudFormation error.
 */
import * as cdk from "aws-cdk-lib";
import { Tags } from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as devopsagent from "aws-cdk-lib/aws-devopsagent";
import { Construct } from "constructs";

import { PROJECT_TAG_KEY, PROJECT_TAG_VALUE } from "./network-stack";

/**
 * The AWS DevOps Agent trust service principal (the service that assumes the
 * agent-space and operator roles).
 */
const DEVOPS_AGENT_SERVICE_PRINCIPAL = "aidevops.amazonaws.com";

/** The AWS-managed policy that grants the agent-space role its monitoring access. */
const AGENT_ACCESS_MANAGED_POLICY = "AIDevOpsAgentAccessPolicy";

/** The AWS-managed policy for the operator app role. */
const OPERATOR_APP_MANAGED_POLICY = "AIDevOpsOperatorAppAccessPolicy";

/** The agent space name created by this stack. */
const AGENT_SPACE_NAME = "nf-devops-agent-space";

/**
 * AWS Regions where AWS DevOps Agent (the `AWS::DevOpsAgent::*` resource types)
 * is available. Sourced from the AWS DevOps Agent "Supported Regions" guide.
 * Used by `bin/app.ts` to guard the deploy so an unsupported region fails fast
 * with a clear message instead of an opaque CloudFormation error.
 */
export const DEVOPS_AGENT_SUPPORTED_REGIONS: readonly string[] = [
  "us-east-1",
  "us-west-2",
  "ca-central-1",
  "sa-east-1",
  "ap-south-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-northeast-1",
  "eu-central-1",
  "eu-west-1",
  "eu-west-2",
];

/** Props for {@link AgentSpaceStack}. No cross-stack references — fully standalone. */
export type AgentSpaceStackProps = cdk.StackProps;

/**
 * The AWS DevOps Agent onboarding stack. Exposes the agent-space ARN and the two
 * role ARNs for stack outputs (wired in `bin/app.ts`).
 */
export class AgentSpaceStack extends cdk.Stack {
  /** ARN of the created agent space (`AWS::DevOpsAgent::AgentSpace`). */
  public readonly agentSpaceArn: string;
  /** ARN of the agent-space service role the DevOps Agent assumes. */
  public readonly agentSpaceRoleArn: string;
  /** ARN of the operator-app role. */
  public readonly operatorRoleArn: string;

  constructor(scope: Construct, id: string, props?: AgentSpaceStackProps) {
    super(scope, id, props);

    // ── 1. Agent-space service role ──────────────────────────────────────────
    // Trusted only by the DevOps Agent service principal, and only when the call
    // originates from THIS account and an agent space in THIS region (the
    // aws:SourceAccount / aws:SourceArn conditions prevent the confused-deputy
    // pattern). Role name is intentionally CDK-generated (not fixed) so a deploy
    // never collides with a pre-existing manually-onboarded role of the same name.
    const agentSpaceRole = new iam.Role(this, "AgentSpaceRole", {
      assumedBy: new iam.ServicePrincipal(DEVOPS_AGENT_SERVICE_PRINCIPAL, {
        conditions: {
          StringEquals: { "aws:SourceAccount": this.account },
          ArnLike: {
            "aws:SourceArn": `arn:aws:aidevops:${this.region}:${this.account}:agentspace/*`,
          },
        },
      }),
      description: "AWS DevOps Agent agent-space service role (nf-devops-agent sample)",
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(AGENT_ACCESS_MANAGED_POLICY),
      ],
      inlinePolicies: {
        AllowCreateServiceLinkedRoles: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              sid: "AllowCreateResourceExplorerServiceLinkedRole",
              effect: iam.Effect.ALLOW,
              actions: ["iam:CreateServiceLinkedRole"],
              resources: [
                `arn:aws:iam::${this.account}:role/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer`,
              ],
            }),
          ],
        }),
      },
    });

    // ── 2. Operator-app role ───────────────────────────────────────────────────
    const operatorRole = new iam.Role(this, "OperatorAppRole", {
      assumedBy: new iam.ServicePrincipal(DEVOPS_AGENT_SERVICE_PRINCIPAL),
      description: "AWS DevOps Agent operator-app role (nf-devops-agent sample)",
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(OPERATOR_APP_MANAGED_POLICY),
      ],
    });

    // The operator role's trust policy needs BOTH sts:AssumeRole and
    // sts:TagSession in a single statement (the DevOps Agent operator app tags
    // its sessions), scoped by the same source-account / source-arn conditions.
    (operatorRole.node.defaultChild as iam.CfnRole).assumeRolePolicyDocument =
      new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            principals: [new iam.ServicePrincipal(DEVOPS_AGENT_SERVICE_PRINCIPAL)],
            actions: ["sts:AssumeRole", "sts:TagSession"],
            conditions: {
              StringEquals: { "aws:SourceAccount": this.account },
              ArnLike: {
                "aws:SourceArn": `arn:aws:aidevops:${this.region}:${this.account}:agentspace/*`,
              },
            },
          }),
        ],
      });

    // ── 3. Agent space (with the operator app enabled) ─────────────────────────
    const agentSpace = new devopsagent.CfnAgentSpace(this, "AgentSpace", {
      name: AGENT_SPACE_NAME,
      description:
        "Agent space for the AWS Network Firewall incident-response sample (created by CDK)",
      operatorApp: {
        iam: {
          operatorAppRoleArn: operatorRole.roleArn,
        },
      },
    });

    // ── 4. AWS "monitor" association: link THIS account to the agent space ──────
    const awsAssociation = new devopsagent.CfnAssociation(this, "AwsMonitorAssociation", {
      agentSpaceId: agentSpace.ref,
      serviceId: "aws",
      configuration: {
        aws: {
          assumableRoleArn: agentSpaceRole.roleArn,
          accountId: this.account,
          accountType: "monitor",
          resources: [],
        },
      },
    });
    awsAssociation.addDependency(agentSpace);

    // ── Exported props ──
    this.agentSpaceArn = agentSpace.attrArn;
    this.agentSpaceRoleArn = agentSpaceRole.roleArn;
    this.operatorRoleArn = operatorRole.roleArn;

    // Tag every resource for the teardown sweep (Requirement 10).
    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);
  }
}
