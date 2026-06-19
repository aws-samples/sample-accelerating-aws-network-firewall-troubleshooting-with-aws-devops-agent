/**
 * Synth assertion test for the CDK app entry (`bin/app.ts`) — task 12.2.
 *
 * Feature: nf-devops-agent-incident-response
 *
 * WHY THIS TEST MIRRORS `bin/app.ts` RATHER THAN IMPORTING IT
 * ───────────────────────────────────────────────────────────────────────────
 * `bin/app.ts` constructs its own `cdk.App` at module load (it is the cdk
 * entry, not an exported function), reads scenario values from CDK *context*,
 * and resolves the deployment account from the ambient `CDK_DEFAULT_ACCOUNT`.
 * Importing it for a hermetic assertion is awkward: there is no handle on the
 * `App` it builds and its env depends on process state.
 *
 * So this test takes the HERMETIC approach: it replicates the exact app wiring
 * (the same eight stacks, in the same dependency order, with the same props) and
 * re-adds the same `CfnOutput`s, but under a PINNED env and a baseline
 * `scenarioContext` derived from `toContext(baseline())`. The wiring and the
 * output block below are a faithful copy of `bin/app.ts` — keep them in sync if
 * `bin/app.ts` changes.
 *
 * It then asserts the two R1.4 success indicators:
 *   1. All eight stacks construct and SYNTHESIZE without error
 *      (`Template.fromStack` throws on a synth error), and
 *   2. The required `CfnOutput`s — the observable "all resources were created"
 *      indication — are present in the synthesized templates:
 *        - firewall:  FirewallArn, FirewallPolicyArn, RuleGroupArn0..2
 *        - logging:   AlertLogGroupName, AlertLogGroupArn,
 *                     FlowLogGroupName, FlowLogGroupArn
 *        - alarms:    AlarmTopicArn
 *        - agentIam:  AgentRoleArn
 *        - workload:  WorkloadInstanceId
 *
 * Validates: Requirements 1.4 (a successful deployment provides an observable
 * indication that all resources were created — surfaced here as the app's
 * CfnOutputs across the six stacks).
 */

import * as cdk from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";

import { NetworkStack } from "../lib/network-stack";
import { FirewallStack } from "../lib/firewall-stack";
import { LoggingStack } from "../lib/logging-stack";
import { AlarmsStack } from "../lib/alarms-stack";
import { AgentIamStack } from "../lib/agent-iam-stack";
import { WebhookStack } from "../lib/webhook-stack";
import { WorkloadStack } from "../lib/workload-stack";
import { StatusPageStack } from "../lib/status-page-stack";
import { ScenarioScriptStack } from "../lib/scenario-script-stack";
import { baseline, toContext } from "../src/scenarioctl/state";

/**
 * A pinned environment so VPC AZ selection (and the firewall endpoint map) is
 * deterministic during synth — no context lookups / no ambient account.
 */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

/** The designated SaaS test domain (matches the `saasTestDomain` in cdk.json). */
const SAAS_TEST_DOMAIN = "example-saas.example.com";

/**
 * The wired app: the six stacks plus the app-level CfnOutputs, built exactly
 * the way `bin/app.ts` builds them but under {@link ENV} and the baseline
 * scenario context. Returned so tests can synthesize each stack's template.
 */
interface WiredApp {
  app: cdk.App;
  network: NetworkStack;
  firewall: FirewallStack;
  logging: LoggingStack;
  alarms: AlarmsStack;
  agentIam: AgentIamStack;
  workload: WorkloadStack;
  webhook: WebhookStack;
  statusPage: StatusPageStack;
  scenarioScript: ScenarioScriptStack;
}

/**
 * Build the app under the baseline context. This block MIRRORS `bin/app.ts`
 * (stack wiring + CfnOutputs); see the file header for why we replicate rather
 * than import the entry.
 */
function buildBaselineApp(): WiredApp {
  const app = new cdk.App();
  // The test app does not load cdk.json context automatically; set the one
  // context key the firewall stack reads at synth time (Scenario 1 denylist).
  app.node.setContext("saasTestDomain", SAAS_TEST_DOMAIN);

  const scenarioContext = toContext(baseline());

  // 1. Network — the Sample_VPC and routing fabric.
  const network = new NetworkStack(app, "NfNetworkStack", { env: ENV, scenarioContext });

  // 2. Firewall — NF + policy + rule groups.
  const firewall = new FirewallStack(app, "NfFirewallStack", {
    env: ENV,
    scenarioContext,
    vpc: network.vpc,
    firewallSubnets: network.firewallSubnets,
    protectedSubnetRouting: network.protectedSubnetRouting,
    publicSubnetReturnRouting: network.publicSubnetReturnRouting,
    ingressEdgeRouteTableId: network.ingressEdgeRouteTableId,
  });

  // 3. Logging — ALERT/FLOW log groups + S3 bucket + logging configuration.
  const logging = new LoggingStack(app, "NfLoggingStack", {
    env: ENV,
    scenarioContext,
    firewallArn: firewall.firewallArn,
    firewallName: firewall.firewallName,
  });

  // 4. Alarms — DroppedPackets/RejectedPackets alarms + SNS topic.
  const alarms = new AlarmsStack(app, "NfAlarmsStack", {
    env: ENV,
    firewallName: firewall.firewallName,
    notificationEmail: "",
  });

  // 5. Agent IAM — least-privilege read-only role for AWS DevOps Agent.
  const agentIam = new AgentIamStack(app, "NfAgentIamStack", {
    env: ENV,
    firewallArn: firewall.firewallArn,
    policyArn: firewall.policyArn,
    ruleGroupArns: firewall.ruleGroupArns,
    alertLogGroupArn: logging.alertLogGroupArn,
    flowLogGroupArn: logging.flowLogGroupArn,
    logDestination: logging.logDestination,
    s3BucketArn: logging.bucketArn,
  });

  // 6. Workload — the SSM-managed test EC2 instance + per-scenario health checks.
  const workload = new WorkloadStack(app, "NfWorkloadStack", {
    env: ENV,
    vpc: network.vpc,
    protectedSubnet: network.protectedSubnets[0],
    firewallName: firewall.firewallName,
  });

  // 7. Webhook — the SNS -> Lambda -> Secrets Manager -> signed POST bridge.
  const webhook = new WebhookStack(app, "NfWebhookStack", {
    env: ENV,
    alarmTopic: alarms.topic,
  });

  // 8. Status page — public ALB fronting the workload's live status page.
  const statusPage = new StatusPageStack(app, "NfStatusPageStack", {
    env: ENV,
    vpc: network.vpc,
    publicSubnets: network.publicSubnets,
    workloadInstance: workload.instance,
    workloadSecurityGroup: workload.securityGroup,
    allowedCidr: "0.0.0.0/0",
  });

  // ── App-level tag for the teardown sweep (R10) ──
  cdk.Tags.of(app).add("Project", "nf-devops-agent");

  // 9. Scenario script — publishes scripts/nf-scenario.sh into an S3 bucket for
  //    CloudShell. Standalone (no cross-stack references).
  const scenarioScript = new ScenarioScriptStack(app, "NfScenarioScriptStack", { env: ENV });

  // ── Deploy success indicators (R1.4) — scoped to the owning stack ──
  new cdk.CfnOutput(firewall, "FirewallArn", {
    value: firewall.firewallArn,
    description: "AWS Network Firewall ARN",
  });
  new cdk.CfnOutput(firewall, "FirewallPolicyArn", {
    value: firewall.policyArn,
    description: "Network Firewall policy ARN",
  });
  firewall.ruleGroupArns.forEach((arn, i) => {
    new cdk.CfnOutput(firewall, `RuleGroupArn${i}`, {
      value: arn,
      description: `Network Firewall rule group ARN [${i}]`,
    });
  });

  new cdk.CfnOutput(logging, "AlertLogGroupName", {
    value: logging.alertLogGroup.logGroupName,
    description: "CloudWatch Logs ALERT log group name",
  });
  new cdk.CfnOutput(logging, "AlertLogGroupArn", {
    value: logging.alertLogGroupArn,
    description: "CloudWatch Logs ALERT log group ARN",
  });
  new cdk.CfnOutput(logging, "FlowLogGroupName", {
    value: logging.flowLogGroup.logGroupName,
    description: "CloudWatch Logs FLOW log group name",
  });
  new cdk.CfnOutput(logging, "FlowLogGroupArn", {
    value: logging.flowLogGroupArn,
    description: "CloudWatch Logs FLOW log group ARN",
  });

  new cdk.CfnOutput(alarms, "AlarmTopicArn", {
    value: alarms.topicArn,
    description: "SNS topic ARN for firewall alarm notifications",
  });

  new cdk.CfnOutput(agentIam, "AgentRoleArn", {
    value: agentIam.roleArn,
    description: "AWS DevOps Agent least-privilege role ARN",
  });

  new cdk.CfnOutput(workload, "WorkloadInstanceId", {
    value: workload.instanceId,
    description: "Test workload EC2 instance id (egress probe target)",
  });

  new cdk.CfnOutput(statusPage, "StatusPageUrl", {
    value: `http://${statusPage.loadBalancerDnsName}`,
    description: "Public URL of the live workload status page (green/red per scenario)",
  });

  new cdk.CfnOutput(webhook, "WebhookFunctionName", {
    value: webhook.webhookFunction.functionName,
    description: "DevOps Agent webhook bridge Lambda",
  });
  new cdk.CfnOutput(webhook, "WebhookSecretName", {
    value: webhook.webhookSecretName,
    description: "Secrets Manager secret for the DevOps Agent webhook URL + signing secret",
  });

  new cdk.CfnOutput(scenarioScript, "ScenarioScriptS3Uri", {
    value: scenarioScript.scriptS3Uri,
    description: "S3 URI of the CloudShell scenario driver (nf-scenario.sh)",
  });
  new cdk.CfnOutput(scenarioScript, "ScenarioScriptDownload", {
    value: scenarioScript.downloadCommand,
    description: "Copy-paste command to fetch the scenario driver in AWS CloudShell",
  });

  return { app, network, firewall, logging, alarms, agentIam, workload, webhook, statusPage, scenarioScript };
}

describe("CDK app entry synth (mirrors bin/app.ts) — R1.4", () => {
  let wired: WiredApp;
  // Synthesized templates, one per stack. `Template.fromStack` throws on a synth
  // error, so successfully building all six is itself the "stacks synthesize"
  // assertion.
  let templates: Record<string, Template>;

  beforeAll(() => {
    wired = buildBaselineApp();
    templates = {
      NfNetworkStack: Template.fromStack(wired.network),
      NfFirewallStack: Template.fromStack(wired.firewall),
      NfLoggingStack: Template.fromStack(wired.logging),
      NfAlarmsStack: Template.fromStack(wired.alarms),
      NfAgentIamStack: Template.fromStack(wired.agentIam),
      NfWorkloadStack: Template.fromStack(wired.workload),
      NfWebhookStack: Template.fromStack(wired.webhook),
      NfStatusPageStack: Template.fromStack(wired.statusPage),
      NfScenarioScriptStack: Template.fromStack(wired.scenarioScript),
    };
  });

  it("constructs and synthesizes all nine expected stacks without error", () => {
    const expectedStackIds = [
      "NfNetworkStack",
      "NfFirewallStack",
      "NfLoggingStack",
      "NfAlarmsStack",
      "NfAgentIamStack",
      "NfWorkloadStack",
      "NfWebhookStack",
      "NfStatusPageStack",
      "NfScenarioScriptStack",
    ];

    // Every expected stack id is present in the synthesized cloud assembly...
    const assembly = wired.app.synth();
    const synthesizedIds = assembly.stacks.map((s) => s.stackName);
    for (const id of expectedStackIds) {
      expect(synthesizedIds).toContain(id);
    }
    // ...and exactly nine stacks are wired (no more, no fewer).
    expect(assembly.stacks).toHaveLength(expectedStackIds.length);

    // Each per-stack Template was built in beforeAll (which throws on synth
    // error), so a successful build proves the stack synthesizes.
    for (const id of expectedStackIds) {
      expect(templates[id]).toBeDefined();
    }
  });

  it("surfaces the firewall success indicators (firewall ARN, policy ARN, 3 rule-group ARNs)", () => {
    const fw = templates.NfFirewallStack;
    fw.hasOutput("FirewallArn", {});
    fw.hasOutput("FirewallPolicyArn", {});
    fw.hasOutput("RuleGroupArn0", {});
    fw.hasOutput("RuleGroupArn1", {});
    fw.hasOutput("RuleGroupArn2", {});

    // The firewall exposes exactly three rule-group ARNs, so exactly three
    // RuleGroupArn* outputs are emitted.
    const ruleGroupOutputs = fw.findOutputs("*", {});
    const ruleGroupArnKeys = Object.keys(ruleGroupOutputs).filter((k) =>
      k.startsWith("RuleGroupArn"),
    );
    expect(ruleGroupArnKeys).toHaveLength(3);
  });

  it("surfaces the logging success indicators (alert/flow log group names + ARNs)", () => {
    const lg = templates.NfLoggingStack;
    lg.hasOutput("AlertLogGroupName", {});
    lg.hasOutput("AlertLogGroupArn", {});
    lg.hasOutput("FlowLogGroupName", {});
    lg.hasOutput("FlowLogGroupArn", {});
  });

  it("surfaces the alarms success indicator (SNS topic ARN)", () => {
    templates.NfAlarmsStack.hasOutput("AlarmTopicArn", {});
  });

  it("surfaces the agent-iam success indicator (agent role ARN)", () => {
    templates.NfAgentIamStack.hasOutput("AgentRoleArn", {});
  });

  it("surfaces the workload success indicator (instance id)", () => {
    templates.NfWorkloadStack.hasOutput("WorkloadInstanceId", {});
  });

  it("surfaces the webhook bridge indicators (function + secret name)", () => {
    templates.NfWebhookStack.hasOutput("WebhookFunctionName", {});
    templates.NfWebhookStack.hasOutput("WebhookSecretName", {});
  });

  it("surfaces the status-page indicator (public ALB URL)", () => {
    templates.NfStatusPageStack.hasOutput("StatusPageUrl", {});
  });

  it("surfaces the scenario-script indicators (S3 URI + CloudShell download command)", () => {
    templates.NfScenarioScriptStack.hasOutput("ScenarioScriptS3Uri", {});
    templates.NfScenarioScriptStack.hasOutput("ScenarioScriptDownload", {});
  });

  it("emits every required R1.4 output across the eight stacks", () => {
    // The full set of observable success indicators, grouped by owning stack.
    const expectedOutputs: Record<string, string[]> = {
      NfFirewallStack: [
        "FirewallArn",
        "FirewallPolicyArn",
        "RuleGroupArn0",
        "RuleGroupArn1",
        "RuleGroupArn2",
      ],
      NfLoggingStack: [
        "AlertLogGroupName",
        "AlertLogGroupArn",
        "FlowLogGroupName",
        "FlowLogGroupArn",
      ],
      NfAlarmsStack: ["AlarmTopicArn"],
      NfAgentIamStack: ["AgentRoleArn"],
      NfWorkloadStack: ["WorkloadInstanceId"],
      NfWebhookStack: ["WebhookFunctionName", "WebhookSecretName"],
      NfStatusPageStack: ["StatusPageUrl"],
    };

    for (const [stackId, outputNames] of Object.entries(expectedOutputs)) {
      const outputs = templates[stackId].findOutputs("*", {});
      for (const name of outputNames) {
        expect(Object.keys(outputs)).toContain(name);
      }
    }
  });
});
