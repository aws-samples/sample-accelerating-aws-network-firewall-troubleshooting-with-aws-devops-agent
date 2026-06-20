#!/usr/bin/env node
/**
 * CDK app entry (`bin/app.ts`) — wires the eight stacks together and
 * surfaces the deploy success indicators (Requirements 1.3, 1.4, 1.6).
 *
 * Referenced by `cdk.json` as `npx ts-node --prefer-ts-exts bin/app.ts`.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * What this entry does
 * ────────────────────────────────────────────────────────────────────────────
 *   1. Resolves the scenario context from CDK context values (the cdk.json
 *      `context` block by default; overridden per `--context key=value` flags
 *      the `scenarioctl` CLI passes). Each `ScenarioContext` field is a
 *      top-level context key (see `src/scenarioctl/context.ts`), read here via
 *      `app.node.tryGetContext(<key>)` and coerced to its declared type.
 *   2. Resolves `awsRegion` (context, default `us-east-1`) into the CDK `env`
 *      alongside the ambient `CDK_DEFAULT_ACCOUNT`.
 *   3. Instantiates the network, firewall, logging, alarms, agent-iam, workload,
 *      webhook, and status-page stacks IN DEPENDENCY ORDER, passing cross-stack
 *      references as construct props. Because those references are
 *      AWS CloudFormation tokens, CDK infers the inter-stack dependencies (and
 *      therefore the deploy/teardown order) automatically — no explicit
 *      `addDependency` is required (R1.6).
 *   4. Applies the `Project = nf-devops-agent` tag at the app level so
 *      every resource in every stack is swept on teardown (R10).
 *   5. Adds `CfnOutput`s for the observable success indicators (R1.4): the
 *      firewall/policy/rule-group ARNs, the alert/flow log group names + ARNs,
 *      the Amazon Simple Notification Service (Amazon SNS) topic ARN, the agent role ARN, and the workload instance id.
 *
 * The stacks read scenario values from BOTH the `scenarioContext` prop and a
 * `tryGetContext` fallback, so passing the resolved `scenarioContext` down is
 * the clean path: a `--context activeScenario=2 ...` deploy (from the CLI
 * runner) drives the synthesized template through these props.
 */
import * as cdk from "aws-cdk-lib";

import { NetworkStack } from "../lib/network-stack";
import { TestEndpointStack } from "../lib/test-endpoint-stack";
import { FirewallStack } from "../lib/firewall-stack";
import { LoggingStack } from "../lib/logging-stack";
import { AlarmsStack } from "../lib/alarms-stack";
import { AgentIamStack } from "../lib/agent-iam-stack";
import { WebhookStack } from "../lib/webhook-stack";
import { WorkloadStack } from "../lib/workload-stack";
import { StatusPageStack } from "../lib/status-page-stack";
import { ScenarioScriptStack } from "../lib/scenario-script-stack";
import {
  LogDestination,
  Scenario,
  ScenarioContext,
  StreamExceptionPolicy,
} from "../src/scenarioctl/state";

/** The project-wide tag applied app-wide for the teardown sweep (design Decision 3). */
const PROJECT_TAG_KEY = "Project";
const PROJECT_TAG_VALUE = "nf-devops-agent";

/** Default AWS region when `awsRegion` context is unset (design Decision 3). */
const DEFAULT_AWS_REGION = "us-east-1";

/** Read a string context value, falling back to `fallback` when unset/empty. */
function readStringContext(app: cdk.App, key: string, fallback: string): string {
  const value = app.node.tryGetContext(key);
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

/** Read a numeric context value, tolerating string-encoded numbers from `--context`. */
function readNumberContext(app: cdk.App, key: string, fallback: number): number {
  const value = app.node.tryGetContext(key);
  if (value === undefined || value === null || value === "") return fallback;
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : fallback;
}

/** Read a boolean context value, tolerating the string "true"/"false" from `--context`. */
function readBooleanContext(app: cdk.App, key: string, fallback: boolean): boolean {
  const value = app.node.tryGetContext(key);
  if (value === undefined || value === null) return fallback;
  return value === true || value === "true";
}

/** Coerce a raw context string into the {@link Scenario} union (default `none`). */
function coerceScenario(value: string): Scenario {
  return value === "1" || value === "2" || value === "3" ? value : "none";
}

/** Coerce a raw context string into {@link StreamExceptionPolicy} (default `CONTINUE`). */
function coerceStreamExceptionPolicy(value: string): StreamExceptionPolicy {
  return value === "DROP" || value === "REJECT" ? value : "CONTINUE";
}

/** Coerce a raw context string into {@link LogDestination} (default `cloudwatch`). */
function coerceLogDestination(value: string): LogDestination {
  return value === "s3" ? "s3" : "cloudwatch";
}

/**
 * Assemble the {@link ScenarioContext} from the top-level CDK context keys. The
 * defaults match the `cdk.json` baseline so a plain `cdk synth`/`cdk deploy`
 * (no active scenario) renders the working baseline.
 */
function resolveScenarioContext(app: cdk.App): ScenarioContext {
  return {
    activeScenario: coerceScenario(readStringContext(app, "activeScenario", "none")),
    allowPriority: readNumberContext(app, "allowPriority", 100),
    dropPriority: readNumberContext(app, "dropPriority", 200),
    streamExceptionPolicy: coerceStreamExceptionPolicy(
      readStringContext(app, "streamExceptionPolicy", "CONTINUE"),
    ),
    asymmetricRoute: readBooleanContext(app, "asymmetricRoute", false),
    domainDenyActive: readBooleanContext(app, "domainDenyActive", false),
    logDestination: coerceLogDestination(readStringContext(app, "logDestination", "cloudwatch")),
  };
}

const app = new cdk.App();

// ── Resolve scenario context + the deployment env ──
const scenarioContext = resolveScenarioContext(app);
const awsRegion = readStringContext(app, "awsRegion", DEFAULT_AWS_REGION);
const notificationEmail = readStringContext(app, "notificationEmail", "");

// Health-check probe targets. By default they point at the self-deployed test
// endpoint (NfTestEndpointStack) — deploy-generated NLB DNS names, so NO real
// external domain is referenced anywhere. Each can still be overridden via
// context to point at a different reachable endpoint.
//
// The Scenario 1 firewall SNI deny rule matches the SAME app-endpoint DNS name
// the probe hits, so a denied SNI drops the probe exactly as before — the agent
// still discovers the dropped host in the alert log + rg-domain rule.
const saasTestDomainOverride = readStringContext(app, "saasTestDomain", "");
const domainTargetUrl = readStringContext(app, "domainTargetUrl", "");
const statelessTargetUrl = readStringContext(app, "statelessTargetUrl", "");
const asymmetricTargetUrl = readStringContext(app, "asymmetricTargetUrl", "");
const controlTargetUrl = readStringContext(app, "controlTargetUrl", "");

// The CIDR allowed to reach the public status page (default open to the
// internet; lock to your own IP/range for anything beyond a short sample).
const statusPageAllowedCidr = readStringContext(app, "statusPageAllowedCidr", "0.0.0.0/0");

// Basic-auth credentials for the status page + webhook-config UI. The page is
// public (internet-facing via Amazon CloudFront), so it is always gated by a login. The
// username defaults to `admin`. The password is always randomly generated into AWS
// Secrets Manager at deploy and printed by scripts/deploy.sh (there is no
// plaintext-password override, to keep the password out of the synthesized template).
const statusPageUsername = readStringContext(app, "statusPageUsername", "admin");

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: awsRegion,
};

// ── Stacks in dependency order; cross-stack token props infer the deploy order ──

// 1. Network — the Sample_VPC and routing fabric (no upstream dependency).
const network = new NetworkStack(app, "NfNetworkStack", { env, scenarioContext });

// 1b. Test endpoint — a SECOND, isolated VPC with internet-facing NLBs and a
//     single target instance, so the scenario probes hit self-owned, deploy-
//     generated URLs instead of real external domains. Its target SG is scoped
//     to the main VPC's NAT EIPs (no 0.0.0.0/0). The firewall SNI rule and the
//     workload probes reference its NLB DNS names (tokens) — nothing hardcoded.
const testEndpoint = new TestEndpointStack(app, "NfTestEndpointStack", {
  env,
  natEipAddresses: network.natEipAddresses,
});

// Effective probe targets + Scenario 1 SNI domain, derived from the test
// endpoint's generated NLB DNS names unless explicitly overridden via context.
const appDns = testEndpoint.appEndpointDns;
const s3Dns = testEndpoint.s3EndpointDns;
const controlDns = testEndpoint.controlEndpointDns;
const effectiveSaasTestDomain = saasTestDomainOverride || appDns;
const effectiveDomainTargetUrl = domainTargetUrl || `https://${appDns}`;
const effectiveStatelessTargetUrl = statelessTargetUrl || `${appDns}:9142`;
// Scenario 3 probes a DISTINCT host (the s3 endpoint), not appDns: Scenario 1's
// TLS SNI deny matches the app endpoint's hostname, and since S1 and S3 are both
// HTTPS :443, sharing one host made breaking S1 also drop the S3 probe (tripping
// Alarm-3 collaterally). A separate host keeps S1 isolated while S3 still fails
// correctly under the subnet-wide asymmetric-routing outage.
const effectiveAsymmetricTargetUrl = asymmetricTargetUrl || `https://${s3Dns}`;
const effectiveControlTargetUrl = controlTargetUrl || `https://${controlDns}`;

// 2. Firewall — NF + policy + rule groups; wires the firewall-endpoint routes.
const firewall = new FirewallStack(app, "NfFirewallStack", {
  env,
  scenarioContext,
  vpc: network.vpc,
  firewallSubnets: network.firewallSubnets,
  protectedSubnetRouting: network.protectedSubnetRouting,
  publicSubnetReturnRouting: network.publicSubnetReturnRouting,
  ingressEdgeRouteTableId: network.ingressEdgeRouteTableId,
  saasTestDomain: effectiveSaasTestDomain,
});

// 3. Logging — ALERT/FLOW log groups + Amazon Simple Storage Service (Amazon S3) bucket + logging configuration.
const logging = new LoggingStack(app, "NfLoggingStack", {
  env,
  scenarioContext,
  firewallArn: firewall.firewallArn,
  firewallName: firewall.firewallName,
});

// 4. Alarms — DroppedPackets/RejectedPackets alarms + SNS topic.
const alarms = new AlarmsStack(app, "NfAlarmsStack", {
  env,
  firewallName: firewall.firewallName,
  notificationEmail,
});

// 5. Agent IAM — least-privilege read-only role for AWS DevOps Agent.
const agentIam = new AgentIamStack(app, "NfAgentIamStack", {
  env,
  firewallArn: firewall.firewallArn,
  policyArn: firewall.policyArn,
  ruleGroupArns: firewall.ruleGroupArns,
  alertLogGroupArn: logging.alertLogGroupArn,
  flowLogGroupArn: logging.flowLogGroupArn,
  logDestination: logging.logDestination,
  s3BucketArn: logging.bucketArn,
});

// 6. Workload — the AWS Systems Manager (SSM)-managed test Amazon EC2 instance + per-scenario health-check daemon.
const workload = new WorkloadStack(app, "NfWorkloadStack", {
  env,
  vpc: network.vpc,
  protectedSubnet: network.protectedSubnets[0],
  firewallName: firewall.firewallName,
  // Scenario probes target the self-deployed test endpoint's generated NLB DNS
  // names (no hardcoded domains). Scenario 1 probes the same host the firewall
  // denylist blocks.
  domainTargetUrl: effectiveDomainTargetUrl,
  statelessTargetUrl: effectiveStatelessTargetUrl,
  asymmetricTargetUrl: effectiveAsymmetricTargetUrl,
  controlTargetUrl: effectiveControlTargetUrl,
  statusPageUsername,
});

// 7. Webhook — the SNS -> AWS Lambda -> Secrets Manager -> signed POST bridge that
//    wires the alarms to the AWS DevOps Agent webhook.
const webhook = new WebhookStack(app, "NfWebhookStack", {
  env,
  alarmTopic: alarms.topic,
});

// 8. Status page — a public ALB fronting the workload's live green/red status
//    page (depends on network for the public subnets and workload for the
//    instance + its security group).
const statusPage = new StatusPageStack(app, "NfStatusPageStack", {
  env,
  vpc: network.vpc,
  // Out-of-band ALB subnets: their route table carries NO firewall return route,
  // so ALB-to-workload :8080 management traffic always uses the VPC `local`
  // route and never traverses a firewall endpoint. This keeps the status page up
  // even while a scenario (especially Scenario 3) drops all firewall egress.
  publicSubnets: network.albSubnets,
  workloadInstance: workload.instance,
  workloadSecurityGroup: workload.securityGroup,
  allowedCidr: statusPageAllowedCidr,
});

// ── App-level tag for the teardown sweep (R10) ──
cdk.Tags.of(app).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);

// 9. Scenario script — publishes scripts/nf-scenario.sh into a deterministically
//    named S3 bucket so the scenarios can be driven straight from CloudShell with a
//    fixed `aws s3 cp` command (no repo clone / CDK / Node). Standalone: no
//    cross-stack references, so it deploys in parallel with the rest.
const scenarioScript = new ScenarioScriptStack(app, "NfScenarioScriptStack", { env });

// ── Deploy success indicators (R1.4). Each CfnOutput is scoped to the stack ──
// that owns the underlying resource.

// Firewall stack outputs: firewall ARN, policy ARN, rule-group ARNs.
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

// Logging stack outputs: alert/flow log group names + ARNs.
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

// Alarms stack output: SNS topic ARN.
new cdk.CfnOutput(alarms, "AlarmTopicArn", {
  value: alarms.topicArn,
  description: "SNS topic ARN for firewall alarm notifications",
});

// Webhook stack outputs: the bridge Lambda name and the credentials secret the
// operator updates with the DevOps Agent webhook URL + signing secret.
new cdk.CfnOutput(webhook, "WebhookFunctionName", {
  value: webhook.webhookFunction.functionName,
  description: "DevOps Agent webhook bridge Lambda (subscribed to the alarms SNS topic)",
});
new cdk.CfnOutput(webhook, "WebhookSecretName", {
  value: webhook.webhookSecretName,
  description: "Secrets Manager secret to update with the DevOps Agent webhook URL + signing secret",
});

// Agent IAM stack output: agent role ARN.
new cdk.CfnOutput(agentIam, "AgentRoleArn", {
  value: agentIam.roleArn,
  description: "AWS DevOps Agent least-privilege role ARN",
});

// Workload stack output: test workload instance id.
new cdk.CfnOutput(workload, "WorkloadInstanceId", {
  value: workload.instanceId,
  description: "Test workload EC2 instance id (egress probe target)",
});

// Status-page stack outputs: the HTTPS CloudFront URL (primary) and the direct
// HTTP ALB URL (origin, for debugging).
new cdk.CfnOutput(statusPage, "StatusPageUrl", {
  value: `https://${statusPage.distributionDomainName}`,
  description: "Public HTTPS URL of the live workload status page (CloudFront)",
});
new cdk.CfnOutput(statusPage, "StatusPageAlbUrl", {
  value: `http://${statusPage.loadBalancerDnsName}`,
  description: "Direct HTTP ALB URL behind CloudFront (origin; for debugging)",
});

// Status-page login: the username and the Secrets Manager secret that holds the
// generated password (the password itself is never a CloudFormation output).
new cdk.CfnOutput(workload, "StatusPageUsername", {
  value: statusPageUsername,
  description: "Username for the status page + webhook-config UI",
});
new cdk.CfnOutput(workload, "StatusPagePasswordSecret", {
  value: workload.statusPageSecret.secretName,
  description: "Secrets Manager secret holding the generated status-page login password",
});
new cdk.CfnOutput(workload, "StatusPagePasswordCommand", {
  value: `aws secretsmanager get-secret-value --secret-id ${workload.statusPageSecret.secretName} --query SecretString --output text`,
  description: "Command to read the generated status-page login password",
});

// Scenario-script stack outputs: where the CloudShell driver lives and the exact
// command to pull it. Printed by scripts/deploy.sh as a next step.
new cdk.CfnOutput(scenarioScript, "ScenarioScriptS3Uri", {
  value: scenarioScript.scriptS3Uri,
  description: "S3 URI of the CloudShell scenario driver (nf-scenario.sh)",
});
new cdk.CfnOutput(scenarioScript, "ScenarioScriptDownload", {
  value: scenarioScript.downloadCommand,
  description: "Copy-paste command to fetch the scenario driver in AWS CloudShell",
});

// Test-endpoint stack outputs: the generated NLB DNS names the scenarios probe.
new cdk.CfnOutput(testEndpoint, "AppEndpointDnsOut", {
  value: testEndpoint.appEndpointDns,
  description: "Test endpoint (app) NLB DNS name — Scenario 1 and 2 probe target",
});
new cdk.CfnOutput(testEndpoint, "S3EndpointDnsOut", {
  value: testEndpoint.s3EndpointDns,
  description: "Test endpoint (s3) NLB DNS name — Scenario 3 probe target (distinct host)",
});
new cdk.CfnOutput(testEndpoint, "ControlEndpointDnsOut", {
  value: testEndpoint.controlEndpointDns,
  description: "Test endpoint (control) NLB DNS name — page-only control probe target",
});
