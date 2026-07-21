<h1 align="center">Accelerating AWS Network Firewall incident response with AWS DevOps Agent</h1>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT--0-yellow.svg" alt="License: MIT-0"></a>
  <a href="https://aws.amazon.com/cdk/"><img src="https://img.shields.io/badge/AWS_CDK-TypeScript-blue.svg" alt="AWS CDK TypeScript"></a>
  <a href="https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html"><img src="https://img.shields.io/badge/AWS_Network_Firewall-Sample-orange.svg" alt="AWS Network Firewall"></a>
  <a href="https://aws.amazon.com/devops-agent/"><img src="https://img.shields.io/badge/AWS_DevOps_Agent-Incident_Response-905BDC.svg" alt="AWS DevOps Agent"></a>
  <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html"><img src="https://img.shields.io/badge/Amazon_CloudWatch-Alarms_%26_Logs-005EB8.svg" alt="Amazon CloudWatch"></a>
  <a href="#"><img src="https://img.shields.io/badge/Status-Demo-teal.svg" alt="Status: Demo"></a>
  <a href="#"><img src="https://img.shields.io/badge/Node.js-18%2B-green.svg" alt="Node.js 18+"></a>
</p>

A deployable AWS Network Firewall sample for incident response with AWS DevOps Agent. It stands up a sample Amazon Virtual Private Cloud (Amazon VPC) protected by AWS Network Firewall, wires up logging, Amazon CloudWatch alarms, and a least-privilege AWS Identity and Access Management (AWS IAM) role for the agent, then provides three reproducible break-fix scenarios. For each scenario the agent investigates using **native AWS APIs only** (AWS Network Firewall `Describe*`/`List*` calls plus Amazon CloudWatch Logs reads) and recommends a fix. There is no custom MCP server or bespoke tooling to maintain.

The project is a single AWS Cloud Development Kit (AWS CDK) (TypeScript) codebase. The correctness-sensitive logic (IAM policy builder, scenario state machine, alarm invariants) lives in pure, property-tested TypeScript modules that the CDK stacks import directly, so the code validated by the tests is the code that gets synthesized and deployed.

## Prerequisites

- **Node.js 18+ and npm** to install dependencies and run the CDK app and the `scenarioctl` CLI.
- **AWS Command Line Interface (AWS CLI) v2** and **AWS credentials** configured for the target account (environment variables, a shared profile, or an assumed role).
- **AWS CDK** is provided as a local devDependency (run via `npx`), so no global install is needed. `scripts/deploy.sh` bootstraps CDK automatically if the account and region are not yet bootstrapped.
- **AWS DevOps Agent Space**, the agent workspace, configured with context about the deployed firewall and pointed at the agent IAM role for read access.

### Configuration defaults (CDK context)

All defaults live in the `context` block of `cdk.json` and can be overridden with `--context key=value`:

| Context value | Default | Purpose |
|---|---|---|
| `awsRegion` | `us-east-1` | Single region the app deploys into (resolved into the CDK `env`). |
| `saasTestDomain` | _(empty)_ | Scenario 1 SaaS endpoint added to the domain denylist. Defaults to the test endpoint's generated app NLB DNS name (see below); set to override with your own reachable domain. |
| `notificationEmail` | _(empty)_ | Optional address for the SNS email subscription on alarm notifications. |
| `devopsAgentPrincipal` | _(account-root placeholder)_ | The AWS DevOps Agent trust principal (Agent Space role/principal ARN, or the agent service principal). Set to the real principal for a production deployment. |
| `logDestination` | `cloudwatch` | Active log destination, `cloudwatch` or `s3`. |
| `domainTargetUrl` | _(test endpoint)_ | Scenario 1 health-check probe URL. Defaults to `https://<app endpoint NLB DNS>`, the same host the firewall denies, so the check is green at baseline and red once the scenario is activated. |
| `statelessTargetUrl` | _(test endpoint)_ | Scenario 2 probe target (TCP port 9142 test class). Defaults to `<app endpoint NLB DNS>:9142`, which the test endpoint answers on, so the check is green at baseline and red once the stateless priorities are inverted. Format is `host:port` (a TCP connect, not HTTP). |
| `asymmetricTargetUrl` | _(test endpoint)_ | Scenario 3 probe URL. Defaults to `https://<app endpoint NLB DNS>`, a reachable HTTPS endpoint. |
| `controlTargetUrl` | _(test endpoint)_ | Status-page control probe (no metric, no alarm). Defaults to `https://<control endpoint NLB DNS>`, a separate endpoint no scenario rule targets, used to detect a subnet-wide egress outage (Scenario 3) versus an isolated rule failure. |
| `probeSecret` | _(generated default)_ | Shared secret the HTTPS probes send to the test endpoint (`X-Probe-Secret` header) as defence in depth on top of the NAT-EIP-scoped security group. |
| `statusPageAllowedCidr` | `0.0.0.0/0` | CIDR allowed to reach the public status-page ALB on HTTP :80. Defaults to open; for anything beyond a short-lived environment, lock it to a specific IP or range. |
| `statusPageUsername` | `admin` | Basic-auth username for the status page + webhook-config UI. The password is always generated into AWS Secrets Manager at deploy and printed by `scripts/deploy.sh`. |
| `deployAgentSpace` | `true` | Whether to deploy `NfAgentSpaceStack`, which automates AWS DevOps Agent onboarding (agent space + roles + this-account association). Set to `false` to skip it and onboard the agent manually. Requires an AWS DevOps Agent [supported Region](https://docs.aws.amazon.com/devopsagent/latest/userguide/about-aws-devops-agent-supported-regions.html); the deploy fails fast otherwise. |

### Health-check probe targets

The workload runs a health-check daemon that probes one target per scenario and publishes a custom CloudWatch metric per check (this is what gives each scenario its own alarm). A probe counts as **failed only on a connection timeout (curl exit 28)**, the signature of a firewall drop, so the target must be reachable at baseline and only break when you activate the scenario.

- **All three scenarios work out of the box against a self-deployed test endpoint.** The CDK app provisions `NfTestEndpointStack` — a separate, isolated VPC with two internet-facing Network Load Balancers and a single target instance — so the probes hit live, self-owned URLs generated at deploy time (no external/real domains). Scenario 1 probes `https://<app endpoint NLB DNS>`, Scenario 2 opens a TCP connection to `<app endpoint NLB DNS>:9142`, and Scenario 3 probes `https://<app endpoint NLB DNS>`. All are reachable at baseline, so every scenario demonstrates the full green→red→fix loop with no override. Because the targets are the deploy-generated NLB DNS names (CloudFormation tokens), nothing is hardcoded.
- Each probe targets a **distinct endpoint and port** so the three checks stay isolated. Scenario 2 uses port 9142 (rather than 443) so inverting the stateless priorities drops only its traffic class while Scenarios 1 and 3 stay green. Isolation is by port, not destination IP, so the endpoint's IP can change without breaking the rule. Override any target via `--context statelessTargetUrl=...` (or `domainTargetUrl` / `asymmetricTargetUrl`) to use different reachable endpoints.
- A fourth **control probe** (`controlTargetUrl`, default `https://<control endpoint NLB DNS>`) targets the test endpoint's separate control NLB that no scenario rule touches. It is page-only (no metric, no alarm) and measures the egress path itself. Scenario 3 flips the whole protected-subnet route cross-AZ, so it takes all egress down and the control probe fails too. The status page uses this to show a subnet-wide-outage banner and mark the Scenario 1 and 2 cards as collateral (amber `UNREACHABLE`) rather than implying their own conditions fired, while all three alarms fire for the agent to correlate.

## Quick start

```bash
bash scripts/deploy.sh           # prereq check + bootstrap + deploy all stacks (clean baseline)
```

`scripts/deploy.sh` checks prerequisites (Node 18+, npm, AWS CLI, credentials), installs dependencies, compiles and tests, bootstraps CDK if needed, deploys all eleven stacks at the clean baseline, and prints the outputs and next steps. Re-running it is safe (CDK only changes what drifted). Pass `--skip-tests` to skip the local test run.

> The eleventh stack, `NfAgentSpaceStack`, automates the one-time AWS DevOps Agent onboarding (agent space + roles + this-account association) and is deployed by default. It only deploys in a [Region where AWS DevOps Agent is available](https://docs.aws.amazon.com/devopsagent/latest/userguide/about-aws-devops-agent-supported-regions.html); otherwise the deploy fails fast with a message. Set `--context deployAgentSpace=false` to skip it (e.g. to onboard the agent manually). Creating the agent **webhook** and wiring it to the alarm pipeline stays a manual reader step either way.

Then drive the scenarios one at a time (only one scenario can be active at a time). AWS CloudShell is the easiest place to run these. Two options:

```bash
# Option A - no-setup CloudShell script (pure AWS CLI, no repo/CDK/Node needed).
# The deploy publishes the script to an S3 bucket in your account; copy the exact
# command from the NfScenarioScriptStack `ScenarioScriptDownload` output:
aws s3 cp s3://nf-devops-agent-scripts-<account-id>-<region>/nf-scenario.sh nf-scenario.sh && chmod +x nf-scenario.sh
./nf-scenario.sh activate <n>    # break (n = 1|2|3)
./nf-scenario.sh revert  <n>     # fix
./nf-scenario.sh status          # sync state, alarms, status-page URL

# Option B - from the cloned repo (redeploys the scenario's stack change via CDK):
npm run scenario activate <n>    # break the firewall in one of three ways (n = 1|2|3)
npm run scenario verify <n>      # run the egress probe + check the expected drop signals
npm run scenario revert <n>      # return to the working baseline
npm run scenario status          # show the current active scenario

bash scripts/destroy.sh          # revert any active scenario, cdk destroy --all, tag sweep
```

> **Warning:** `bash scripts/destroy.sh` permanently deletes all resources, including the
> Amazon S3 log bucket and every firewall log it holds. If you need to retain logs for
> compliance, audit, or analysis, export them to a separate location before running the
> teardown. See the runbook Teardown section for the full deletion order.

Both options change the same live firewall and leave the deployment matching the CDK baseline after a revert (verified with `cdk diff`). `scripts/nf-scenario.sh` discovers all resource ids at runtime, so it works on any deployment of this stack in the current account/region.

`scripts/destroy.sh` prompts for confirmation (enter `destroy`); pass `--yes` to skip the prompt for unattended teardown.

Development scripts:

```bash
npm run build                    # tsc
npm test                         # jest (unit, CDK assertion, and property tests)
npm run synth                    # cdk synth
npm run lint                     # eslint . --ext .ts
```

## What gets deployed

The app provisions eleven stacks, wired together by cross-stack references so the deploy and teardown order falls out of the dependency graph:

| Stack | Contents |
|---|---|
| `NfNetworkStack` | Sample Amazon VPC across two AZs, firewall/protected/public subnets, IGW, two NAT gateways, route tables, and AWS Systems Manager interface endpoints. |
| `NfFirewallStack` | AWS Network Firewall, firewall policy (`STRICT_ORDER`), and the `rg-stateless-priority`, `rg-stateful-baseline`, and `rg-domain` rule groups. |
| `NfLoggingStack` | Separate ALERT and FLOW Amazon CloudWatch log groups, an Amazon Simple Storage Service (Amazon S3) log bucket, and the firewall logging configuration. |
| `NfAlarmsStack` | Three alarms (one on the native `AWS/NetworkFirewall` `DroppedPackets` metric, two on custom application-health metrics) and the Amazon Simple Notification Service (Amazon SNS) topic they publish to. |
| `NfAgentIamStack` | The least-privilege, read-only agent AWS IAM role. |
| `NfWorkloadStack` | The `t3.micro` test workload (AWS Systems Manager-managed, no public IP, egress-only) running the health-check daemon and the status-page web server. |
| `NfWebhookStack` | The alarm-pipeline bridge: an AWS Lambda function subscribed to the alarms Amazon SNS topic that reads webhook credentials from AWS Secrets Manager, HMAC-signs an incident payload, and POSTs it to the AWS DevOps Agent webhook. |
| `NfStatusPageStack` | A public Application Load Balancer that fronts the workload's live status page (green/red per scenario) on HTTP :80. |
| `NfScenarioScriptStack` | An S3 bucket (`nf-devops-agent-scripts-<account>-<region>`) that the deploy publishes `scripts/nf-scenario.sh` into, so the scenarios can be driven from AWS CloudShell with a fixed `aws s3 cp` command (no repo clone, CDK, or Node). |
| `NfAgentSpaceStack` | **(Optional, on by default)** Automates the one-time AWS DevOps Agent onboarding: the agent space (`AWS::DevOpsAgent::AgentSpace`) with the operator app, the AWS "monitor" association for this account, and the agent-space service role (AWS-managed `AIDevOpsAgentAccessPolicy` + Resource Explorer service-linked-role permission) and operator-app role. Standalone (no cross-stack references). Gated by `deployAgentSpace` (default `true`) and by AWS DevOps Agent regional availability. The webhook still gets created and wired manually. |

On a successful deploy the app emits these outputs as the observable indication that all resources were created:

- Firewall ARN, firewall policy ARN, and the rule-group ARNs
- ALERT and FLOW log group names and ARNs
- SNS topic ARN
- Agent IAM role ARN
- Test workload instance id
- Webhook bridge Lambda name and the `nf-devops-agent-webhook-credentials` secret name
- Public status-page URL (the `StatusPageUrl` ALB output)
- The CloudShell scenario-driver download command (`ScenarioScriptDownload`) and its S3 URI (`ScenarioScriptS3Uri`)
- When `NfAgentSpaceStack` is deployed (default): the agent space ARN (`AgentSpaceArn`) and the agent-space (`AgentSpaceRoleArn`) and operator-app (`AgentSpaceOperatorRoleArn`) role ARNs

## Live status page

`NfStatusPageStack` puts an Application Load Balancer in front of a tiny web server on the workload, with an Amazon CloudFront distribution in front of the ALB so the page is served over **HTTPS** (the `StatusPageUrl` output is the `https://...cloudfront.net` URL; the direct HTTP ALB origin is also output as `StatusPageAlbUrl` for debugging). It renders one green/red card per scenario, refreshed every 10 seconds. The page is gated by a **styled in-page login** (a signed session cookie, not a browser basic-auth popup); sign in with the `StatusPageUsername` output and the password from the AWS Secrets Manager secret named by `StatusPagePasswordSecret`. Watch a card flip from **Healthy** to **DROPPED** when its scenario alarm fires, and back to green when the alarm clears. The card state is read from the **live Amazon CloudWatch alarm state** (the daemon calls `DescribeAlarms` each cycle over the Amazon CloudWatch interface endpoint), so the page mirrors exactly what AWS DevOps Agent sees. The fix can come from anywhere, the scenario script's revert or a CLI command an operator runs on the agent's advice, and the card clears as soon as the alarm returns to OK. The page also hosts a **Configure webhook** form that writes the DevOps Agent webhook URL + signing secret to AWS Secrets Manager (see "Wiring AWS DevOps Agent"). Amazon CloudFront forwards to the ALB, which health-checks the server at `/healthz` (the only unauthenticated path).

> **Security note:** the status page is reachable from the internet by default (`statusPageAllowedCidr = 0.0.0.0/0` on the ALB) and gated by a single shared login over a session cookie. Amazon CloudFront serves it over HTTPS, but the CloudFront-to-ALB origin hop is plain HTTP, so treat the credential as low-assurance and do not reuse a real password. The page exposes scenario names, a green/red state, and the webhook-config form (which writes to AWS Secrets Manager but never displays the stored secret). For anything beyond a short-lived environment, set `statusPageAllowedCidr` to a specific IP or range and put a custom domain + ACM certificate on the origin.

## Wiring AWS DevOps Agent

The alarm pipeline carries a firewall drop to the agent automatically: `DroppedPackets` → Amazon CloudWatch alarm → Amazon SNS → webhook bridge AWS Lambda function (reads AWS Secrets Manager, HMAC-signs, POSTs) → AWS DevOps Agent webhook → investigation.

The **agent space itself is created for you** by `NfAgentSpaceStack` as part of the deploy (default; see "What gets deployed"), so step 1 below is automated. The remaining steps — creating the agent **webhook** and wiring it to the alarm pipeline — stay manual, matching the accompanying blog post:

1. **(Automated by `NfAgentSpaceStack`.)** The agent space, its service/operator roles, and this account's association are created on deploy. The agent space ARN is the `AgentSpaceArn` output. If you set `deployAgentSpace=false` (or deployed in a Region without AWS DevOps Agent), create the agent space manually instead and grant it the least-privilege role from the `AgentRoleArn` output.
2. In the agent space, create the agent webhook and download its URL + signing secret.
3. Open the status page using the `StatusPageUrl` output.
4. Sign in with the `StatusPageUsername` output and the password from the `StatusPagePasswordSecret` AWS Secrets Manager secret.
5. Choose **Configure webhook**.
6. Paste the webhook URL and signing secret.
7. Save the configuration. The page writes `{"webhookUrl":"...","webhookSecret":"..."}` to the `nf-devops-agent-webhook-credentials` AWS Secrets Manager secret, so there is no AWS CLI step. Until the secret is set the bridge AWS Lambda function skips delivery (placeholder detected).
8. Verify by invoking the `nf-devops-agent-webhook` AWS Lambda function with a test Amazon SNS event.

See `runbook/runbook.md` ("Wiring AWS DevOps Agent to the alarm pipeline") for the full walkthrough.

## Verification environment variables

`baseline`, `activate`, `revert`, and `verify` run an egress probe on the workload (via SSM) and check the scenario's expected drop signals. Export the relevant stack outputs so verification can run; when they are not set, verification is skipped with a message rather than failing the deploy.

| Variable | Source |
|---|---|
| `NF_INSTANCE_ID` | Workload instance id output. |
| `NF_FIREWALL_NAME` | Firewall name (`nf-devops-agent`). |
| `NF_ALERT_LOG_GROUP` | ALERT log group name output. |
| `NF_FLOW_LOG_GROUP` | FLOW log group name output. |
| `NF_TARGET_URL` | Default egress probe target. |
| `NF_TARGET_URL_<n>` | Optional per-scenario probe target override (`n = 1|2|3`). |

## Cost note

> **Stand up, run the scenarios, and tear down the same day.** The two Network Firewall endpoints and two NAT gateways (one of each per AZ, two AZs are required to reproduce Scenario 3) are the dominant cost; they bill hourly while the environment exists. `npm run destroy` is the cost control. Every resource is tagged `Project = nf-devops-agent`, and the teardown runs a tag sweep on that key to catch any stragglers a failed delete leaves behind.

## Further reading

- [`runbook/runbook.md`](runbook/runbook.md): the operator runbook, covering per-scenario activation, trigger verification, the agent investigation and recommended fix, revert steps, and the teardown order and verification sweep.

## Conclusion

This sample provides reproducible AWS Network Firewall incident-response scenarios investigated by AWS DevOps Agent using native AWS APIs only. The workflow is intentionally stand-up-and-tear-down: deploy all eleven stacks at a clean baseline, run one break-fix scenario at a time, let the agent investigate and recommend a fix, then destroy the environment the same day to control the AWS Network Firewall and NAT gateway hourly cost. Deploy the sample to experience agent-driven firewall troubleshooting end to end, from a tripped Amazon CloudWatch alarm through to a ready-to-run mitigation.
