# Operator Runbook: AWS Network Firewall incident response with AWS DevOps Agent

This runbook is the operator-facing companion to the sample environment. It documents,
for each of the three break-fix scenarios, the exact command to run, how to confirm the
trigger fired, the investigation AWS DevOps Agent is expected to perform using native
AWS APIs and Amazon CloudWatch Logs, the outcome and recommended fix the agent surfaces, and how
to revert and confirm the environment is healthy again. It closes with the teardown order
and a post-teardown verification sweep.

Everything below is limited to what the CDK app actually provisions across its eight stacks
(network, firewall, logging, alarms, agent IAM, workload, webhook, status page). No
resource, metric, or fix is referenced that the code does not create.

## Deployed resource names

These fixed names are referenced throughout the runbook (single deployment per
account/region):

| Resource | Name |
|---|---|
| Firewall | `nf-devops-agent` |
| Firewall policy | `nf-devops-agent-policy` |
| Stateless rule group | `rg-stateless-priority` |
| Stateful baseline rule group | `rg-stateful-baseline` |
| Domain rule group | `rg-domain` |
| ALERT log group | `/nf-devops-agent/alert` |
| FLOW log group | `/nf-devops-agent/flow` |
| Status page (public ALB) | `StatusPageUrl` output (HTTP :80) |
| Project tag (teardown sweep) | `Project = nf-devops-agent` |

Scenario-specific targets. These are **intentional references to real AWS service
endpoints** used as functional test targets (not example placeholders); the scenarios
require reachable, resolvable endpoints to demonstrate a real firewall drop (see
`SECURITY.md`):

- SaaS test domain (Scenario 1): `saasTestDomain` context value, default `docs.aws.amazon.com` (an intentional real AWS endpoint).
- Stateless test traffic class (Scenario 2): TCP destination port `9142` (probed against `cassandra.<region>.amazonaws.com:9142`, the regional Amazon Keyspaces (for Apache Cassandra) TLS endpoint, via a TCP connect — an intentional real AWS service endpoint).
- Control probe (status page only, not a scenario): `https://sts.amazonaws.com`, an intentional real AWS endpoint no scenario rule targets, used to detect a subnet-wide egress outage (Scenario 3 scope) versus an isolated per-scenario rule failure. Publishes no metric and raises no alarm.

## Command reference

All operator actions go through the `scenarioctl` CLI, exposed as npm scripts. The
`scenario` script is `ts-node src/scenarioctl/cli.ts`; `baseline` and `destroy` are their
own scripts.

| Action | Command | Equivalent |
|---|---|---|
| Deploy everything (clean baseline) | `bash scripts/deploy.sh` | prereq check + bootstrap + `cdk deploy --all` |
| Deploy + verify baseline only | `npm run baseline` | `ts-node src/scenarioctl/cli.ts baseline` |
| Activate a scenario | `npm run scenario activate <1\|2\|3>` | `... cli.ts activate <n>` |
| Revert a scenario | `npm run scenario revert <1\|2\|3>` | `... cli.ts revert <n>` |
| Verify a scenario (no deploy) | `npm run scenario verify <1\|2\|3>` | `... cli.ts verify <n>` |
| Show active scenario | `npm run scenario status` | `... cli.ts status` |
| Tear the environment down | `bash scripts/destroy.sh` | revert + `cdk destroy --all` + tag sweep |

Only one scenario can be active at a time. Activating a scenario while a different one is
active is rejected with an instruction to revert the active scenario first. Re-running
`activate <n>` while `n` is already active, or `revert <n>` while `n` is already reverted,
is a no-op that succeeds.

### Verification probe and signals

`baseline`, `activate`, `revert`, and `verify` all run the same egress probe and drop
checks. The probe runs on the test workload through SSM `SendCommand`
(`AWS-RunShellScript` running a bounded `curl`), then polls `GetCommandInvocation` to a
terminal state. SSM control traffic reaches the workload over interface VPC endpoints that
bypass the firewall, so the probe can always run even while firewall egress is broken.

After the probe, the CLI checks the scenario's expected drop signals:

| Scenario | Signals checked |
|---|---|
| Baseline (`none`) | none, only that egress succeeds |
| 1 | `DroppedPackets` metric, ALERT log |
| 2 | `DroppedPackets` metric |
| 3 | `DroppedPackets` metric, FLOW log |

A blocked `curl` (non-zero exit) is itself a direct drop signal. The `DroppedPackets`
metric is read with `GetMetricData` against `AWS/NetworkFirewall`, summed across both AZ
endpoints by `FirewallName`. The metric and ALERT log are polled within a 5-minute window;
the FLOW log within 60 seconds.

Verification requires the deployed stack outputs exported as environment variables
(`NF_INSTANCE_ID`, `NF_FIREWALL_NAME`, `NF_ALERT_LOG_GROUP`, `NF_FLOW_LOG_GROUP`, and
`NF_TARGET_URL`, with an optional per-scenario `NF_TARGET_URL_<n>`). When these are not
set, verification is skipped with a message rather than failing the deploy.

### Per-scenario alarms and the agent pipeline

Separate from the `scenarioctl verify` probe, the deployed environment runs continuously.
The alarms use two sources, to show both options a real environment can adopt. Scenario 1
alarms on the NATIVE AWS Network Firewall `DroppedPackets` metric (namespace
`AWS/NetworkFirewall`), summed across the per-Availability-Zone stateful streams, so no
workload instrumentation is needed. Scenarios 2 and 3 alarm on a custom metric the
health-check daemon publishes per check (namespace `NfAgent/Workload`, dimensioned by
`Firewall`): `1` on a firewall-drop timeout, `0` when healthy. The alarm names are
deliberately GENERIC (`Alarm-1/2/3`) and carry no hint of the root cause: the
webhook payload tells AWS DevOps Agent only that something is dropping, so the agent must
investigate the firewall config and logs to find the cause rather than being handed the
answer:

| Scenario | Alarm source | Alarm name (sent to the agent) |
|---|---|---|
| 1 | Native `AWS/NetworkFirewall` `DroppedPackets` | `Alarm-1` |
| 2 | Custom `NfAgent/Workload` `StatelessRuleFailures` | `Alarm-2` |
| 3 | Custom `NfAgent/Workload` `AsymmetricFlowFailures` | `Alarm-3` |

All three alarms publish to the same SNS topic, which the webhook bridge Lambda subscribes
to. Each scenario below is activated by the scripted `npm run scenario activate <n>` (run
it from AWS CloudShell or any shell with the repo cloned and credentials set), which
redeploys the affected stack with that one scenario's change and trips its alarm.

## Baseline verification

Before activating any scenario, confirm the environment is healthy.

```
npm run baseline
```

This deploys the canonical working state (`activeScenario = none`) and then runs the
egress probe from the test workload to the affected target. Baseline succeeds when the
egress request completes and **no** drop trigger is observed: the `curl` returns, the
`DroppedPackets` metric does not rise, and no drop log entries appear. This is the
known-good state every scenario reverts back to.

If `npm run baseline` reports a healthy egress, the environment is ready. If it reports a drop,
the environment is not at baseline (revert any active scenario, or re-run `baseline`).

### Live status page

`NfStatusPageStack` deploys an Amazon CloudFront distribution in front of an Application
Load Balancer and a small web server on the workload that renders one green/red card per
scenario, refreshed every 10 seconds. Open the `StatusPageUrl` output (the
`https://...cloudfront.net` URL) in a browser and keep it open while running the
scenarios: the affected card flips from **Healthy** to **DROPPED** when its scenario alarm
fires, and back to green when the alarm clears (whether you revert with the script or apply
a fix by hand on the agent's advice). The page reads the **live Amazon CloudWatch alarm state**
(the daemon calls `DescribeAlarms` each cycle over the Amazon CloudWatch interface endpoint, so it
works even when a scenario drops all firewall egress) and the ALB health-checks the server
at `/healthz`.

The daemon also runs a page-only **control probe** against an AWS endpoint no scenario
rule targets (`https://sts.amazonaws.com`), so the page can tell an isolated rule failure
apart from a subnet-wide egress outage. For Scenarios 1 and 2 the control probe stays
green and only the affected card turns red. For Scenario 3 the route change takes the
whole egress path down, so the control probe also fails: the page then shows a
subnet-wide-outage banner, keeps the Scenario 3 card red as the root cause, and marks the
Scenario 1 and 2 cards amber as `UNREACHABLE (collateral)` with a note that their own
conditions are not firing. The control probe publishes no metric and raises no alarm.

The page is served over **HTTPS through Amazon CloudFront** and is gated by a **styled
in-page login** (a signed session cookie, not a browser basic-auth popup): sign in with the
`StatusPageUsername` output and the password from the AWS Secrets Manager secret named by
the `StatusPagePasswordSecret` output. The webhook-configuration form (which transmits the
DevOps Agent webhook URL and signing secret) is therefore submitted over the encrypted
CloudFront connection, never in clear text. The CloudFront-to-ALB origin hop is plain HTTP
inside the account, so treat the login credential as low-assurance and do not reuse a real
password. Network exposure is still open by default (`statusPageAllowedCidr = 0.0.0.0/0` on
the ALB); set `statusPageAllowedCidr` to a specific IP or range, and put a custom domain +
ACM certificate on the origin, for anything beyond a short sample.

---

## Wiring AWS DevOps Agent to the alarm pipeline

The CDK app deploys the full pipeline that carries a firewall drop to AWS DevOps Agent:
the firewall increments `DroppedPackets` → an Amazon CloudWatch alarm transitions to `ALARM` →
the alarm publishes to the Amazon SNS topic → Amazon SNS invokes the `nf-devops-agent-webhook`
AWS Lambda function → the Lambda reads the webhook URL + signing secret from AWS Secrets Manager, builds
an incident payload, signs it with HMAC SHA-256, and POSTs it to the DevOps Agent webhook
→ the agent validates the signature and starts an investigation.

One-time setup connects the agent to that pipeline:

1. **Create a DevOps Agent Space.**
2. **Grant the Space read access to this account.**
3. **Configure the Space to assume the least-privilege role** from the `AgentRoleArn`
   output (or set the `devopsAgentPrincipal` context value to the Agent Space principal
   before deploying so the role trusts it).
4. **Configure the DevOps Agent webhook** and download the CSV with the webhook URL and
   signing secret.
5. **Store the credentials from the status page:**
   1. Open the status page using the `StatusPageUrl` output.
   2. Sign in with the `StatusPageUsername` output and the password from the AWS Secrets Manager secret named by the `StatusPagePasswordSecret` output.
   3. Choose **Configure webhook**.
   4. Paste the webhook URL and signing secret from the CSV.
   5. Save the configuration. The page writes `{"webhookUrl":"<url>","webhookSecret":"<secret>"}` to the `nf-devops-agent-webhook-credentials` secret (no AWS CLI or console step), and never displays the stored secret back. Until this is set, the bridge AWS Lambda function detects the placeholder value and skips delivery, so the deploy never blocks.
6. **Verify** by invoking the `nf-devops-agent-webhook` AWS Lambda function with a test Amazon SNS event;
   a `200` response and a test investigation in the DevOps Agent web app confirm the path.

Amazon SNS sits between CloudWatch and Lambda so delivery is retried on throttling, extra
subscribers (email, chat, ticketing) can be added without touching the alarms, and
cross-account alarms can feed one pipeline. Each scenario below fires the same pipeline;
the investigation/fix the agent produces is documented per scenario.

---

## Scenario 1: Domain deny list blocking a legitimate endpoint

**Requirements: R5.4, R5.5**

### Activate

```
npm run scenario activate 1
```

This adds the designated SaaS domain (`saasTestDomain`, default `docs.aws.amazon.com`) to the
`rg-domain` Suricata domain rule group as a `drop` rule that matches on the TLS SNI.

**Manual alternative (console):**

1. In the Amazon VPC console, navigate to AWS Network Firewall → Network Firewall rule groups.
2. Choose `rg-domain`.
3. Choose **Edit**.
4. Add a `drop` rule for the SaaS domain.
5. Configure the rule to match on the TLS SNI using Suricata syntax: `drop tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:"..."; ...)`.
6. For the `content` value, use the domain from the `saasTestDomain` context value (default `docs.aws.amazon.com`, the intentional real test domain; see `SECURITY.md`).
7. Save the changes.

Either way, the firewall's native `DroppedPackets` metric rises above its baseline and the
`Alarm-1` alarm fires.

### Trigger and verification

`curl https://<saasTestDomain>` from the test workload is dropped on the TLS SNI, so the
TLS request no longer completes. The activation verification confirms the trigger by
observing the blocked egress, an increase in `DroppedPackets` within 5 minutes, and an
ALERT log entry naming the blocked domain within 5 minutes.

### Expected DevOps Agent investigation

1. `FilterLogEvents` on the ALERT log group `/nf-devops-agent/alert` to find the
   drop event and read the blocked domain out of the alert entry.
2. `ListRuleGroups` and `DescribeRuleGroup` to locate the matching deny entry in the
   `rg-domain` domain rule group.

### Expected outcome and recommended fix

The agent surfaces the exact domain entry and the rule group it lives in (`rg-domain`),
and recommends **removing the deny entry, or adding an allow/exception** so the legitimate
endpoint is reachable again.

### Revert and revert-verification

```
npm run scenario revert 1
```

Reverting removes the SaaS domain's drop rule from the `rg-domain` rule group.
Revert-verification confirms baseline egress is restored: the workload can reach the
domain again within 5 minutes and no drop trigger is observed.

---

## Scenario 2: Stateless rule priority misconfiguration

**Requirements: R6.4, R6.5**

### Activate

```
npm run scenario activate 2
```

This inverts the rule priorities in the `rg-stateless-priority` stateless rule group so
the allow (pass) rule is ordered **after** the drop rule for the designated test traffic
class (baseline allow `100` < drop `200`; Scenario 2 allow `200` > drop `100`).

**Manual alternative (console):**

1. In the Amazon VPC console, navigate to AWS Network Firewall.
2. Choose Network Firewall rule groups.
3. Choose `rg-stateless-priority`.
4. Choose **Edit**.
5. Change the allow rule priority to `200`.
6. Change the drop rule priority to `100`.
7. Choose **Save**.

Either way, the `StatelessRuleFailures` health check begins failing and the
`Alarm-2` alarm fires.

### Trigger and verification

A TCP connect to the designated stateless test class target (TCP port `9142`, probed against
`cassandra.<region>.amazonaws.com:9142`) is dropped because the drop rule, now at the lower priority
value, is evaluated first. The activation verification confirms the blocked egress and an
increase in `DroppedPackets` within 5 minutes.

### Expected DevOps Agent investigation

1. `DescribeFirewallPolicy` on `nf-devops-agent-policy` to read the stateless rule
   group references.
2. `DescribeRuleGroup` on `rg-stateless-priority` to read each rule's priority value, and
   find the allow (pass) rule ordered after the drop rule (allow priority `200` greater
   than drop priority `100`).

### Expected outcome and recommended fix

The agent identifies the priority conflict and recommends **reordering the allow rule
ahead of the drop rule** (restore allow priority < drop priority) so the test traffic
class is forwarded.

### Revert and revert-verification

```
npm run scenario revert 2
```

Reverting restores the baseline priorities (allow `100` < drop `200`). Revert-verification
confirms the traffic to TCP `9142` is forwarded again and no drop trigger is observed.

---

## Scenario 3: Asymmetric cross-Availability-Zone routing drop

**Requirements: R7.4, R7.5**

### Activate

```
npm run scenario activate 3
```

This flips the protected subnet's egress route to the **other** AZ's firewall endpoint and
moves the workload's return route so egress and return traverse different endpoints. A
flow's SYN exits through one endpoint while its return arrives at a different endpoint that
never saw the SYN, so the handshake never completes. This is purely a routing fault. It
makes **no** firewall-policy change.

**Manual alternative (console):**

1. In the Amazon VPC console, navigate to Route tables.
2. Choose the protected-subnet-A route table.
3. Edit the `0.0.0.0/0` route to target the **other** AZ's firewall endpoint.
4. Choose **Save**.
5. Navigate to Route tables.
6. Choose the public-subnet-B route table.
7. Add a route for the workload subnet CIDR (`10.0.4.0/24`) targeting the **own**-AZ (AZ-a) firewall endpoint.
8. Choose **Save**.

Either way, the `AsymmetricFlowFailures` health check begins failing and the
`Alarm-3` alarm fires.

> **Scope (this scenario differs from 1 and 2).** The egress route change
> is a property of the WHOLE protected subnet, not one traffic class, so every
> outbound flow becomes asymmetric and ALL egress from the workload stops. The
> Scenario 1 and Scenario 2 health checks therefore also fail, and all three
> alarms move to `ALARM` at once. This is intentional. A routing fault has a
> wider scope than a single rule edit, and it is the case that shows AWS
> DevOps Agent correlating multiple alarms to one root cause. The status page
> detects this via a page-only control probe (an AWS endpoint no scenario rule
> targets): when that control probe also fails, the page shows a subnet-wide
> outage banner, marks the Scenario 3 card as the red root cause, and marks the
> Scenario 1 and 2 cards amber as `UNREACHABLE (collateral)` with a note that
> their own conditions are NOT firing.

### Trigger and verification

With the egress and return paths split across AZs, a new connection's SYN and its return
packets reach different firewall endpoints. Neither endpoint sees the whole flow, so the
handshake never completes and egress is dropped. The activation verification confirms the
drop and an increase in `DroppedPackets`, and checks for FLOW log drop entries within 60
seconds.

### Expected DevOps Agent investigation

1. `FilterLogEvents` on the FLOW log group `/nf-devops-agent/flow` to see drops
   clustered on one path/AZ rather than spread evenly, the signature of an asymmetric flow.
2. `DescribeRouteTables` on the protected and public subnet route tables to find the
   egress route pointing at the other AZ's firewall endpoint while the return route points
   at the own-AZ endpoint.
3. Correlate the three simultaneous alarms (`Alarm-1`,
   `Alarm-2`, `Alarm-3`) and the
   `ReplaceRoute` / `CreateRoute` CloudTrail events to one routing root cause,
   rather than treating the Scenario 1 and 2 alarms as separate incidents.

### Expected outcome and recommended fix

The agent identifies the asymmetric-flow condition and recommends **restoring symmetric
same-Availability-Zone routing** so a flow's egress and return traverse the same firewall endpoint and the
handshake completes. It attributes the Scenario 1 and 2 alarms to the same routing change
(collateral of the subnet-wide outage), not to their own conditions.

### Revert and revert-verification

```
npm run scenario revert 3
```

Reverting restores the same-AZ egress route and the symmetric return route. Revert-
verification confirms packets for the affected flow are no longer dropped, the control
probe recovers, all three alarms clear, and baseline egress is healthy (every status-page
card returns to green).

---

## Teardown

**Requirements: R10.4, R10.5**

Tear the entire environment down with a single command:

```
bash scripts/destroy.sh
```

`bash scripts/destroy.sh` (which calls `scenarioctl destroy`):

1. Reverts any active scenario to baseline first, so the teardown starts from a clean
   state (a failed revert is logged as a warning but does not stop the teardown).
2. Runs `cdk destroy --all --force` non-interactively.
3. On a clean destroy, reports success and that no tagged resources remain.
4. On a destroy failure, runs a tag-based straggler sweep and exits non-zero.

### Deletion order

`cdk destroy` hands the work to CloudFormation, which computes a dependency-aware deletion
order from the resource references in the synthesized templates. You do not specify the
order manually; the logical order it follows is:

1. **Logging configuration and firewall-endpoint routes are removed first.** The
   `CfnLoggingConfiguration` disassociates from the firewall, and the protected-subnet
   egress routes and IGW edge (ingress) routes that point at the firewall endpoints are
   deleted, before the subnets and VPC they belong to.
2. **The firewall, its policy, and the three rule groups are deleted before the VPC.** The
   firewall endpoints must be gone before their firewall subnets and the VPC can be
   removed.
3. **The S3 log bucket auto-empties and deletes.** **Warning: the S3 log bucket and all
   firewall logs it holds are permanently deleted during teardown. If you need to retain
   logs for compliance, audit, or analysis, export them to a separate location before
   running the teardown.** Because the bucket is provisioned with
   `autoDeleteObjects` and `RemovalPolicy.DESTROY`, CDK's custom resource empties it on
   delete so it is removed even with log objects present.
4. **Remaining resources** (CloudWatch log groups `/nf-devops-agent/alert` and
   `/nf-devops-agent/flow`, the three per-scenario alarms, the SNS topic, the webhook
   bridge Lambda and
   its `nf-devops-agent-webhook-credentials` Secrets Manager secret, the status-page
   CloudFront distribution, Application Load Balancer and its security group, the agent IAM role, the test workload and its
   instance role, the SSM interface endpoints, NAT gateways, the IGW, subnets, route
   tables, and the VPC) are deleted in the order their dependencies allow.

### Post-teardown verification sweep

When `cdk destroy` fails to remove a resource, `bash scripts/destroy.sh` runs a tag-based sweep
using the Resource Groups Tagging API (`GetResources`), filtered on
`Project = nf-devops-agent`. The sweep:

- Continues past individual page failures rather than stopping at the first error.
- Lists every remaining tagged resource (ARN and inferred type), or reports that none
  could be enumerated.
- Exits non-zero so the teardown is marked as completed with failures.

A clean teardown confirms no tagged resources remain. After a teardown with failures,
delete the listed resources manually and re-run `bash scripts/destroy.sh` to confirm the sweep
finds nothing tagged `Project = nf-devops-agent`.

## Conclusion

This runbook covers the three break-fix scenarios end to end (the domain deny list, the
stateless rule priority misconfiguration, and the asymmetric cross-Availability-Zone
routing drop), the full alarm pipeline that carries each drop to AWS DevOps Agent, and the
teardown order with its post-teardown verification sweep. Activate only one scenario at a
time, revert to the known-good baseline before activating another, and tear the
environment down the same day: the two AWS Network Firewall endpoints and two NAT gateways
bill hourly and are the dominant cost, so `bash scripts/destroy.sh` is the cost control.
