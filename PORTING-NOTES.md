# Porting Notes — Python → TypeScript (porting aid, safe to delete)

This file captures the semantics of the now-deleted Python modules
(`scenarioctl/state.py`, `policy.py`, `alarms.py`) so tasks 2–4 can port them to
TypeScript with their behavior preserved. The TypeScript field names switch from
`snake_case` to `camelCase` per the design's data model. **This file is a porting
aid and may be deleted once tasks 2–4 are complete.**

---

## 1. `state.py` → `src/scenarioctl/state.ts` (task 2)

Pure, side-effect-free scenario state machine. Drives CDK context (via
`toContext`) instead of Terraform tfvars (`to_tfvars`).

### Types
- `Scenario = "none" | "1" | "2" | "3" | "4"`
- `StreamExceptionPolicy = "CONTINUE" | "REJECT" | "DROP"`
- `LogDestination = "cloudwatch" | "s3"`
- `DesiredState` (all fields `readonly`):
  - `activeScenario: Scenario` — the selector, set by every scenario
  - `allowPriority: number` — Scenario 2 owned (baseline 100)
  - `dropPriority: number` — Scenario 2 owned (baseline 200)
  - `streamExceptionPolicy: StreamExceptionPolicy` — Scenario 3 owned (baseline CONTINUE)
  - `asymmetricRoute: boolean` — Scenario 3 owned (baseline false)
  - `domainDenyActive: boolean` — Scenario 1 owned (baseline false)
  - `regressionActive: boolean` — Scenario 4 owned (baseline false)
  - `s4ChangeTimestampUtc: string | null` — Scenario 4 owned (baseline null)
  - `logDestination: LogDestination` — deployment config, owned by NO scenario (baseline cloudwatch)
- `ScenarioContext` — same fields as `DesiredState` minus nothing; the plain object
  the stacks read back via `app.node.tryGetContext(...)`. Note `s4ChangeTimestampUtc`
  is rendered as `""` (empty string) when null (non-nullable context value).

### Baseline constants
- `_BASELINE_ALLOW_PRIORITY = 100`
- `_BASELINE_DROP_PRIORITY = 200`
- `baseline()` returns: `activeScenario="none"`, `allowPriority=100`, `dropPriority=200`,
  `streamExceptionPolicy="CONTINUE"`, `asymmetricRoute=false`, `domainDenyActive=false`,
  `regressionActive=false`, `s4ChangeTimestampUtc=null`, `logDestination="cloudwatch"`.

### Field ownership (the single-scenario invariant)
Each `desired(n)` flips ONLY the fields scenario `n` owns; everything else stays baseline:
| Scenario | Owned fields flipped |
|---|---|
| `"none"` | (none) |
| `"1"` | `domainDenyActive = true` |
| `"2"` | `allowPriority = 200`, `dropPriority = 100` (INVERTED from baseline so drop wins) |
| `"3"` | `streamExceptionPolicy = "DROP"`, `asymmetricRoute = true` |
| `"4"` | `regressionActive = true` (timestamp set only via `activate`) |

`activeScenario` is set to the scenario string by every non-none `desired(n)`.

### Functions
- `baseline(): DesiredState` — canonical "all working" state (constants above).
- `desired(scenario): DesiredState` — DETERMINISTIC pure map. Throws/raises on unknown
  scenario. Never records a timestamp (so `desired(n)` deep-equals `desired(n)` — Property 5).
  For "2" it inverts priorities (allow=200, drop=100). For "4" leaves `s4ChangeTimestampUtc=null`.
- `activate(scenario, now?): DesiredState` — imperative entry. Identical to `desired` for
  "none"/1/2/3; for "4" sets `s4ChangeTimestampUtc` to a non-null ISO-8601 UTC string with
  trailing `Z` (format `YYYY-MM-DDTHH:MM:SSZ`). `now` optional clock injection; naive→UTC,
  tz-aware→converted to UTC, default `Date.now()`/current UTC.
- `isActive(state): boolean` — `state.activeScenario !== "none"`.
- `toContext(state): ScenarioContext` — replaces Python `to_tfvars`. Deterministic.
  Renders `s4ChangeTimestampUtc` null → `""`. All values JSON-serializable.

### Invariants asserted by property tests (Properties 4–8, 10)
- P4 round-trip: `desired(n)` then `desired("none")` deep-equals `baseline()` (ignore timestamp metadata).
- P5 idempotence: `desired(n)` equals `desired(n)`; `toContext(desired(n))` stable.
- P6 single-scenario: distinct `n !== m` differ only in their own owned fields.
- P7 priority: `desired("2")` has `allowPriority > dropPriority`; baseline has `allowPriority < dropPriority`.
- P8 stream-exception: `desired("3")` is DROP + `asymmetricRoute=true`; baseline in {CONTINUE,REJECT} + `asymmetricRoute=false`.
- P10 timestamp: activate-path `desired("4")`/`activate("4")` has non-null ISO-8601 UTC `s4ChangeTimestampUtc`.

---

## 2. `policy.py` → `src/scenarioctl/policy.ts` (task 3)

Pure builder for the least-privilege DevOps Agent IAM policy document. No action wildcards (R4.6).

### Constants
- `POLICY_VERSION = "2012-10-17"`
- `NF_DESCRIBE_ACTIONS = ["network-firewall:DescribeFirewall", "network-firewall:DescribeFirewallPolicy", "network-firewall:DescribeRuleGroup"]`
- `NF_LIST_ACTIONS = ["network-firewall:ListFirewalls", "network-firewall:ListFirewallPolicies", "network-firewall:ListRuleGroups"]`
- `LOGS_READ_ACTIONS = ["logs:GetLogEvents", "logs:FilterLogEvents"]`
- `S3_READ_ACTIONS = ["s3:GetObject", "s3:ListBucket"]`
- `ALLOWED_ACTIONS = ReadonlySet` = union of the four tuples above (exact, complete allowlist).

### Types
- `PolicyInputs`: `firewallArn`, `policyArn`, `ruleGroupArns: readonly string[]`,
  `alertLogGroupArn`, `flowLogGroupArn`, `logDestination: LogDestination`, `s3BucketArn: string | null`.
- `PolicyStatementJson`: `{ Effect: "Allow"; Action: readonly string[]; Resource: ... }`
  (Python also includes a `Sid`; preserve `Sid`s — see below).
- `PolicyDocumentJson`: `{ Version: "2012-10-17"; Statement: readonly PolicyStatementJson[] }`.

### `buildAgentPolicy(inputs): PolicyDocumentJson`
Always emits 3 statements; adds a 4th iff `logDestination === "s3"`:
1. **`Sid: "NetworkFirewallDescribe"`** — `Effect: Allow`, `Action: NF_DESCRIBE_ACTIONS`,
   `Resource: [firewallArn, policyArn, ...ruleGroupArns]` (R4.1).
2. **`Sid: "NetworkFirewallList"`** — `Action: NF_LIST_ACTIONS`, `Resource: "*"`
   (resource wildcard, NOT an action wildcard — list actions are not resource-scopable) (R4.2, R4.6).
3. **`Sid: "CloudWatchLogsRead"`** — `Action: LOGS_READ_ACTIONS`,
   `Resource: [alertArn, alertArn + ":log-stream:*", flowArn, flowArn + ":log-stream:*"]` (R4.3).
   Helper `_log_group_resources(arn)` returns `[arn, arn + ":log-stream:*"]`.
4. **`Sid: "S3LogDestinationRead"`** (conditional, only if `logDestination==="s3"`) —
   `Action: S3_READ_ACTIONS`, `Resource: [s3BucketArn, s3BucketArn + "/*"]` (R4.5).

### Validation / throws
- Throw if `logDestination` not in {`cloudwatch`, `s3`}.
- Throw if `logDestination === "s3"` but `s3BucketArn` is missing/empty.

### Determinism
Deterministic for given inputs. Every emitted `Action` is a literal member of `ALLOWED_ACTIONS`
(by construction — actions drawn from the same tuples) → no `"*"`, no `service:*`, no mutating verb.

### Properties (1–3)
- P1 no action wildcards: every `Action` ∈ `ALLOWED_ACTIONS`; none `=== "*"` or matches `^[a-z0-9-]+:\*$`.
- P2 read-only: no `Action` contains `Create|Update|Delete|Put|Associate|Disassociate|Tag|Untag|Modify`.
- P3 S3 conditional: `s3:GetObject`/`s3:ListBucket` present iff `logDestination === "s3"`; else no `s3:*`.

---

## 3. `alarms.py` → `src/scenarioctl/alarms.ts` (task 4)

Pure builder for the two CloudWatch alarm configs, validating invariants on construction.

### Constants
- `NAMESPACE = "AWS/NetworkFirewall"`
- `DROPPED_PACKETS_METRIC = "DroppedPackets"`, `REJECTED_PACKETS_METRIC = "RejectedPackets"`
- Defaults: `DEFAULT_THRESHOLD = 1`, `DEFAULT_PERIOD_SECONDS = 60`, `DEFAULT_EVALUATION_PERIODS = 1`,
  `DEFAULT_DATAPOINTS_TO_ALARM = 1`, `DEFAULT_COMPARISON_OPERATOR = "GreaterThanOrEqualToThreshold"`,
  `DEFAULT_STATISTIC = "Sum"`.
- `ALLOWED_COMPARISON_OPERATORS = {GreaterThanOrEqualToThreshold, GreaterThanThreshold, LessThanThreshold, LessThanOrEqualToThreshold}`
- `ALLOWED_STATISTICS = {SampleCount, Average, Sum, Minimum, Maximum}`

### Type `AlarmConfig`
Fields: `metricName`, `namespace`, `threshold`, `periodSeconds`, `evaluationPeriods`,
`datapointsToAlarm`, `comparisonOperator`, `statistic`.

### Validation (Property 9, R3.4) — enforced on construction; throw on violation
- Reject boolean-like values for `threshold`/`periodSeconds`/`evaluationPeriods`/`datapointsToAlarm`
  (in Python, bool is an int subclass; in TS, reject `typeof === "boolean"`).
- Reject non-finite / NaN numbers.
- `threshold > 0`
- `periodSeconds > 0`
- `evaluationPeriods >= 1`
- `datapointsToAlarm >= 1`
- `datapointsToAlarm <= evaluationPeriods`
- `comparisonOperator ∈ ALLOWED_COMPARISON_OPERATORS`
- `statistic ∈ ALLOWED_STATISTICS`

### `buildAlarmConfigs(params?)` → pair `{ dropped, rejected }`
Both share threshold/period/evaluation params; differ only in `metricName`
(`DroppedPackets` vs `RejectedPackets`). All params default to the design values, so
`buildAlarmConfigs()` with no args yields the baseline pair. Validation happens via
`AlarmConfig` construction, so invalid params cause `buildAlarmConfigs` to throw.

### Property 9
For all generated configs: `threshold > 0`, `periodSeconds > 0`, `evaluationPeriods >= 1`,
`datapointsToAlarm <= evaluationPeriods`; the builder rejects violating inputs.
