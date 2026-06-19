/**
 * Scenario verification helpers (AWS-side, side-effecting).
 *
 * This module runs the egress probe and reads metrics/logs to confirm whether a
 * scenario's expected firewall-drop trigger occurred. It is the only
 * `scenarioctl` module besides `runner.ts` that touches AWS at runtime.
 *
 * It uses AWS SDK v3 clients:
 *   - `@aws-sdk/client-ssm`            — `SendCommand` + `GetCommandInvocation`
 *     to run a bounded `curl` egress probe on the test workload and poll it to a
 *     terminal state.
 *   - `@aws-sdk/client-cloudwatch`     — `GetMetricData` to read the
 *     `AWS/NetworkFirewall` `DroppedPackets` metric.
 *   - `@aws-sdk/client-cloudwatch-logs`— `FilterLogEvents` to read ALERT / FLOW
 *     log entries.
 *
 * Result classification contract (the core requirement, R9.3/R9.4/R9.6):
 *   - `"probe-error"`          — the probe itself could NOT run (AWS Systems
 *     Manager (SSM) SendCommand
 *     failed, the instance is not SSM-managed, the command invocation errored, or
 *     the command never reached a terminal state). The verification is
 *     inconclusive: we never observed whether the firewall would drop traffic.
 *   - `"trigger-not-observed"` — the probe ran fine but the expected drop signal
 *     was NOT seen inside the requirement window (e.g. baseline: egress
 *     succeeded; or scenario: no drop yet).
 *   - `"trigger-observed"`     — the expected drop signal WAS seen (egress
 *     blocked, `DroppedPackets` increased, or an ALERT/FLOW drop entry appeared).
 *
 * Bounded retries: every metric/log poll runs inside the requirement window via
 * {@link pollWithBackoff} — 5 minutes for the metric and ALERT log (R5.3, R5.4,
 * R8.2), 60 seconds for the FLOW log (R7.3), 120 seconds for routing (R7.1,
 * R7.6). All clocks (`now`) and waits (`sleep`) are injectable so task 14.3 can
 * drive the windows deterministically without real time passing.
 *
 * Testability: all three SDK clients are injectable. Each function accepts a
 * pre-constructed client (typed to a minimal `*ClientLike` interface that the
 * real SDK client satisfies) and falls back to a real client only when none is
 * supplied. Task 14.3 passes mocked clients; task 15 (the CLI) passes real ones.
 */

import {
  SSMClient,
  SendCommandCommand,
  GetCommandInvocationCommand,
  SendCommandCommandOutput,
  GetCommandInvocationCommandOutput,
} from "@aws-sdk/client-ssm";
import {
  CloudWatchClient,
  GetMetricDataCommand,
  GetMetricDataCommandOutput,
} from "@aws-sdk/client-cloudwatch";
import {
  CloudWatchLogsClient,
  FilterLogEventsCommand,
  FilterLogEventsCommandOutput,
} from "@aws-sdk/client-cloudwatch-logs";

import { Scenario } from "./state";

// ---------------------------------------------------------------------------
// Injectable client interfaces
// ---------------------------------------------------------------------------

/**
 * Minimal SSM client surface used by {@link runEgressProbe}. The real
 * `SSMClient` satisfies this; tests provide a stub with just `send`.
 */
export interface SsmClientLike {
  send(command: SendCommandCommand): Promise<SendCommandCommandOutput>;
  send(command: GetCommandInvocationCommand): Promise<GetCommandInvocationCommandOutput>;
}

/** Minimal CloudWatch client surface used by {@link checkDroppedPackets}. */
export interface CloudWatchClientLike {
  send(command: GetMetricDataCommand): Promise<GetMetricDataCommandOutput>;
}

/** Minimal CloudWatch Logs client surface used by {@link checkLogEvents}. */
export interface CloudWatchLogsClientLike {
  send(command: FilterLogEventsCommand): Promise<FilterLogEventsCommandOutput>;
}

// ---------------------------------------------------------------------------
// Window / timing defaults (match the requirement windows)
// ---------------------------------------------------------------------------

/** Metric propagation window: DroppedPackets within 5 minutes (R5.3, R8.2). */
export const DEFAULT_METRIC_WINDOW_MS = 300_000;

/** ALERT log propagation window: within 5 minutes of the drop (R5.4). */
export const DEFAULT_ALERT_LOG_WINDOW_MS = 300_000;

/** FLOW log propagation window: within 60 seconds of the drop (R7.3). */
export const DEFAULT_FLOW_LOG_WINDOW_MS = 60_000;

/** Routing-condition window: created/restored within 120 seconds (R7.1, R7.6). */
export const DEFAULT_ROUTING_WINDOW_MS = 120_000;

/** Default interval between metric/log polls. */
export const DEFAULT_POLL_INTERVAL_MS = 10_000;

/** Default ceiling for polling the SSM command to a terminal state. */
export const DEFAULT_PROBE_COMMAND_TIMEOUT_MS = 60_000;

/** Default interval between SSM `GetCommandInvocation` polls. */
export const DEFAULT_PROBE_POLL_INTERVAL_MS = 2_000;

/** Default `curl --max-time` for the egress probe, in seconds. */
export const DEFAULT_CURL_MAX_TIME_SECONDS = 10;

/** Minimum summed DroppedPackets that counts as an observed metric trigger. */
export const DEFAULT_MIN_DROPPED_PACKETS = 1;

/** SSM document used to run the shell probe. */
const SSM_SHELL_DOCUMENT = "AWS-RunShellScript";

/** SSM command-invocation statuses that are terminal. */
const TERMINAL_SSM_STATUSES: ReadonlySet<string> = new Set<string>([
  "Success",
  "Failed",
  "Cancelled",
  "TimedOut",
]);

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

/** Injectable clock; defaults to {@link Date.now}. */
export type NowFn = () => number;

/** Injectable async wait; defaults to a real `setTimeout`. */
export type SleepFn = (ms: number) => Promise<void>;

const realSleep: SleepFn = (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const realNow: NowFn = () => Date.now();

/** Best-effort extraction of an error's `name` (e.g. an SDK error code). */
function errorName(error: unknown): string {
  if (error && typeof error === "object" && "name" in error) {
    const name = (error as { name?: unknown }).name;
    if (typeof name === "string") {
      return name;
    }
  }
  return "";
}

/** Best-effort extraction of an error message. */
function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

// ---------------------------------------------------------------------------
// pollWithBackoff
// ---------------------------------------------------------------------------

/** Options controlling {@link pollWithBackoff}. */
export interface PollOptions {
  /** Total time budget for polling, in milliseconds. */
  readonly maxWindowMs: number;
  /** Wait between attempts, in milliseconds. */
  readonly intervalMs: number;
  /** Injectable wait (defaults to real `setTimeout`). */
  readonly sleep?: SleepFn;
  /** Injectable clock (defaults to `Date.now`). */
  readonly now?: NowFn;
}

/** What a single poll attempt produced and whether it satisfied the predicate. */
export interface PollProbe<T> {
  /** Whether the awaited condition was satisfied on this attempt. */
  readonly observed: boolean;
  /** The value produced this attempt (returned as `lastValue`). */
  readonly value: T;
}

/** Outcome of a bounded poll. */
export interface PollOutcome<T> {
  /** Whether the condition was observed before the window elapsed. */
  readonly observed: boolean;
  /** Number of times `fn` was invoked (always >= 1). */
  readonly attempts: number;
  /** Elapsed wall-clock time, in milliseconds, measured via `now`. */
  readonly elapsedMs: number;
  /** The value produced by the last attempt, if any. */
  readonly lastValue: T | undefined;
}

/**
 * Invoke `fn` repeatedly until it reports `observed: true` or the `maxWindowMs`
 * budget elapses, sleeping `intervalMs` between attempts (clamped so it never
 * sleeps past the window). `fn` always runs at least once. Returns whether the
 * condition was observed plus diagnostics.
 *
 * Clock and sleep are injectable so tests can exhaust the window without real
 * delay and assert that retries stayed inside the requirement window.
 */
export async function pollWithBackoff<T>(
  fn: () => Promise<PollProbe<T>>,
  options: PollOptions,
): Promise<PollOutcome<T>> {
  const now = options.now ?? realNow;
  const sleep = options.sleep ?? realSleep;
  const start = now();
  let attempts = 0;
  let lastValue: T | undefined;

  for (;;) {
    attempts += 1;
    const probe = await fn();
    lastValue = probe.value;
    if (probe.observed) {
      return { observed: true, attempts, elapsedMs: now() - start, lastValue };
    }
    const elapsed = now() - start;
    const remaining = options.maxWindowMs - elapsed;
    if (remaining <= 0) {
      return { observed: false, attempts, elapsedMs: elapsed, lastValue };
    }
    await sleep(Math.min(options.intervalMs, remaining));
  }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** Stages at which the egress probe can fail to run (i.e. `probe-error`). */
export type ProbeErrorStage =
  | "send-command"
  | "instance-not-managed"
  | "poll-invocation"
  | "invocation-incomplete";

/**
 * The probe could not be run, so the verification is inconclusive. This is
 * distinct from "trigger-not-observed", where the probe ran but no drop was
 * seen.
 */
export interface ProbeError {
  readonly kind: "probe-error";
  /** Where in the probe lifecycle the failure occurred. */
  readonly stage: ProbeErrorStage;
  /** Human-readable explanation (includes the underlying SDK error message). */
  readonly message: string;
}

/** The egress probe ran to a terminal SSM state and produced an exit/HTTP code. */
export interface EgressProbeRan {
  readonly kind: "probe-ran";
  /**
   * True when `curl` connected and completed (response code 0). False when the
   * connection was dropped/blocked (non-zero `curl` exit) — the scenario
   * manifestation, not a probe failure.
   */
  readonly egressSucceeded: boolean;
  /** HTTP status code parsed from `curl`'s `%{http_code}` (e.g. `"200"`), or null. */
  readonly httpCode: string | null;
  /** The SSM `ResponseCode` (the `curl` process exit code), or null if absent. */
  readonly responseCode: number | null;
  /** Terminal SSM command-invocation status (`Success` / `Failed` / ...). */
  readonly ssmStatus: string;
  /** The SSM command id (useful for operator drill-down). */
  readonly commandId: string;
  /** Captured stdout (`%{http_code}` output). */
  readonly stdout: string;
  /** Captured stderr. */
  readonly stderr: string;
}

/** Either the probe ran (to a terminal state) or it could not run. */
export type EgressProbeResult = EgressProbeRan | ProbeError;

/** What a DroppedPackets metric read observed. */
export interface MetricObservation {
  /** True when the summed DroppedPackets met the minimum within the window. */
  readonly observed: boolean;
  /** The largest summed DroppedPackets datapoint seen. */
  readonly totalDropped: number;
  /** Poll attempts made. */
  readonly attempts: number;
  /** Elapsed polling time in milliseconds. */
  readonly elapsedMs: number;
}

/** What a FilterLogEvents read observed. */
export interface LogObservation {
  /** True when at least one matching log event was found within the window. */
  readonly observed: boolean;
  /** Number of matching events seen on the successful (or final) attempt. */
  readonly matchCount: number;
  /** A few sample messages for operator/agent context. */
  readonly sampleMessages: readonly string[];
  /** Poll attempts made. */
  readonly attempts: number;
  /** Elapsed polling time in milliseconds. */
  readonly elapsedMs: number;
}

/** Aggregated evidence backing a {@link VerificationResult}. */
export interface VerificationDetails {
  /** The scenario this verification targeted. */
  readonly scenario: Scenario;
  /** The terminal egress-probe result. */
  readonly probe: EgressProbeRan;
  /** Convenience mirror of `probe.egressSucceeded`. */
  readonly egressSucceeded: boolean;
  /** DroppedPackets metric observation, when a metric check was requested. */
  readonly metric?: MetricObservation;
  /** ALERT log observation, when an alert-log check was requested. */
  readonly alertLog?: LogObservation;
  /** FLOW log observation, when a flow-log check was requested. */
  readonly flowLog?: LogObservation;
  /** Names of the drop signals that were observed (empty when none). */
  readonly observedSignals: readonly string[];
}

/**
 * The outcome of verifying a scenario. `probe-error` means the probe could not
 * run; the other two mean it ran and either did or did not see the drop trigger.
 */
export type VerificationResult =
  | { readonly kind: "trigger-observed"; readonly details: VerificationDetails }
  | { readonly kind: "trigger-not-observed"; readonly details: VerificationDetails }
  | ProbeError;

// ---------------------------------------------------------------------------
// Egress probe (SSM)
// ---------------------------------------------------------------------------

/** Parameters for {@link runEgressProbe}. */
export interface RunEgressProbeParams {
  /** The SSM-managed test workload instance id. */
  readonly instanceId: string;
  /** The URL the probe `curl`s (the affected egress target). */
  readonly targetUrl: string;
  /** Pre-constructed SSM client; a real client is created when omitted. */
  readonly ssm?: SsmClientLike;
  /** `curl --max-time` in seconds (default 10). */
  readonly maxTimeSeconds?: number;
  /** Ceiling for polling the command to terminal state (default 60s). */
  readonly commandTimeoutMs?: number;
  /** Interval between `GetCommandInvocation` polls (default 2s). */
  readonly pollIntervalMs?: number;
  /** Injectable wait. */
  readonly sleep?: SleepFn;
  /** Injectable clock. */
  readonly now?: NowFn;
}

/**
 * Validate that a value can be safely single-quoted inside the shell command.
 * Rejects single quotes and newlines, which would break out of the quoting.
 */
function assertShellSafe(label: string, value: string): void {
  if (value.includes("'") || value.includes("\n") || value.includes("\r")) {
    throw new Error(`${label} contains characters that cannot be safely quoted: ${value}`);
  }
}

/**
 * Build the bounded `curl` command. Writes the HTTP status code to stdout and
 * suppresses the body, capped by `--max-time`. The URL is single-quoted (and
 * validated by {@link assertShellSafe}) to avoid shell injection.
 *
 * `-k` allows the self-signed certificate the test endpoint serves (the probe
 * only measures connect success vs a firewall-drop timeout, not cert validity).
 * If `NF_PROBE_SECRET` is set, it is sent as the `X-Probe-Secret` header so the
 * endpoint's shared-secret gate is satisfied; there is NO hardcoded fallback, so
 * nothing predictable ships in the code. The header is optional for correctness:
 * the probe classifies any completed connection as egress-succeeded, so even
 * without the header a reachable endpoint returns a response (HTTP 403) rather
 * than a firewall-drop timeout.
 */
function buildCurlCommand(targetUrl: string, maxTimeSeconds: number): string {
  const secret = process.env.NF_PROBE_SECRET;
  const hdr = secret ? `-H 'X-Probe-Secret: ${secret}' ` : "";
  return `curl -sS -k ${hdr}-o /dev/null -w "%{http_code}" --max-time ${maxTimeSeconds} '${targetUrl}'`;
}

/**
 * Run the egress probe on the workload via SSM `SendCommand` (`AWS-RunShellScript`
 * running a bounded `curl`), then poll `GetCommandInvocation` until the command
 * reaches a terminal state.
 *
 * Classification:
 *   - SendCommand throwing (incl. the instance not being SSM-managed) →
 *     `probe-error`.
 *   - The invocation never reaching a terminal state within `commandTimeoutMs`,
 *     or polling erroring → `probe-error`.
 *   - A terminal invocation with a real `ResponseCode` → `probe-ran`, where
 *     `egressSucceeded = (ResponseCode === 0)`. A non-zero `curl` exit (egress
 *     blocked) is a successful PROBE that observed a drop, not a probe error.
 *   - A terminal status without a usable `ResponseCode` (e.g. `-1`, meaning the
 *     command never started on the node) → `probe-error`.
 */
export async function runEgressProbe(params: RunEgressProbeParams): Promise<EgressProbeResult> {
  const ssm: SsmClientLike = params.ssm ?? new SSMClient({});
  const maxTimeSeconds = params.maxTimeSeconds ?? DEFAULT_CURL_MAX_TIME_SECONDS;
  const commandTimeoutMs = params.commandTimeoutMs ?? DEFAULT_PROBE_COMMAND_TIMEOUT_MS;
  const pollIntervalMs = params.pollIntervalMs ?? DEFAULT_PROBE_POLL_INTERVAL_MS;

  assertShellSafe("targetUrl", params.targetUrl);
  assertShellSafe("instanceId", params.instanceId);

  const command = buildCurlCommand(params.targetUrl, maxTimeSeconds);

  // 1) Dispatch the command.
  let sent: SendCommandCommandOutput;
  try {
    sent = await ssm.send(
      new SendCommandCommand({
        InstanceIds: [params.instanceId],
        DocumentName: SSM_SHELL_DOCUMENT,
        Comment: "scenarioctl egress probe",
        TimeoutSeconds: Math.max(maxTimeSeconds + 5, Math.ceil(commandTimeoutMs / 1000)),
        Parameters: {
          commands: [command],
          executionTimeout: [String(maxTimeSeconds + 5)],
        },
      }),
    );
  } catch (error) {
    const name = errorName(error);
    // InvalidInstanceId is SSM's signal that the instance is not managed/online.
    const stage: ProbeErrorStage =
      name === "InvalidInstanceId" ? "instance-not-managed" : "send-command";
    return {
      kind: "probe-error",
      stage,
      message: `SSM SendCommand failed (${name || "unknown"}): ${errorMessage(error)}`,
    };
  }

  const commandId = sent.Command?.CommandId;
  if (!commandId) {
    return {
      kind: "probe-error",
      stage: "send-command",
      message: "SSM SendCommand returned no CommandId",
    };
  }

  // 2) Poll until terminal (or the window elapses).
  let pollError: ProbeError | undefined;
  const outcome = await pollWithBackoff<GetCommandInvocationCommandOutput | undefined>(
    async () => {
      try {
        const invocation = await ssm.send(
          new GetCommandInvocationCommand({ CommandId: commandId, InstanceId: params.instanceId }),
        );
        const status = invocation.Status ?? "";
        return { observed: TERMINAL_SSM_STATUSES.has(status), value: invocation };
      } catch (error) {
        // The invocation record is eventually consistent; keep polling on the
        // benign "not yet registered" error, fail on anything else.
        if (errorName(error) === "InvocationDoesNotExist") {
          return { observed: false, value: undefined };
        }
        pollError = {
          kind: "probe-error",
          stage: "poll-invocation",
          message: `SSM GetCommandInvocation failed (${errorName(error) || "unknown"}): ${errorMessage(error)}`,
        };
        return { observed: true, value: undefined };
      }
    },
    {
      maxWindowMs: commandTimeoutMs,
      intervalMs: pollIntervalMs,
      sleep: params.sleep,
      now: params.now,
    },
  );

  if (pollError) {
    return pollError;
  }

  const invocation = outcome.lastValue;
  if (!outcome.observed || !invocation) {
    return {
      kind: "probe-error",
      stage: "invocation-incomplete",
      message: `SSM command ${commandId} did not reach a terminal state within ${commandTimeoutMs}ms`,
    };
  }

  const status = invocation.Status ?? "";
  const responseCode = invocation.ResponseCode;
  const stdout = invocation.StandardOutputContent ?? "";
  const stderr = invocation.StandardErrorContent ?? "";

  // A ResponseCode of -1 means the command never started on the node — the probe
  // could not actually run, so this is a probe-error, not a drop observation.
  if (responseCode === undefined || responseCode === null || responseCode < 0) {
    return {
      kind: "probe-error",
      stage: "invocation-incomplete",
      message: `SSM command ${commandId} ended in status "${status}" without a usable ResponseCode`,
    };
  }

  return {
    kind: "probe-ran",
    egressSucceeded: responseCode === 0,
    httpCode: parseHttpCode(stdout),
    responseCode,
    ssmStatus: status,
    commandId,
    stdout,
    stderr,
  };
}

/** Extract a trailing HTTP status code (e.g. `"200"`) from `curl` stdout, if present. */
function parseHttpCode(stdout: string): string | null {
  const match = stdout.trim().match(/(\d{3})\s*$/);
  return match ? match[1] : null;
}

// ---------------------------------------------------------------------------
// Metric check (CloudWatch GetMetricData)
// ---------------------------------------------------------------------------

/** Parameters for {@link checkDroppedPackets}. */
export interface CheckDroppedPacketsParams {
  /** The deployed firewall name (the `FirewallName` metric dimension). */
  readonly firewallName: string;
  /** Lower bound of the metric query window. */
  readonly since: Date;
  /** Pre-constructed CloudWatch client; a real client is created when omitted. */
  readonly cloudwatch?: CloudWatchClientLike;
  /** Total polling budget (default 5 minutes). */
  readonly windowMs?: number;
  /** Interval between metric polls (default 10s). */
  readonly intervalMs?: number;
  /** Minimum summed DroppedPackets that counts as observed (default 1). */
  readonly minDropped?: number;
  /** Metric period in seconds (default 60). */
  readonly periodSeconds?: number;
  /** Injectable wait. */
  readonly sleep?: SleepFn;
  /** Injectable clock. */
  readonly now?: NowFn;
}

/** Validate a firewall name before interpolating it into a Metrics Insights query. */
function assertMetricNameSafe(firewallName: string): void {
  if (!/^[A-Za-z0-9._-]+$/.test(firewallName)) {
    throw new Error(`firewallName is not a safe metric dimension value: ${firewallName}`);
  }
}

/**
 * Poll `GetMetricData` for the `AWS/NetworkFirewall` `DroppedPackets` metric
 * summed across the firewall's AZ/engine dimensions, until the summed value
 * meets `minDropped` or the window elapses. Uses a CloudWatch Metrics Insights
 * `SELECT SUM(...)` expression so a single query covers both AZ endpoints.
 */
export async function checkDroppedPackets(
  params: CheckDroppedPacketsParams,
): Promise<MetricObservation> {
  const cloudwatch = params.cloudwatch ?? new CloudWatchClient({});
  const windowMs = params.windowMs ?? DEFAULT_METRIC_WINDOW_MS;
  const intervalMs = params.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const minDropped = params.minDropped ?? DEFAULT_MIN_DROPPED_PACKETS;
  const periodSeconds = params.periodSeconds ?? 60;

  assertMetricNameSafe(params.firewallName);
  const expression =
    `SELECT SUM(DroppedPackets) FROM "AWS/NetworkFirewall" WHERE FirewallName = '${params.firewallName}'`;

  let maxTotal = 0;
  const outcome = await pollWithBackoff<number>(
    async () => {
      const endTime = new Date((params.now ?? realNow)());
      const response = await cloudwatch.send(
        new GetMetricDataCommand({
          StartTime: params.since,
          EndTime: endTime,
          ScanBy: "TimestampDescending",
          MetricDataQueries: [
            {
              Id: "drops",
              Expression: expression,
              Period: periodSeconds,
            },
          ],
        }),
      );
      const total = sumMetricValues(response);
      if (total > maxTotal) {
        maxTotal = total;
      }
      return { observed: maxTotal >= minDropped, value: maxTotal };
    },
    { maxWindowMs: windowMs, intervalMs, sleep: params.sleep, now: params.now },
  );

  return {
    observed: outcome.observed,
    totalDropped: maxTotal,
    attempts: outcome.attempts,
    elapsedMs: outcome.elapsedMs,
  };
}

/** Sum every datapoint across every returned metric-data result. */
function sumMetricValues(response: GetMetricDataCommandOutput): number {
  let total = 0;
  for (const result of response.MetricDataResults ?? []) {
    for (const value of result.Values ?? []) {
      total += value;
    }
  }
  return total;
}

// ---------------------------------------------------------------------------
// Log checks (CloudWatch Logs FilterLogEvents)
// ---------------------------------------------------------------------------

/** Parameters for {@link checkLogEvents}, {@link checkAlertLogs}, {@link checkFlowLogs}. */
export interface CheckLogEventsParams {
  /** The CloudWatch Logs log group to search. */
  readonly logGroupName: string;
  /** Lower bound of the search window. */
  readonly since: Date;
  /** CloudWatch Logs filter pattern (default: match all events). */
  readonly filterPattern?: string;
  /** Pre-constructed Logs client; a real client is created when omitted. */
  readonly logs?: CloudWatchLogsClientLike;
  /** Total polling budget (default 5 minutes for alert, 60s for flow). */
  readonly windowMs?: number;
  /** Interval between log polls (default 10s). */
  readonly intervalMs?: number;
  /** Max sample messages to retain (default 3). */
  readonly sampleLimit?: number;
  /** Injectable wait. */
  readonly sleep?: SleepFn;
  /** Injectable clock. */
  readonly now?: NowFn;
}

/**
 * Poll `FilterLogEvents` on `logGroupName` for events matching `filterPattern`
 * since `since`, until at least one event matches or the window elapses. Returns
 * the match count and a few sample messages.
 */
export async function checkLogEvents(params: CheckLogEventsParams): Promise<LogObservation> {
  const logs = params.logs ?? new CloudWatchLogsClient({});
  const windowMs = params.windowMs ?? DEFAULT_ALERT_LOG_WINDOW_MS;
  const intervalMs = params.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const sampleLimit = params.sampleLimit ?? 3;
  const startTime = params.since.getTime();

  let matchCount = 0;
  let sampleMessages: string[] = [];

  const outcome = await pollWithBackoff<number>(
    async () => {
      const response = await logs.send(
        new FilterLogEventsCommand({
          logGroupName: params.logGroupName,
          startTime,
          filterPattern: params.filterPattern ?? "",
        }),
      );
      const events = response.events ?? [];
      if (events.length > 0) {
        matchCount = events.length;
        sampleMessages = events
          .slice(0, sampleLimit)
          .map((event) => event.message ?? "")
          .filter((message) => message.length > 0);
      }
      return { observed: events.length > 0, value: events.length };
    },
    { maxWindowMs: windowMs, intervalMs, sleep: params.sleep, now: params.now },
  );

  return {
    observed: outcome.observed,
    matchCount,
    sampleMessages,
    attempts: outcome.attempts,
    elapsedMs: outcome.elapsedMs,
  };
}

/** Check the ALERT log group (5-minute window by default, R5.4). */
export function checkAlertLogs(params: CheckLogEventsParams): Promise<LogObservation> {
  return checkLogEvents({ windowMs: DEFAULT_ALERT_LOG_WINDOW_MS, ...params });
}

/** Check the FLOW log group (60-second window by default, R7.3). */
export function checkFlowLogs(params: CheckLogEventsParams): Promise<LogObservation> {
  return checkLogEvents({ windowMs: DEFAULT_FLOW_LOG_WINDOW_MS, ...params });
}

// ---------------------------------------------------------------------------
// verifyScenario (higher-level orchestration)
// ---------------------------------------------------------------------------

/** Which drop signals a scenario verification should check. */
export interface ScenarioChecks {
  readonly metric: boolean;
  readonly alertLog: boolean;
  readonly flowLog: boolean;
}

/** Per-scenario default signal selection (mirrors the scenario→manifestation map). */
const SCENARIO_CHECKS: Readonly<Record<Scenario, ScenarioChecks>> = {
  none: { metric: false, alertLog: false, flowLog: false },
  "1": { metric: true, alertLog: true, flowLog: false },
  "2": { metric: true, alertLog: false, flowLog: false },
  "3": { metric: true, alertLog: false, flowLog: true },
};

/** Parameters for {@link verifyScenario}. */
export interface VerifyScenarioParams {
  /** SSM-managed workload instance id. */
  readonly instanceId: string;
  /** Egress target the probe `curl`s. */
  readonly targetUrl: string;
  /** Deployed firewall name (for the metric check). */
  readonly firewallName: string;
  /** ALERT log group name. */
  readonly alertLogGroupName: string;
  /** FLOW log group name. */
  readonly flowLogGroupName: string;
  /** Override which signals to check (defaults derived from the scenario). */
  readonly checks?: Partial<ScenarioChecks>;
  /** Filter pattern for the ALERT log check (e.g. the blocked domain). */
  readonly alertFilterPattern?: string;
  /** Filter pattern for the FLOW log check (e.g. a drop disposition). */
  readonly flowFilterPattern?: string;
  /** Lower bound for metric/log queries (defaults to just before the probe). */
  readonly since?: Date;
  /** Window overrides. */
  readonly metricWindowMs?: number;
  readonly alertWindowMs?: number;
  readonly flowWindowMs?: number;
  /** Injectable clients. */
  readonly ssm?: SsmClientLike;
  readonly cloudwatch?: CloudWatchClientLike;
  readonly logs?: CloudWatchLogsClientLike;
  /** Injectable timing. */
  readonly sleep?: SleepFn;
  readonly now?: NowFn;
}

/**
 * Run the egress probe and, if it ran, check the scenario's expected drop
 * signals, returning a {@link VerificationResult}.
 *
 * The "trigger" is uniformly "the firewall dropped the affected egress": it is
 * observed when egress is blocked, OR the DroppedPackets metric increased, OR a
 * matching ALERT/FLOW drop entry appeared. Baseline (`"none"`) verification
 * therefore expects `trigger-not-observed` (healthy egress); scenario
 * verification expects `trigger-observed`. The caller (the CLI) interprets which
 * outcome is the success case for its command.
 *
 * If the probe could not run, returns `probe-error` immediately — the metric and
 * log checks are skipped because the verification is inconclusive.
 */
export async function verifyScenario(
  scenario: Scenario,
  params: VerifyScenarioParams,
): Promise<VerificationResult> {
  const since = params.since ?? new Date((params.now ?? realNow)());

  const probe = await runEgressProbe({
    instanceId: params.instanceId,
    targetUrl: params.targetUrl,
    ssm: params.ssm,
    sleep: params.sleep,
    now: params.now,
  });
  if (probe.kind === "probe-error") {
    return probe;
  }

  const checks: ScenarioChecks = { ...SCENARIO_CHECKS[scenario], ...params.checks };
  const observedSignals: string[] = [];

  // Egress being blocked is itself a direct drop signal.
  if (!probe.egressSucceeded) {
    observedSignals.push("egress-blocked");
  }

  let metric: MetricObservation | undefined;
  if (checks.metric) {
    metric = await checkDroppedPackets({
      firewallName: params.firewallName,
      since,
      cloudwatch: params.cloudwatch,
      windowMs: params.metricWindowMs ?? DEFAULT_METRIC_WINDOW_MS,
      sleep: params.sleep,
      now: params.now,
    });
    if (metric.observed) {
      observedSignals.push("dropped-packets-metric");
    }
  }

  let alertLog: LogObservation | undefined;
  if (checks.alertLog) {
    alertLog = await checkAlertLogs({
      logGroupName: params.alertLogGroupName,
      since,
      filterPattern: params.alertFilterPattern,
      logs: params.logs,
      windowMs: params.alertWindowMs ?? DEFAULT_ALERT_LOG_WINDOW_MS,
      sleep: params.sleep,
      now: params.now,
    });
    if (alertLog.observed) {
      observedSignals.push("alert-log");
    }
  }

  let flowLog: LogObservation | undefined;
  if (checks.flowLog) {
    flowLog = await checkFlowLogs({
      logGroupName: params.flowLogGroupName,
      since,
      filterPattern: params.flowFilterPattern,
      logs: params.logs,
      windowMs: params.flowWindowMs ?? DEFAULT_FLOW_LOG_WINDOW_MS,
      sleep: params.sleep,
      now: params.now,
    });
    if (flowLog.observed) {
      observedSignals.push("flow-log");
    }
  }

  const details: VerificationDetails = {
    scenario,
    probe,
    egressSucceeded: probe.egressSucceeded,
    metric,
    alertLog,
    flowLog,
    observedSignals,
  };

  return observedSignals.length > 0
    ? { kind: "trigger-observed", details }
    : { kind: "trigger-not-observed", details };
}
