/**
 * Unit tests for the scenario verification helpers (`src/scenarioctl/verify.ts`).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These are hermetic example-based unit tests. They NEVER touch AWS: each test
 * injects a fake AWS SDK v3 client (a plain object satisfying the module's
 * `*ClientLike` interface, whose `send` behavior the test controls per command
 * type) plus an injectable virtual clock (`now`) and `sleep` (a no-op that
 * advances the virtual clock and records intervals). No real timers are used,
 * so the bounded retry windows elapse deterministically and instantly.
 *
 * What is asserted:
 *   - `runEgressProbe` classifies SSM outcomes into `probe-error` (with the
 *     correct stage) vs `probe-ran` (with `egressSucceeded` derived from the
 *     curl ResponseCode), per R9.3/R9.6.
 *   - `verifyScenario` classifies a run into `trigger-observed` /
 *     `trigger-not-observed` / `probe-error`, and SKIPS the metric/log checks
 *     when the probe could not run.
 *   - `pollWithBackoff`, `checkDroppedPackets`, and `checkFlowLogs` keep their
 *     retries inside the configured window: bounded attempts, the poll stops
 *     once the window elapses (returns observed:false), and it stops early once
 *     the condition is observed.
 *
 * _Requirements: 9.3, 9.6_
 */

import {
  SendCommandCommand,
  GetCommandInvocationCommand,
  SendCommandCommandOutput,
  GetCommandInvocationCommandOutput,
} from "@aws-sdk/client-ssm";
import { GetMetricDataCommand, GetMetricDataCommandOutput } from "@aws-sdk/client-cloudwatch";
import {
  FilterLogEventsCommand,
  FilterLogEventsCommandOutput,
} from "@aws-sdk/client-cloudwatch-logs";

import {
  runEgressProbe,
  verifyScenario,
  checkDroppedPackets,
  checkFlowLogs,
  pollWithBackoff,
  DEFAULT_METRIC_WINDOW_MS,
  DEFAULT_POLL_INTERVAL_MS,
  DEFAULT_FLOW_LOG_WINDOW_MS,
  SsmClientLike,
  CloudWatchClientLike,
  CloudWatchLogsClientLike,
  NowFn,
  SleepFn,
  PollProbe,
} from "../src/scenarioctl/verify";

// ---------------------------------------------------------------------------
// Test doubles: a virtual clock and fake AWS SDK v3 clients
// ---------------------------------------------------------------------------

/**
 * A deterministic virtual clock. `now()` returns accumulated virtual time and
 * `sleep(ms)` advances it (the faithful model: time only passes when you wait).
 * No real timers, so windows elapse instantly. Records every slept interval.
 */
function createVirtualClock(): {
  now: NowFn;
  sleep: SleepFn;
  sleeps: number[];
  current: () => number;
} {
  let current = 0;
  const sleeps: number[] = [];
  const now: NowFn = () => current;
  const sleep: SleepFn = (ms) => {
    sleeps.push(ms);
    current += ms;
    return Promise.resolve();
  };
  return { now, sleep, sleeps, current: () => current };
}

/** Build an SDK-shaped error carrying a specific `name` (e.g. an error code). */
function namedError(name: string, message: string): Error {
  return Object.assign(new Error(message), { name });
}

interface FakeSsm {
  client: SsmClientLike;
  sendCommandCalls: () => number;
  getInvocationCalls: () => number;
}

/**
 * Fake SSM client. `onSendCommand` produces the `SendCommand` output (or throws
 * to simulate a dispatch failure); `onGetInvocation` produces each
 * `GetCommandInvocation` poll result (call index is 1-based).
 */
function createFakeSsm(opts: {
  onSendCommand: () => SendCommandCommandOutput;
  onGetInvocation: (call: number) => GetCommandInvocationCommandOutput;
}): FakeSsm {
  let sendCommandCalls = 0;
  let getInvocationCalls = 0;
  const send = async (
    command: SendCommandCommand | GetCommandInvocationCommand,
  ): Promise<unknown> => {
    if (command instanceof SendCommandCommand) {
      sendCommandCalls += 1;
      return opts.onSendCommand();
    }
    if (command instanceof GetCommandInvocationCommand) {
      getInvocationCalls += 1;
      return opts.onGetInvocation(getInvocationCalls);
    }
    throw new Error("Unexpected SSM command");
  };
  return {
    client: { send } as unknown as SsmClientLike,
    sendCommandCalls: () => sendCommandCalls,
    getInvocationCalls: () => getInvocationCalls,
  };
}

interface FakeCloudWatch {
  client: CloudWatchClientLike;
  calls: () => number;
}

/** Fake CloudWatch client; `handler(call)` returns each `GetMetricData` result. */
function createFakeCloudWatch(
  handler: (call: number) => GetMetricDataCommandOutput,
): FakeCloudWatch {
  let calls = 0;
  const client: CloudWatchClientLike = {
    send: async (_command: GetMetricDataCommand): Promise<GetMetricDataCommandOutput> => {
      calls += 1;
      return handler(calls);
    },
  };
  return { client, calls: () => calls };
}

interface FakeLogs {
  client: CloudWatchLogsClientLike;
  calls: () => number;
}

/** Fake CloudWatch Logs client; `handler(call)` returns each `FilterLogEvents` result. */
function createFakeLogs(
  handler: (call: number) => FilterLogEventsCommandOutput,
): FakeLogs {
  let calls = 0;
  const client: CloudWatchLogsClientLike = {
    send: async (_command: FilterLogEventsCommand): Promise<FilterLogEventsCommandOutput> => {
      calls += 1;
      return handler(calls);
    },
  };
  return { client, calls: () => calls };
}

// Convenience output builders ------------------------------------------------

function sendOk(commandId = "cmd-1234"): SendCommandCommandOutput {
  return { Command: { CommandId: commandId }, $metadata: {} };
}

function invocation(
  fields: Partial<GetCommandInvocationCommandOutput>,
): GetCommandInvocationCommandOutput {
  return { $metadata: {}, ...fields };
}

function metricResult(total: number): GetMetricDataCommandOutput {
  return {
    MetricDataResults: total > 0 ? [{ Id: "drops", Values: [total] }] : [{ Id: "drops", Values: [] }],
    $metadata: {},
  };
}

function logResult(messages: string[]): FilterLogEventsCommandOutput {
  return {
    events: messages.map((message) => ({ message })),
    $metadata: {},
  };
}

const PROBE_PARAMS = {
  instanceId: "i-0123456789abcdef0",
  targetUrl: "https://saas.example.com",
};

const SCENARIO_PARAMS = {
  ...PROBE_PARAMS,
  firewallName: "test-firewall",
  alertLogGroupName: "/nf/alert",
  flowLogGroupName: "/nf/flow",
};

// ---------------------------------------------------------------------------
// runEgressProbe — classification
// ---------------------------------------------------------------------------

describe("runEgressProbe classification", () => {
  it("classifies a SendCommand throw as probe-error at stage send-command", async () => {
    const clock = createVirtualClock();
    const ssm = createFakeSsm({
      onSendCommand: () => {
        throw new Error("transient SSM failure");
      },
      onGetInvocation: () => {
        throw new Error("should never be polled");
      },
    });

    const result = await runEgressProbe({
      ...PROBE_PARAMS,
      ssm: ssm.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(result.kind).toBe("probe-error");
    if (result.kind === "probe-error") {
      expect(result.stage).toBe("send-command");
    }
    // The probe never started, so the invocation poll must not have run.
    expect(ssm.getInvocationCalls()).toBe(0);
  });

  it("classifies an InvalidInstanceId SendCommand error as instance-not-managed", async () => {
    const clock = createVirtualClock();
    const ssm = createFakeSsm({
      onSendCommand: () => {
        throw namedError("InvalidInstanceId", "instance is not SSM-managed");
      },
      onGetInvocation: () => {
        throw new Error("should never be polled");
      },
    });

    const result = await runEgressProbe({
      ...PROBE_PARAMS,
      ssm: ssm.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(result.kind).toBe("probe-error");
    if (result.kind === "probe-error") {
      expect(result.stage).toBe("instance-not-managed");
    }
  });

  it("classifies a terminal Success with ResponseCode 0 as probe-ran (egress succeeded)", async () => {
    const clock = createVirtualClock();
    const ssm = createFakeSsm({
      onSendCommand: () => sendOk("cmd-success"),
      onGetInvocation: () =>
        invocation({
          Status: "Success",
          ResponseCode: 0,
          StandardOutputContent: "200",
          StandardErrorContent: "",
        }),
    });

    const result = await runEgressProbe({
      ...PROBE_PARAMS,
      ssm: ssm.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(result.kind).toBe("probe-ran");
    if (result.kind === "probe-ran") {
      expect(result.egressSucceeded).toBe(true);
      expect(result.responseCode).toBe(0);
      expect(result.httpCode).toBe("200");
      expect(result.ssmStatus).toBe("Success");
      expect(result.commandId).toBe("cmd-success");
    }
  });

  it("classifies a terminal non-zero ResponseCode (curl timeout 28) as probe-ran (egress blocked, NOT an error)", async () => {
    const clock = createVirtualClock();
    const ssm = createFakeSsm({
      onSendCommand: () => sendOk(),
      onGetInvocation: () =>
        invocation({
          // curl exits 28 on --max-time timeout: the firewall dropped the egress.
          Status: "Failed",
          ResponseCode: 28,
          StandardOutputContent: "000",
          StandardErrorContent: "curl: (28) Connection timed out",
        }),
    });

    const result = await runEgressProbe({
      ...PROBE_PARAMS,
      ssm: ssm.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    // A non-zero curl exit is a SUCCESSFUL probe that observed a drop.
    expect(result.kind).toBe("probe-ran");
    if (result.kind === "probe-ran") {
      expect(result.egressSucceeded).toBe(false);
      expect(result.responseCode).toBe(28);
    }
  });

  it("classifies ResponseCode -1 as probe-error at stage invocation-incomplete", async () => {
    const clock = createVirtualClock();
    const ssm = createFakeSsm({
      onSendCommand: () => sendOk(),
      onGetInvocation: () => invocation({ Status: "Failed", ResponseCode: -1 }),
    });

    const result = await runEgressProbe({
      ...PROBE_PARAMS,
      ssm: ssm.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(result.kind).toBe("probe-error");
    if (result.kind === "probe-error") {
      expect(result.stage).toBe("invocation-incomplete");
    }
  });

  it("classifies a never-terminal invocation as probe-error and keeps polling inside the bounded window", async () => {
    const clock = createVirtualClock();
    const commandTimeoutMs = 10_000;
    const pollIntervalMs = 2_000;
    const ssm = createFakeSsm({
      onSendCommand: () => sendOk(),
      // Never reaches a terminal status.
      onGetInvocation: () => invocation({ Status: "InProgress" }),
    });

    const result = await runEgressProbe({
      ...PROBE_PARAMS,
      ssm: ssm.client,
      commandTimeoutMs,
      pollIntervalMs,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(result.kind).toBe("probe-error");
    if (result.kind === "probe-error") {
      expect(result.stage).toBe("invocation-incomplete");
    }
    // Bounded retries: at most ceil(window/interval) + 1 polls, and the virtual
    // clock never advanced past the configured timeout window.
    const maxPolls = Math.ceil(commandTimeoutMs / pollIntervalMs) + 1;
    expect(ssm.getInvocationCalls()).toBeLessThanOrEqual(maxPolls);
    expect(ssm.getInvocationCalls()).toBeGreaterThan(1);
    expect(clock.current()).toBeLessThanOrEqual(commandTimeoutMs);
  });
});

// ---------------------------------------------------------------------------
// verifyScenario — classification
// ---------------------------------------------------------------------------

describe("verifyScenario classification", () => {
  it("returns probe-error and SKIPS the metric/log checks when the probe cannot run", async () => {
    const clock = createVirtualClock();
    const ssm = createFakeSsm({
      onSendCommand: () => {
        throw namedError("InvalidInstanceId", "instance is not SSM-managed");
      },
      onGetInvocation: () => {
        throw new Error("should never be polled");
      },
    });
    const cloudwatch = createFakeCloudWatch(() => metricResult(0));
    const logs = createFakeLogs(() => logResult([]));

    const result = await verifyScenario("1", {
      ...SCENARIO_PARAMS,
      ssm: ssm.client,
      cloudwatch: cloudwatch.client,
      logs: logs.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(result.kind).toBe("probe-error");
    // The verification is inconclusive, so metric/log reads must be skipped.
    expect(cloudwatch.calls()).toBe(0);
    expect(logs.calls()).toBe(0);
  });

  it("returns trigger-observed with egress-blocked when the probe shows a dropped egress", async () => {
    const clock = createVirtualClock();
    const ssm = createFakeSsm({
      onSendCommand: () => sendOk(),
      onGetInvocation: () => invocation({ Status: "Failed", ResponseCode: 28 }),
    });
    const cloudwatch = createFakeCloudWatch(() => metricResult(0));
    const logs = createFakeLogs(() => logResult([]));

    const result = await verifyScenario("1", {
      ...SCENARIO_PARAMS,
      ssm: ssm.client,
      cloudwatch: cloudwatch.client,
      logs: logs.client,
      // Keep the (here irrelevant) metric/alert checks to a single quick poll.
      metricWindowMs: 0,
      alertWindowMs: 0,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(result.kind).toBe("trigger-observed");
    if (result.kind === "trigger-observed") {
      expect(result.details.observedSignals).toContain("egress-blocked");
      expect(result.details.egressSucceeded).toBe(false);
    }
  });

  it("returns trigger-observed with dropped-packets-metric when egress succeeds but DroppedPackets >= 1", async () => {
    const clock = createVirtualClock();
    const ssm = createFakeSsm({
      onSendCommand: () => sendOk(),
      onGetInvocation: () =>
        invocation({ Status: "Success", ResponseCode: 0, StandardOutputContent: "200" }),
    });
    // First metric poll already reports a drop.
    const cloudwatch = createFakeCloudWatch(() => metricResult(5));
    const logs = createFakeLogs(() => logResult([]));

    // Scenario 2 checks only the DroppedPackets metric.
    const result = await verifyScenario("2", {
      ...SCENARIO_PARAMS,
      ssm: ssm.client,
      cloudwatch: cloudwatch.client,
      logs: logs.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(result.kind).toBe("trigger-observed");
    if (result.kind === "trigger-observed") {
      expect(result.details.observedSignals).toContain("dropped-packets-metric");
      // Egress itself succeeded, so the egress-blocked signal must be absent.
      expect(result.details.observedSignals).not.toContain("egress-blocked");
      expect(result.details.egressSucceeded).toBe(true);
    }
  });

  it("returns trigger-not-observed when the probe runs, egress succeeds, and no drop signal appears", async () => {
    const clock = createVirtualClock();
    const ssm = createFakeSsm({
      onSendCommand: () => sendOk(),
      onGetInvocation: () =>
        invocation({ Status: "Success", ResponseCode: 0, StandardOutputContent: "200" }),
    });
    const cloudwatch = createFakeCloudWatch(() => metricResult(0));
    const logs = createFakeLogs(() => logResult([]));

    const result = await verifyScenario("1", {
      ...SCENARIO_PARAMS,
      ssm: ssm.client,
      cloudwatch: cloudwatch.client,
      logs: logs.client,
      // One quick empty poll for each requested signal.
      metricWindowMs: 0,
      alertWindowMs: 0,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(result.kind).toBe("trigger-not-observed");
    if (result.kind === "trigger-not-observed") {
      expect(result.details.observedSignals).toHaveLength(0);
    }
  });
});

// ---------------------------------------------------------------------------
// Bounded retries — pollWithBackoff and the metric/log poll windows
// ---------------------------------------------------------------------------

describe("pollWithBackoff bounded retries", () => {
  it("stops once the window elapses (observed:false) with bounded attempts and elapsed <= window", async () => {
    const clock = createVirtualClock();
    const windowMs = 300_000;
    const intervalMs = 10_000;
    let calls = 0;

    const outcome = await pollWithBackoff<number>(
      async (): Promise<PollProbe<number>> => {
        calls += 1;
        return { observed: false, value: calls };
      },
      { maxWindowMs: windowMs, intervalMs, sleep: clock.sleep, now: clock.now },
    );

    expect(outcome.observed).toBe(false);
    // Retries stay inside the window: elapsed never exceeds it.
    expect(outcome.elapsedMs).toBeLessThanOrEqual(windowMs);
    // Attempts are bounded by ceil(window/interval) + 1.
    expect(outcome.attempts).toBeLessThanOrEqual(Math.ceil(windowMs / intervalMs) + 1);
    expect(outcome.attempts).toBe(calls);
    // It slept between attempts, but never longer than the configured interval,
    // and the cumulative wait never exceeded the window.
    for (const slept of clock.sleeps) {
      expect(slept).toBeLessThanOrEqual(intervalMs);
    }
    expect(clock.sleeps.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(windowMs);
  });

  it("stops early once the condition is observed", async () => {
    const clock = createVirtualClock();
    let calls = 0;

    const outcome = await pollWithBackoff<string>(
      async (): Promise<PollProbe<string>> => {
        calls += 1;
        // Observed on the third attempt.
        return { observed: calls === 3, value: `attempt-${calls}` };
      },
      { maxWindowMs: 300_000, intervalMs: 10_000, sleep: clock.sleep, now: clock.now },
    );

    expect(outcome.observed).toBe(true);
    expect(outcome.attempts).toBe(3);
    expect(calls).toBe(3);
    // Stopped early: only slept between the three attempts.
    expect(clock.sleeps).toHaveLength(2);
    expect(outcome.elapsedMs).toBeLessThan(300_000);
  });
});

describe("checkDroppedPackets / checkFlowLogs retry windows", () => {
  it("checkDroppedPackets polls within the 5-minute metric window and stops when it elapses", async () => {
    const clock = createVirtualClock();
    const cloudwatch = createFakeCloudWatch(() => metricResult(0)); // never observed

    const observation = await checkDroppedPackets({
      firewallName: "test-firewall",
      since: new Date(0),
      cloudwatch: cloudwatch.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(observation.observed).toBe(false);
    expect(observation.totalDropped).toBe(0);
    // Default metric window is 5 minutes; retries stay inside it.
    expect(observation.elapsedMs).toBeLessThanOrEqual(DEFAULT_METRIC_WINDOW_MS);
    const maxPolls = Math.ceil(DEFAULT_METRIC_WINDOW_MS / DEFAULT_POLL_INTERVAL_MS) + 1;
    expect(observation.attempts).toBeLessThanOrEqual(maxPolls);
    expect(cloudwatch.calls()).toBe(observation.attempts);
  });

  it("checkDroppedPackets stops early once DroppedPackets crosses the threshold", async () => {
    const clock = createVirtualClock();
    // Empty for the first two polls, then a drop appears.
    const cloudwatch = createFakeCloudWatch((call) => metricResult(call >= 3 ? 4 : 0));

    const observation = await checkDroppedPackets({
      firewallName: "test-firewall",
      since: new Date(0),
      cloudwatch: cloudwatch.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(observation.observed).toBe(true);
    expect(observation.totalDropped).toBeGreaterThanOrEqual(1);
    expect(observation.attempts).toBe(3);
    expect(observation.elapsedMs).toBeLessThan(DEFAULT_METRIC_WINDOW_MS);
  });

  it("checkFlowLogs polls within the 60-second flow window and stops when it elapses", async () => {
    const clock = createVirtualClock();
    const logs = createFakeLogs(() => logResult([])); // never any matching event

    const observation = await checkFlowLogs({
      logGroupName: "/nf/flow",
      since: new Date(0),
      logs: logs.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(observation.observed).toBe(false);
    expect(observation.matchCount).toBe(0);
    // Default flow window is 60 seconds; retries stay inside it.
    expect(observation.elapsedMs).toBeLessThanOrEqual(DEFAULT_FLOW_LOG_WINDOW_MS);
    const maxPolls = Math.ceil(DEFAULT_FLOW_LOG_WINDOW_MS / DEFAULT_POLL_INTERVAL_MS) + 1;
    expect(observation.attempts).toBeLessThanOrEqual(maxPolls);
  });

  it("checkFlowLogs stops early and reports samples once a matching event appears", async () => {
    const clock = createVirtualClock();
    // No events on the first poll, then a drop entry shows up.
    const logs = createFakeLogs((call) =>
      call >= 2 ? logResult(["flow drop disposition=drop"]) : logResult([]),
    );

    const observation = await checkFlowLogs({
      logGroupName: "/nf/flow",
      since: new Date(0),
      logs: logs.client,
      sleep: clock.sleep,
      now: clock.now,
    });

    expect(observation.observed).toBe(true);
    expect(observation.matchCount).toBeGreaterThanOrEqual(1);
    expect(observation.attempts).toBe(2);
    expect(observation.sampleMessages).toContain("flow drop disposition=drop");
    expect(observation.elapsedMs).toBeLessThan(DEFAULT_FLOW_LOG_WINDOW_MS);
  });
});
