/**
 * Unit tests for the `destroy` teardown verb and its tag-based straggler sweep
 * (`src/scenarioctl/cli.ts`).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These are hermetic, example-based unit tests. They NEVER touch AWS:
 *
 *   - Layer A drives `runDestroy(deps)` through a fully mocked {@link CliDeps}.
 *     Only `destroy` / `sweepTaggedResources` / `deploy` / `readState` are
 *     overridden per test; `log` and `errorLog` are captured into arrays so the
 *     emitted report can be asserted on. No real runner, verifier, clock, or
 *     filesystem is involved.
 *   - Layer B drives the real {@link sweepTaggedResources} against a fake
 *     {@link TaggingClientLike} whose `send` returns canned
 *     `GetResources`-shaped pages (or throws to simulate a page failure), so the
 *     pagination + continue-past-failure resilience is exercised offline.
 *
 * What is asserted (R10.2 focus, with R10.3 / revert ordering alongside):
 *   - Clean teardown reports success / "no tagged resources remain", does NOT
 *     sweep, writes baseline state, and exits 0 (R10.3).
 *   - A `cdk destroy` failure TRIGGERS the sweep with `("Project",
 *     "nf-devops-agent")`, reports EVERY remaining resource ARN and the
 *     per-page sweep error (continues past failures), states teardown completed
 *     with failures, and exits non-zero (R10.2).
 *   - An active scenario is reverted to baseline (a `deploy`) BEFORE `destroy`.
 *   - `sweepTaggedResources` collects page-1 ARNs and records ONE error when a
 *     later page throws (it does not propagate), and collects every ARN across
 *     multiple full pages with no errors when pagination terminates cleanly
 *     (R10.2 pagination + resilience).
 *   - `resourceTypeFromArn` maps representative ARNs to `service:type`.
 *
 * _Requirements: 10.2_
 */

import {
  GetResourcesCommand,
  GetResourcesCommandOutput,
} from "@aws-sdk/client-resource-groups-tagging-api";

import {
  CdkRunResult,
  CdkDeployOptions,
  CdkDestroyOptions,
} from "../src/scenarioctl/runner";
import {
  runDestroy,
  sweepTaggedResources,
  resourceTypeFromArn,
  CliDeps,
  SweepResult,
  PersistedState,
  TaggingClientLike,
  PROJECT_TAG_KEY,
  PROJECT_TAG_VALUE,
  EXIT_OK,
  EXIT_FAILURE,
} from "../src/scenarioctl/cli";

// ---------------------------------------------------------------------------
// Test doubles for Layer A: a mocked CliDeps
// ---------------------------------------------------------------------------

/** Canned successful `cdk` run result. */
function runOk(): CdkRunResult {
  return { ok: true, exitCode: 0, stdout: "", stderr: "" };
}

/** Canned failed `cdk` run result carrying `error`. */
function runFail(error: string, exitCode = 1): CdkRunResult {
  return { ok: false, exitCode, stdout: "", stderr: "", error };
}

/** The captured side-effect sinks a test inspects after running a handler. */
interface Captured {
  logs: string[];
  errors: string[];
  /** Every `(scenario|null)` written to the state file, in order. */
  writes: PersistedState[];
  /** Ordered trace of side-effecting calls, used to assert revert-before-destroy. */
  calls: string[];
  /** Args the sweep was invoked with (null until called). */
  sweepArgs: { tagKey: string; tagValue: string } | null;
}

/**
 * Build a mocked {@link CliDeps} with harmless defaults for every field. The
 * `overrides` patch in the per-test behavior (almost always `destroy`,
 * `sweepTaggedResources`, and the seeded `readState`). `log`/`errorLog` and the
 * call trace are captured into the returned {@link Captured} record.
 */
function makeDeps(overrides: Partial<CliDeps> = {}): { deps: CliDeps; captured: Captured } {
  const captured: Captured = {
    logs: [],
    errors: [],
    writes: [],
    calls: [],
    sweepArgs: null,
  };

  const base: CliDeps = {
    // Default deploy/destroy succeed; tests override as needed.
    deploy: async (_options?: CdkDeployOptions): Promise<CdkRunResult> => {
      captured.calls.push("deploy");
      return runOk();
    },
    destroy: async (_options?: CdkDestroyOptions): Promise<CdkRunResult> => {
      captured.calls.push("destroy");
      return runOk();
    },
    sweepTaggedResources: async (tagKey: string, tagValue: string): Promise<SweepResult> => {
      captured.calls.push("sweep");
      captured.sweepArgs = { tagKey, tagValue };
      return { resources: [], errors: [] };
    },
    // Verification never runs in destroy; provide a harmless default.
    verifyScenario: async () => {
      throw new Error("verifyScenario should not be called by destroy");
    },
    writeContextFile: (_state, _filePath) => "/tmp/cdk.context.json",
    readState: (_statePath): PersistedState => ({
      activeScenario: "none",
    }),
    writeState: (state: PersistedState, _statePath: string): void => {
      captured.calls.push("writeState");
      captured.writes.push(state);
    },
    resolveVerifyConfig: () => ({ ok: false, missing: [] }),
    now: () => new Date("2025-01-01T00:00:00.000Z"),
    log: (message: string) => captured.logs.push(message),
    errorLog: (message: string) => captured.errors.push(message),
    statePath: "/tmp/.scenarioctl-state.json",
    contextPath: "/tmp/cdk.context.json",
    env: {},
  };

  return { deps: { ...base, ...overrides }, captured };
}

/** A persisted state seed for `readState`. */
function seedState(state: PersistedState): (statePath: string) => PersistedState {
  return () => state;
}

// ---------------------------------------------------------------------------
// Test doubles for Layer B: a fake Resource Groups Tagging API client
// ---------------------------------------------------------------------------

/** Build a `GetResources`-shaped page output. */
function page(arns: string[], paginationToken?: string): GetResourcesCommandOutput {
  return {
    ResourceTagMappingList: arns.map((arn) => ({ ResourceARN: arn })),
    ...(paginationToken !== undefined ? { PaginationToken: paginationToken } : {}),
    $metadata: {},
  };
}

interface FakeTaggingClient {
  client: TaggingClientLike;
  /** Number of `send` invocations. */
  sendCalls: () => number;
}

/**
 * Fake tagging client. `handler(call)` produces each page (1-based call index);
 * throwing from the handler simulates a page request that failed.
 */
function createFakeTaggingClient(
  handler: (call: number) => GetResourcesCommandOutput,
): FakeTaggingClient {
  let sendCalls = 0;
  const client: TaggingClientLike = {
    send: async (_command: GetResourcesCommand): Promise<GetResourcesCommandOutput> => {
      sendCalls += 1;
      return handler(sendCalls);
    },
  };
  return { client, sendCalls: () => sendCalls };
}

// ---------------------------------------------------------------------------
// Layer A — runDestroy via mocked CliDeps
// ---------------------------------------------------------------------------

describe("runDestroy clean teardown (R10.3)", () => {
  it("reports success, does NOT sweep, writes baseline, and exits 0", async () => {
    let swept = false;
    const { deps, captured } = makeDeps({
      readState: seedState({ activeScenario: "none" }),
      destroy: async () => {
        captured.calls.push("destroy");
        return runOk();
      },
      sweepTaggedResources: async (tagKey, tagValue) => {
        swept = true;
        captured.sweepArgs = { tagKey, tagValue };
        return { resources: [], errors: [] };
      },
    });

    const code = await runDestroy(deps);

    expect(code).toBe(EXIT_OK);
    // Clean destroy must NOT sweep.
    expect(swept).toBe(false);
    expect(captured.sweepArgs).toBeNull();
    expect(captured.calls).not.toContain("sweep");
    // A log line confirms teardown complete / no tagged resources remain.
    const joinedLogs = captured.logs.join("\n");
    expect(joinedLogs).toMatch(/teardown complete/i);
    expect(joinedLogs).toMatch(/no tagged resources remain/i);
    // State is written back to baseline.
    expect(captured.writes.length).toBeGreaterThan(0);
    const lastWrite = captured.writes[captured.writes.length - 1];
    expect(lastWrite).toEqual({ activeScenario: "none" });
  });
});

describe("runDestroy destroy-failure triggers sweep (R10.2)", () => {
  it("sweeps, reports every remaining resource and the page error, and exits non-zero", async () => {
    const sweepResult: SweepResult = {
      resources: [
        { arn: "arn:aws:network-firewall:us-east-1:111122223333:firewall/test", type: "network-firewall:firewall" },
        { arn: "arn:aws:s3:::nf-agent-logs", type: "s3" },
      ],
      errors: ["page 2 throttled"],
    };

    const { deps, captured } = makeDeps({
      readState: seedState({ activeScenario: "none" }),
      destroy: async () => {
        captured.calls.push("destroy");
        return runFail("stack delete failed");
      },
      sweepTaggedResources: async (tagKey, tagValue) => {
        captured.calls.push("sweep");
        captured.sweepArgs = { tagKey, tagValue };
        return sweepResult;
      },
    });

    const code = await runDestroy(deps);

    // R10.2 — destroy failure exits non-zero.
    expect(code).toBe(EXIT_FAILURE);

    // The sweep was invoked with the project tag key/value.
    expect(captured.sweepArgs).toEqual({ tagKey: "Project", tagValue: "nf-devops-agent" });
    expect(captured.sweepArgs?.tagKey).toBe(PROJECT_TAG_KEY);
    expect(captured.sweepArgs?.tagValue).toBe(PROJECT_TAG_VALUE);

    // The destroy must have happened before the sweep.
    expect(captured.calls.indexOf("destroy")).toBeLessThan(captured.calls.indexOf("sweep"));

    const errorOutput = captured.errors.join("\n");
    // Every remaining resource ARN appears in the error report.
    for (const resource of sweepResult.resources) {
      expect(errorOutput).toContain(resource.arn);
    }
    // The per-page sweep error is also reported (continues past failures).
    expect(errorOutput).toContain("page 2 throttled");
    // It states teardown completed with failures.
    expect(errorOutput).toMatch(/teardown completed with failures/i);
    // The original destroy error is surfaced too.
    expect(errorOutput).toContain("stack delete failed");
  });

  it("still reports failure and exits non-zero when the sweep enumerated nothing", async () => {
    const { deps, captured } = makeDeps({
      readState: seedState({ activeScenario: "none" }),
      destroy: async () => runFail("stack delete failed"),
      sweepTaggedResources: async (tagKey, tagValue) => {
        captured.sweepArgs = { tagKey, tagValue };
        return { resources: [], errors: [] };
      },
    });

    const code = await runDestroy(deps);

    expect(code).toBe(EXIT_FAILURE);
    expect(captured.sweepArgs).toEqual({ tagKey: "Project", tagValue: "nf-devops-agent" });
    expect(captured.errors.join("\n")).toMatch(/teardown completed with failures/i);
  });
});

describe("runDestroy reverts an active scenario before destroying", () => {
  it("calls deploy (revert to baseline) before destroy and exits 0 on a clean teardown", async () => {
    const { deps, captured } = makeDeps({
      readState: seedState({ activeScenario: "3" }),
      deploy: async () => {
        captured.calls.push("deploy");
        return runOk();
      },
      destroy: async () => {
        captured.calls.push("destroy");
        return runOk();
      },
    });

    const code = await runDestroy(deps);

    expect(code).toBe(EXIT_OK);
    // The revert deploy ran, and it ran BEFORE the destroy.
    expect(captured.calls).toContain("deploy");
    expect(captured.calls).toContain("destroy");
    expect(captured.calls.indexOf("deploy")).toBeLessThan(captured.calls.indexOf("destroy"));
    // Clean teardown still skips the sweep.
    expect(captured.calls).not.toContain("sweep");
  });
});

// ---------------------------------------------------------------------------
// Layer B — sweepTaggedResources resilience + pagination (R10.2)
// ---------------------------------------------------------------------------

describe("sweepTaggedResources continues past a failing page (R10.2)", () => {
  it("returns page-1 ARNs and records ONE error when a later page throws", async () => {
    const fake = createFakeTaggingClient((call) => {
      if (call === 1) {
        return page(["arn:aws:network-firewall:us-east-1:111122223333:firewall/a"], "t1");
      }
      throw new Error("AccessDenied on page 2");
    });

    const result = await sweepTaggedResources(PROJECT_TAG_KEY, PROJECT_TAG_VALUE, fake.client);

    // The page-1 ARN survived even though page 2 failed (did not throw).
    expect(result.resources.map((r) => r.arn)).toEqual([
      "arn:aws:network-firewall:us-east-1:111122223333:firewall/a",
    ]);
    // Exactly one page error captured.
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain("AccessDenied on page 2");
    // It attempted page 1 (ok) then page 2 (threw) — two sends.
    expect(fake.sendCalls()).toBe(2);
  });
});

describe("sweepTaggedResources collects every page when pagination terminates cleanly", () => {
  it("collects all ARNs across two full pages with no errors", async () => {
    const fake = createFakeTaggingClient((call) => {
      if (call === 1) {
        return page(
          [
            "arn:aws:s3:::nf-agent-logs",
            "arn:aws:sns:us-east-1:111122223333:nf-agent-alarms",
          ],
          "t1",
        );
      }
      if (call === 2) {
        // The API returns "" (not absent) on the last page.
        return page(
          [
            "arn:aws:network-firewall:us-east-1:111122223333:firewall/test",
            "arn:aws:logs:us-east-1:111122223333:log-group:/nf/alert",
          ],
          "",
        );
      }
      throw new Error("should not request a third page");
    });

    const result = await sweepTaggedResources(PROJECT_TAG_KEY, PROJECT_TAG_VALUE, fake.client);

    expect(result.errors).toEqual([]);
    expect(result.resources.map((r) => r.arn)).toEqual([
      "arn:aws:s3:::nf-agent-logs",
      "arn:aws:sns:us-east-1:111122223333:nf-agent-alarms",
      "arn:aws:network-firewall:us-east-1:111122223333:firewall/test",
      "arn:aws:logs:us-east-1:111122223333:log-group:/nf/alert",
    ]);
    // Two pages, then the empty token stops pagination.
    expect(fake.sendCalls()).toBe(2);
  });
});

describe("resourceTypeFromArn maps ARNs to service:type", () => {
  it("derives the service:type token from representative ARNs", () => {
    expect(resourceTypeFromArn("arn:aws:s3:::nf-agent-logs")).toBe("s3:nf-agent-logs");
    expect(
      resourceTypeFromArn("arn:aws:network-firewall:us-east-1:111122223333:firewall/test"),
    ).toBe("network-firewall:firewall");
    expect(
      resourceTypeFromArn("arn:aws:logs:us-east-1:111122223333:log-group:/nf/alert"),
    ).toBe("logs:log-group");
    // A non-ARN string yields undefined.
    expect(resourceTypeFromArn("not-an-arn")).toBeUndefined();
  });
});
