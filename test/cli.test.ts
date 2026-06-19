/**
 * Unit tests for the `scenarioctl` CLI command handlers (`src/scenarioctl/cli.ts`).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These are hermetic example-based unit tests. They NEVER touch the real
 * filesystem, AWS, or the cdk CLI: every side effect flows through an injected
 * {@link CliDeps} test double built by {@link makeDeps}. `deploy`/`verifyScenario`
 * are `jest.fn()`s the test controls, `readState`/`writeState` are backed by a
 * mutable in-memory `PersistedState` closure so a test can seed the active
 * scenario and assert it is left untouched on a failure, and `log`/`errorLog`
 * push to arrays the test asserts on.
 *
 * The focus (per task 15.2) is the single-active-scenario guard and the
 * deploy-failure path:
 *   - activating a SECOND scenario while another is active is REJECTED with a
 *     revert-first instruction and does NOT mutate state (R9.5);
 *   - a failed `cdk deploy` reports the failing step + captured error/resource,
 *     preserves the last-good state (no partial state mutation), and exits
 *     non-zero (R7.7, R8.8, R9.7);
 *   - the happy paths persist state correctly,
 *     and the no-op rules for re-activate / revert-when-not-active hold.
 *
 * _Requirements: 9.5, 9.7, 7.7, 8.8_
 */

import {
  runActivate,
  runRevert,
  parseArgs,
  EXIT_OK,
  EXIT_FAILURE,
  CliDeps,
  PersistedState,
  SweepResult,
  VerifyConfigResult,
} from "../src/scenarioctl/cli";
import { CdkRunResult, CdkDeployOptions, CdkDestroyOptions } from "../src/scenarioctl/runner";
import {
  VerificationResult,
  VerificationDetails,
  EgressProbeRan,
  VerifyScenarioParams,
} from "../src/scenarioctl/verify";
import { Scenario, DesiredState } from "../src/scenarioctl/state";

// ---------------------------------------------------------------------------
// Result-literal builders (match the EXACT exported shapes)
// ---------------------------------------------------------------------------

/** A successful `cdk deploy` result. */
function deployOk(): CdkRunResult {
  return { ok: true, exitCode: 0, stdout: "", stderr: "" };
}

/**
 * A failed `cdk deploy` result carrying a parsed failing resource. The `error`
 * string ("boom") and the resource logical id ("Firewall") are what the
 * failure-report assertions look for.
 */
function deployFail(): CdkRunResult {
  return {
    ok: false,
    exitCode: 1,
    stdout: "",
    stderr: "",
    error: "boom",
    failedResource: {
      logicalId: "Firewall",
      resourceType: "AWS::NetworkFirewall::Firewall",
      statusReason: "bad",
    },
  };
}

/** A minimal `probe-ran` whose egress was blocked (a direct drop signal). */
function probeRanBlocked(): EgressProbeRan {
  return {
    kind: "probe-ran",
    egressSucceeded: false,
    httpCode: null,
    responseCode: 7,
    ssmStatus: "Success",
    commandId: "cmd-0001",
    stdout: "",
    stderr: "",
  };
}

/** A `trigger-observed` VerificationResult with a minimal valid `details`. */
function triggerObserved(scenario: Scenario): VerificationResult {
  const probe = probeRanBlocked();
  const details: VerificationDetails = {
    scenario,
    probe,
    egressSucceeded: probe.egressSucceeded,
    observedSignals: ["egress-blocked"],
  };
  return { kind: "trigger-observed", details };
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

describe("cli.ts command handlers", () => {
  /** The mutable in-memory persisted state backing readState/writeState. */
  let state: PersistedState;
  /** Captured stdout lines. */
  let logs: string[];
  /** Captured stderr lines. */
  let errors: string[];

  beforeEach(() => {
    state = { activeScenario: "none" };
    logs = [];
    errors = [];
  });

  /**
   * Build a fully-populated {@link CliDeps} test double. Every field defaults to
   * a harmless, hermetic implementation; pass `overrides` to control the bits a
   * test exercises (typically `deploy` and/or `resolveVerifyConfig`).
   */
  function makeDeps(overrides: Partial<CliDeps> = {}): CliDeps {
    const base: CliDeps = {
      deploy: jest.fn((_options?: CdkDeployOptions): Promise<CdkRunResult> =>
        Promise.resolve(deployOk()),
      ),
      destroy: jest.fn((_options?: CdkDestroyOptions): Promise<CdkRunResult> =>
        Promise.resolve(deployOk()),
      ),
      sweepTaggedResources: jest.fn((_tagKey: string, _tagValue: string): Promise<SweepResult> =>
        Promise.resolve({ resources: [], errors: [] }),
      ),
      verifyScenario: jest.fn(
        (scenario: Scenario, _params: VerifyScenarioParams): Promise<VerificationResult> =>
          Promise.resolve(triggerObserved(scenario)),
      ),
      writeContextFile: jest.fn((_state: DesiredState, _filePath?: string): string =>
        "/tmp/context.json",
      ),
      readState: jest.fn((_statePath: string): PersistedState => state),
      writeState: jest.fn((next: PersistedState, _statePath: string): void => {
        state = next;
      }),
      // Default: verification is NOT configured, so post-deploy verify is skipped.
      // This keeps the deploy-focused tests clean. Override to { ok: true, config }
      // when a test needs verify to actually run.
      resolveVerifyConfig: jest.fn(
        (_scenario: Scenario, _env: NodeJS.ProcessEnv): VerifyConfigResult => ({
          ok: false,
          missing: ["NF_INSTANCE_ID"],
        }),
      ),
      now: () => new Date("2024-01-02T03:04:05Z"),
      log: (message: string): void => {
        logs.push(message);
      },
      errorLog: (message: string): void => {
        errors.push(message);
      },
      statePath: "/tmp/state.json",
      contextPath: "/tmp/context.json",
      env: {},
    };
    return { ...base, ...overrides };
  }

  // -------------------------------------------------------------------------
  // 1. Concurrent-activation guard (R9.5)
  // -------------------------------------------------------------------------

  it("rejects activating a second scenario while another is active and instructs revert-first (R9.5)", async () => {
    state = { activeScenario: "1" };
    const deps = makeDeps();

    const code = await runActivate("2", deps);

    expect(code).toBe(EXIT_FAILURE);
    expect(deps.deploy).not.toHaveBeenCalled();
    expect(deps.writeState).not.toHaveBeenCalled();
    // The operator is told to revert the currently-active scenario "1" first.
    expect(errors.some((line) => /revert 1/.test(line))).toBe(true);
    expect(errors.some((line) => /scenario 1 is currently active/i.test(line))).toBe(true);
    // The persisted state is left exactly as seeded.
    expect(state).toEqual({ activeScenario: "1" });
  });

  // -------------------------------------------------------------------------
  // 2. Same-scenario re-activate is a no-op success (R9.1)
  // -------------------------------------------------------------------------

  it("treats re-activating the already-active scenario as a no-op success (R9.1)", async () => {
    state = { activeScenario: "2" };
    const deps = makeDeps();

    const code = await runActivate("2", deps);

    expect(code).toBe(EXIT_OK);
    expect(deps.deploy).not.toHaveBeenCalled();
    expect(deps.writeState).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // 3. Deploy-failure path preserves last-good state and exits non-zero
  //    (R9.7 / R7.7 / R8.8)
  // -------------------------------------------------------------------------

  it("reports the deploy failure, preserves last-good state, and exits non-zero (R9.7, R7.7, R8.8)", async () => {
    state = { activeScenario: "none" };
    const deps = makeDeps({
      deploy: jest.fn((_options?: CdkDeployOptions): Promise<CdkRunResult> =>
        Promise.resolve(deployFail()),
      ),
    });

    const code = await runActivate("3", deps);

    expect(code).toBe(EXIT_FAILURE);
    // No partial mutation: writeState was never called and the in-memory state
    // is still the seeded baseline.
    expect(deps.writeState).not.toHaveBeenCalled();
    expect(state).toEqual({ activeScenario: "none" });
    // The captured error and the failing resource are reported.
    const allErrors = errors.join("\n");
    expect(allErrors).toContain("boom");
    expect(allErrors).toContain("Firewall");
    // The report tells the operator the last-good state is preserved.
    expect(errors.some((line) => /last-good state preserved/i.test(line))).toBe(true);
  });

  // -------------------------------------------------------------------------
  // 4. Happy-path activate persists the new active scenario (R9.1)
  // -------------------------------------------------------------------------

  it("persists the new active scenario after a successful deploy (R9.1)", async () => {
    state = { activeScenario: "none" };
    const deps = makeDeps();

    const code = await runActivate("1", deps);

    expect(code).toBe(EXIT_OK);
    expect(deps.deploy).toHaveBeenCalledTimes(1);
    expect(deps.writeState).toHaveBeenCalledTimes(1);
    expect(deps.writeState).toHaveBeenCalledWith(
      { activeScenario: "1" },
      deps.statePath,
    );
    // Verification was skipped (not configured), so the no-op state stands.
    expect(state).toEqual({ activeScenario: "1" });
  });

  // -------------------------------------------------------------------------
  // 5. Revert of a non-active scenario is a no-op success (R9.2)
  // -------------------------------------------------------------------------

  it("treats reverting a non-active scenario as a no-op success (R9.2)", async () => {
    state = { activeScenario: "none" };
    const deps = makeDeps();

    const code = await runRevert("2", deps);

    expect(code).toBe(EXIT_OK);
    expect(deps.deploy).not.toHaveBeenCalled();
    expect(deps.writeState).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // 8. parseArgs (pure)
  // -------------------------------------------------------------------------

  describe("parseArgs", () => {
    it("parses a valid activate command with its scenario argument", () => {
      expect(parseArgs(["activate", "2"])).toEqual({
        ok: true,
        command: "activate",
        scenario: "2",
      });
    });

    it("rejects activate with no scenario argument", () => {
      expect(parseArgs(["activate"]).ok).toBe(false);
    });

    it("rejects an unknown command", () => {
      expect(parseArgs(["bogus"]).ok).toBe(false);
    });
  });
});
