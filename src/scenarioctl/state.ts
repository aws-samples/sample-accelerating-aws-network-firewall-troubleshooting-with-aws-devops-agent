/**
 * Scenario state machine (pure, side-effect-free).
 *
 * Ported from the now-deleted Python `scenarioctl/state.py` with its semantics
 * preserved (see PORTING-NOTES.md). This module drives CDK context (via
 * `toContext`) instead of Terraform tfvars.
 *
 * Purity contract: every function here is pure. There is no filesystem, AWS, or
 * other side effect.
 */

/** The scenario selector. `"none"` is the working baseline. */
export type Scenario = "none" | "1" | "2" | "3";

/** AWS Network Firewall stream exception policy values. */
export type StreamExceptionPolicy = "CONTINUE" | "REJECT" | "DROP";

/** Active log destination for the firewall logging configuration. */
export type LogDestination = "cloudwatch" | "s3";

/**
 * The canonical desired state for the sample environment. Every field is
 * `readonly` so a `DesiredState` cannot be mutated in place; transitions
 * produce new objects.
 */
export interface DesiredState {
  /** The selector, set by every scenario. */
  readonly activeScenario: Scenario;
  /** Scenario 2 owned (baseline 100, kept below `dropPriority`). */
  readonly allowPriority: number;
  /** Scenario 2 owned (baseline 200, kept above `allowPriority`). */
  readonly dropPriority: number;
  /** Baseline CONTINUE. This sample never changes this (Scenario 3 is routing-only). */
  readonly streamExceptionPolicy: StreamExceptionPolicy;
  /** Scenario 3 owned (true only while Scenario 3 is active). */
  readonly asymmetricRoute: boolean;
  /** Scenario 1 owned (baseline false). */
  readonly domainDenyActive: boolean;
  /** Deployment config, owned by NO scenario (baseline cloudwatch). */
  readonly logDestination: LogDestination;
}

/**
 * The plain object the CDK stacks read back via `app.node.tryGetContext(...)`.
 */
export interface ScenarioContext {
  readonly activeScenario: Scenario;
  readonly allowPriority: number;
  readonly dropPriority: number;
  readonly streamExceptionPolicy: StreamExceptionPolicy;
  readonly asymmetricRoute: boolean;
  readonly domainDenyActive: boolean;
  readonly logDestination: LogDestination;
}

/** Baseline stateless priorities: allow is evaluated before drop, so traffic passes. */
const BASELINE_ALLOW_PRIORITY = 100;
const BASELINE_DROP_PRIORITY = 200;

/**
 * The canonical "all working" state: no scenario active and every scenario-owned
 * field at its baseline value.
 */
export function baseline(): DesiredState {
  return {
    activeScenario: "none",
    allowPriority: BASELINE_ALLOW_PRIORITY,
    dropPriority: BASELINE_DROP_PRIORITY,
    streamExceptionPolicy: "CONTINUE",
    asymmetricRoute: false,
    domainDenyActive: false,
    logDestination: "cloudwatch",
  };
}

/**
 * Deterministic pure map from a scenario to its desired state.
 *
 * Each scenario flips ONLY the fields it owns and leaves everything else at
 * baseline (the single-scenario invariant).
 *
 * @throws if `scenario` is not one of the known {@link Scenario} values.
 */
export function desired(scenario: Scenario): DesiredState {
  const base = baseline();
  switch (scenario) {
    case "none":
      return base;
    case "1":
      // Scenario 1 owns: domainDenyActive.
      return { ...base, activeScenario: "1", domainDenyActive: true };
    case "2":
      // Scenario 2 owns: allow/drop priorities, inverted from baseline so drop wins.
      return {
        ...base,
        activeScenario: "2",
        allowPriority: BASELINE_DROP_PRIORITY,
        dropPriority: BASELINE_ALLOW_PRIORITY,
      };
    case "3":
      // Scenario 3 owns: asymmetricRoute. The egress route flips to the other
      // AZ's firewall endpoint while the return route stays same-AZ, so a flow's
      // SYN and its return traverse different endpoints and the handshake never
      // completes. This routing change alone breaks egress (verified live), so
      // Scenario 3 makes NO firewall-policy change — the only mutations are
      // EC2 route edits, which points the agent's investigation at routing
      // rather than at an unrelated policy field.
      return {
        ...base,
        activeScenario: "3",
        asymmetricRoute: true,
      };
    default:
      // Runtime guard for values cast outside the Scenario union.
      throw new Error(`Unknown scenario: ${String(scenario)}`);
  }
}

/** True when a scenario other than the baseline is active. */
export function isActive(state: DesiredState): boolean {
  return state.activeScenario !== "none";
}

/**
 * Render a desired state into the plain {@link ScenarioContext} object the stacks
 * read back. Deterministic and JSON-serializable.
 */
export function toContext(state: DesiredState): ScenarioContext {
  return {
    activeScenario: state.activeScenario,
    allowPriority: state.allowPriority,
    dropPriority: state.dropPriority,
    streamExceptionPolicy: state.streamExceptionPolicy,
    asymmetricRoute: state.asymmetricRoute,
    domainDenyActive: state.domainDenyActive,
    logDestination: state.logDestination,
  };
}

/**
 * Imperative activation entry point. Now identical to {@link desired} for every
 * scenario; retained as a thin alias so existing callers/tests can keep
 * importing it.
 */
export function activate(scenario: Scenario): DesiredState {
  return desired(scenario);
}
