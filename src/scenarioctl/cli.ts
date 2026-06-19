#!/usr/bin/env node
/**
 * `scenarioctl` CLI — orchestration layer for the AWS Network Firewall sample.
 *
 * This module composes the pure scenario state machine (`state.ts`), the CDK
 * context renderer (`context.ts`), the CDK process runner (`runner.ts`), and the
 * AWS-side verifier (`verify.ts`) into the operator-facing verbs:
 *
 *   scenarioctl baseline                 # deploy baseline, verify healthy egress
 *   scenarioctl activate <1|2|3>         # deploy a scenario, verify the trigger
 *   scenarioctl revert   <1|2|3>         # deploy baseline, verify egress restored
 *   scenarioctl verify   <1|2|3>         # run the probe + checks only (no deploy)
 *   scenarioctl status                   # print the active scenario
 *   scenarioctl destroy                  # (task 16) tear the environment down
 *
 * Design contract (R7.7, R8.8, R9.1–R9.7):
 *   - A small persisted STATE FILE (`<repo root>/.scenarioctl-state.json`) records
 *     the currently active scenario. It
 *     is the single source of truth for the single-active-scenario rule and for
 *     `status`.
 *   - The state file is mutated ONLY AFTER a successful `cdk deploy`. A failed
 *     deploy (or a probe that could not run) leaves the last-good state untouched
 *     and exits non-zero so the operator can re-run (R9.7, R7.7, R8.8).
 *   - `activate <n>` while scenario `n` is already active is a no-op success
 *     (R9.1); `revert <n>` while `n` is not active is a no-op success (R9.2);
 *     activating while a DIFFERENT scenario is active is rejected with a
 *     revert-first instruction (R9.5).
 *
 * Structure / testability:
 *   - Pure logic (arg parsing, context→CLI-args rendering, the
 *     single-active-scenario decision, verify-config resolution) is separated
 *     from side effects.
 *   - All side effects flow through an injectable {@link CliDeps} object that
 *     defaults to the real `runner`/`verify`/`context`/filesystem/clock imports,
 *     so task 15.2 can unit-test the handlers with mocked `runner`/`verify`.
 *   - `main(argv)` RETURNS an exit code; the thin entrypoint guard at the bottom
 *     is the only place that calls `process.exit`.
 */

import * as fs from "fs";
import * as path from "path";

import {
  Scenario,
  DesiredState,
  ScenarioContext,
  baseline,
  desired,
} from "./state";
import { renderContext, writeContextFile, DEFAULT_CONTEXT_PATH } from "./context";
import {
  deploy as realDeploy,
  destroy as realDestroy,
  CdkDeployOptions,
  CdkDestroyOptions,
  CdkRunResult,
} from "./runner";
import {
  verifyScenario as realVerifyScenario,
  VerifyScenarioParams,
  VerificationResult,
} from "./verify";
import {
  ResourceGroupsTaggingAPIClient,
  GetResourcesCommand,
  GetResourcesCommandOutput,
} from "@aws-sdk/client-resource-groups-tagging-api";

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/** Successful completion. */
export const EXIT_OK = 0;
/** Any failure: bad args, deploy failure, probe failure, or unmet verification. */
export const EXIT_FAILURE = 1;

// ---------------------------------------------------------------------------
// Teardown tag sweep (R10.1, R10.2, R10.3)
// ---------------------------------------------------------------------------

/**
 * The project-wide tag key/value every stack resource carries (set via
 * `Tags.of(this).add(...)` in the CDK stacks). These literals MIRROR the
 * exported `PROJECT_TAG_KEY` / `PROJECT_TAG_VALUE` in `lib/network-stack.ts`;
 * they are duplicated here (rather than imported) so the CLI runtime never has
 * to load a CDK stack module. Keep the two in sync.
 */
export const PROJECT_TAG_KEY = "Project";
export const PROJECT_TAG_VALUE = "nf-devops-agent";

/** A single resource discovered by the post-destroy tag sweep. */
export interface SweptResource {
  /** The resource ARN reported by the Resource Groups Tagging API. */
  readonly arn: string;
  /** The resource type, when it can be inferred from the ARN. */
  readonly type?: string;
}

/**
 * Result of a tag-based sweep. `resources` lists every still-tagged resource the
 * sweep could enumerate; `errors` collects per-page failures encountered while
 * paginating. The sweep CONTINUES past individual page errors (R10.2), so both
 * arrays can be populated at once.
 */
export interface SweepResult {
  /** Every remaining tagged resource enumerated across all pages. */
  readonly resources: readonly SweptResource[];
  /** Human-readable messages for any page that could not be enumerated. */
  readonly errors: readonly string[];
}

/**
 * Minimal Resource Groups Tagging API surface the sweep relies on. The real
 * `ResourceGroupsTaggingAPIClient` satisfies this; tests pass a stub with just
 * `send`.
 */
export interface TaggingClientLike {
  send(command: GetResourcesCommand): Promise<GetResourcesCommandOutput>;
}

/**
 * Best-effort parse of the AWS resource TYPE out of an ARN. ARNs look like
 * `arn:aws:<service>:<region>:<account>:<type>/<id>` (or `<type>:<id>`); we
 * return `<service>:<type>` when both are present, falling back to the service
 * alone. Returns `undefined` when nothing useful can be parsed.
 */
export function resourceTypeFromArn(arn: string): string | undefined {
  const parts = arn.split(":");
  // arn : partition : service : region : account : resource...
  if (parts.length < 6 || parts[0] !== "arn") {
    return undefined;
  }
  const service = parts[2];
  if (!service) {
    return undefined;
  }
  const resource = parts.slice(5).join(":");
  const typeToken = resource.split(/[/:]/)[0];
  if (typeToken && typeToken.length > 0) {
    return `${service}:${typeToken}`;
  }
  return service;
}

/**
 * Enumerate every resource tagged `tagKey = tagValue` using the Resource Groups
 * Tagging API `GetResources` operation, paginating via `PaginationToken`.
 *
 * Resilience (R10.2): each page request is wrapped in `try`/`catch`. A failed
 * page is recorded in `errors` and pagination stops (the token cannot be
 * advanced past a failed page), but every resource gathered so far is still
 * returned — the sweep never throws.
 *
 * @param tagKey the tag key to filter on (e.g. {@link PROJECT_TAG_KEY}).
 * @param tagValue the tag value to filter on (e.g. {@link PROJECT_TAG_VALUE}).
 * @param client optional injected tagging client (defaults to a real one).
 */
export async function sweepTaggedResources(
  tagKey: string,
  tagValue: string,
  client: TaggingClientLike = new ResourceGroupsTaggingAPIClient({}),
): Promise<SweepResult> {
  const resources: SweptResource[] = [];
  const errors: string[] = [];
  let paginationToken: string | undefined;

  do {
    let page: GetResourcesCommandOutput;
    try {
      page = await client.send(
        new GetResourcesCommand({
          TagFilters: [{ Key: tagKey, Values: [tagValue] }],
          ...(paginationToken ? { PaginationToken: paginationToken } : {}),
        }),
      );
    } catch (error: unknown) {
      errors.push(error instanceof Error ? error.message : String(error));
      break;
    }

    for (const mapping of page.ResourceTagMappingList ?? []) {
      const arn = mapping.ResourceARN;
      if (typeof arn === "string" && arn.length > 0) {
        const type = resourceTypeFromArn(arn);
        resources.push(type ? { arn, type } : { arn });
      }
    }

    // The API returns "" (not null) when there are no more pages.
    paginationToken =
      typeof page.PaginationToken === "string" && page.PaginationToken.length > 0
        ? page.PaginationToken
        : undefined;
  } while (paginationToken);

  return { resources, errors };
}

// ---------------------------------------------------------------------------
// Persisted state file
// ---------------------------------------------------------------------------

/**
 * The persisted CLI state. This is intentionally a small subset of
 * {@link DesiredState}: only what the single-active-scenario rule and `status`
 * need. The full desired state for a deploy is always recomputed from
 * `state.ts`, never read back from disk.
 */
export interface PersistedState {
  /** The scenario currently believed to be active (`"none"` = baseline). */
  readonly activeScenario: Scenario;
}

/**
 * Default state-file path: the repository root (two levels up from
 * `src/scenarioctl/`) joined with `.scenarioctl-state.json`. This file is
 * git-ignored — it is operator-local runtime state, not source.
 */
export const DEFAULT_STATE_PATH = path.resolve(__dirname, "..", "..", ".scenarioctl-state.json");

/** The clean baseline persisted state (used as the default when no file exists). */
function baselinePersistedState(): PersistedState {
  return { activeScenario: "none" };
}

/** Runtime guard: is `value` one of the known {@link Scenario} literals? */
function isScenario(value: unknown): value is Scenario {
  return value === "none" || value === "1" || value === "2" || value === "3";
}

/**
 * Read the persisted state from `statePath`. Returns the baseline state when the
 * file is absent or unparseable (a corrupt/partial file must never crash the
 * CLI — the operator can always re-run from baseline).
 */
export function readStateFile(statePath: string = DEFAULT_STATE_PATH): PersistedState {
  if (!fs.existsSync(statePath)) {
    return baselinePersistedState();
  }
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(statePath, { encoding: "utf8" }));
    if (typeof parsed !== "object" || parsed === null) {
      return baselinePersistedState();
    }
    const record = parsed as Record<string, unknown>;
    const activeScenario = isScenario(record.activeScenario) ? record.activeScenario : "none";
    return { activeScenario };
  } catch {
    return baselinePersistedState();
  }
}

/** Write the persisted state to `statePath` as pretty-printed JSON. */
export function writeStateFile(
  state: PersistedState,
  statePath: string = DEFAULT_STATE_PATH,
): void {
  fs.writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8" });
}

// ---------------------------------------------------------------------------
// Context → cdk --context args
// ---------------------------------------------------------------------------

/**
 * Render a {@link ScenarioContext} into the flat `Record<string,string>` the
 * runner turns into repeated `--context key=value` args. Every value is
 * stringified: booleans as `"true"`/`"false"` and numbers as decimal strings.
 * This keeps the `cdk deploy` self-contained without depending on the on-disk
 * file.
 */
export function contextToCliArgs(ctx: ScenarioContext): Record<string, string> {
  return {
    activeScenario: ctx.activeScenario,
    allowPriority: String(ctx.allowPriority),
    dropPriority: String(ctx.dropPriority),
    streamExceptionPolicy: ctx.streamExceptionPolicy,
    asymmetricRoute: String(ctx.asymmetricRoute),
    domainDenyActive: String(ctx.domainDenyActive),
    logDestination: ctx.logDestination,
  };
}

// ---------------------------------------------------------------------------
// Verify runtime config (resolved from environment / stack outputs)
// ---------------------------------------------------------------------------

/**
 * The runtime parameters `verify.ts` needs. These originate from the deployed
 * stack's AWS CloudFormation outputs (see `bin/app.ts` CfnOutputs, task 12). For now
 * the operator exports them as environment variables; a future enhancement can
 * read them from `describe-stacks`.
 *
 * Environment variables:
 *   - `NF_INSTANCE_ID`     — the AWS Systems Manager (SSM)-managed workload instance id.
 *   - `NF_FIREWALL_NAME`   — the deployed firewall name (metric dimension).
 *   - `NF_ALERT_LOG_GROUP` — the ALERT Amazon CloudWatch Logs group name.
 *   - `NF_FLOW_LOG_GROUP`  — the FLOW CloudWatch Logs group name.
 *   - `NF_TARGET_URL`      — the egress target the probe `curl`s. A per-scenario
 *     override `NF_TARGET_URL_<n>` (e.g. `NF_TARGET_URL_1`) takes precedence.
 */
export interface VerifyRuntimeConfig {
  readonly instanceId: string;
  readonly targetUrl: string;
  readonly firewallName: string;
  readonly alertLogGroupName: string;
  readonly flowLogGroupName: string;
}

/** Either a complete runtime config, or the list of missing env vars. */
export type VerifyConfigResult =
  | { readonly ok: true; readonly config: VerifyRuntimeConfig }
  | { readonly ok: false; readonly missing: readonly string[] };

/**
 * Resolve the {@link VerifyRuntimeConfig} for `scenario` from `env`. The target
 * URL prefers a per-scenario `NF_TARGET_URL_<n>` and falls back to
 * `NF_TARGET_URL`. Returns `{ ok: false, missing }` listing the env vars that
 * still need exporting — callers stay tolerant when verification is not
 * configured rather than treating it as a hard failure of a deploy.
 */
export function resolveVerifyConfig(
  scenario: Scenario,
  env: NodeJS.ProcessEnv,
): VerifyConfigResult {
  const perScenarioUrl =
    scenario !== "none" ? env[`NF_TARGET_URL_${scenario}`] : undefined;
  const targetUrl = perScenarioUrl ?? env.NF_TARGET_URL;

  const missing: string[] = [];
  if (!env.NF_INSTANCE_ID) {
    missing.push("NF_INSTANCE_ID");
  }
  if (!targetUrl) {
    missing.push(scenario !== "none" ? `NF_TARGET_URL_${scenario} (or NF_TARGET_URL)` : "NF_TARGET_URL");
  }
  if (!env.NF_FIREWALL_NAME) {
    missing.push("NF_FIREWALL_NAME");
  }
  if (!env.NF_ALERT_LOG_GROUP) {
    missing.push("NF_ALERT_LOG_GROUP");
  }
  if (!env.NF_FLOW_LOG_GROUP) {
    missing.push("NF_FLOW_LOG_GROUP");
  }

  if (missing.length > 0) {
    return { ok: false, missing };
  }

  return {
    ok: true,
    config: {
      instanceId: env.NF_INSTANCE_ID as string,
      targetUrl: targetUrl as string,
      firewallName: env.NF_FIREWALL_NAME as string,
      alertLogGroupName: env.NF_ALERT_LOG_GROUP as string,
      flowLogGroupName: env.NF_FLOW_LOG_GROUP as string,
    },
  };
}

// ---------------------------------------------------------------------------
// Injectable dependencies
// ---------------------------------------------------------------------------

/**
 * The side-effecting surface the handlers depend on. Every field defaults to the
 * real implementation via {@link defaultDeps}; tests override `deploy` /
 * `verifyScenario` (and usually `readState`/`writeState`/`log`/`statePath`) to
 * drive the handlers hermetically.
 */
export interface CliDeps {
  /** Run `cdk deploy` (defaults to `runner.deploy`). */
  readonly deploy: (options?: CdkDeployOptions) => Promise<CdkRunResult>;
  /** Run `cdk destroy` (defaults to `runner.destroy`). */
  readonly destroy: (options?: CdkDestroyOptions) => Promise<CdkRunResult>;
  /**
   * Enumerate every resource tagged `tagKey = tagValue` (defaults to
   * {@link sweepTaggedResources} backed by the Resource Groups Tagging API).
   */
  readonly sweepTaggedResources: (tagKey: string, tagValue: string) => Promise<SweepResult>;
  /** Run the scenario verification (defaults to `verify.verifyScenario`). */
  readonly verifyScenario: (
    scenario: Scenario,
    params: VerifyScenarioParams,
  ) => Promise<VerificationResult>;
  /** Render+write the CDK context file (defaults to `context.writeContextFile`). */
  readonly writeContextFile: (state: DesiredState, filePath?: string) => string;
  /** Read the persisted state (defaults to {@link readStateFile}). */
  readonly readState: (statePath: string) => PersistedState;
  /** Write the persisted state (defaults to {@link writeStateFile}). */
  readonly writeState: (state: PersistedState, statePath: string) => void;
  /** Resolve verify runtime config (defaults to {@link resolveVerifyConfig}). */
  readonly resolveVerifyConfig: (scenario: Scenario, env: NodeJS.ProcessEnv) => VerifyConfigResult;
  /** Wall clock (defaults to `() => new Date()`). */
  readonly now: () => Date;
  /** Standard-out sink (defaults to `console.log`). */
  readonly log: (message: string) => void;
  /** Standard-error sink (defaults to `console.error`). */
  readonly errorLog: (message: string) => void;
  /** Path to the persisted state file (defaults to {@link DEFAULT_STATE_PATH}). */
  readonly statePath: string;
  /** Path to the generated context file (defaults to context's default). */
  readonly contextPath: string;
  /** Environment used for verify-config resolution (defaults to `process.env`). */
  readonly env: NodeJS.ProcessEnv;
}

/** Build the default {@link CliDeps} wired to the real imports. */
export function defaultDeps(): CliDeps {
  return {
    deploy: realDeploy,
    destroy: realDestroy,
    sweepTaggedResources: (tagKey, tagValue) => sweepTaggedResources(tagKey, tagValue),
    verifyScenario: realVerifyScenario,
    writeContextFile,
    readState: (statePath) => readStateFile(statePath),
    writeState: (state, statePath) => writeStateFile(state, statePath),
    resolveVerifyConfig,
    now: () => new Date(),
    log: (message) => console.log(message),
    errorLog: (message) => console.error(message),
    statePath: DEFAULT_STATE_PATH,
    contextPath: DEFAULT_CONTEXT_PATH,
    env: process.env,
  };
}

// ---------------------------------------------------------------------------
// Argument parsing (pure)
// ---------------------------------------------------------------------------

/** The set of CLI verbs. `destroy` is recognized but stubbed until task 16. */
export type Command = "baseline" | "activate" | "revert" | "verify" | "status" | "destroy" | "help";

/** A scenario selector accepted by `activate`/`revert`/`verify` (excludes baseline). */
export type ScenarioArg = "1" | "2" | "3";

/** The result of parsing argv: either a dispatchable command or an error. */
export type ParsedArgs =
  | { readonly ok: true; readonly command: "activate" | "revert" | "verify"; readonly scenario: ScenarioArg }
  | { readonly ok: true; readonly command: "baseline" | "status" | "destroy" | "help" }
  | { readonly ok: false; readonly error: string };

/** Usage text printed on a parse error or `help`. */
export const USAGE = [
  "Usage: scenarioctl <command> [args]",
  "",
  "Commands:",
  "  baseline                 Deploy the working baseline and verify healthy egress.",
  "  activate <1|2|3>         Activate a break-fix scenario and verify its trigger.",
  "  revert   <1|2|3>         Revert a scenario to baseline and verify egress restored.",
  "  verify   <1|2|3>         Run the egress probe + drop checks for a scenario (no deploy).",
  "  status                   Print the active scenario.",
  "  destroy                  Tear down the environment (cdk destroy + tag-based straggler sweep).",
].join("\n");

/** Validate that `value` is a `1|2|3` scenario argument. */
function parseScenarioArg(value: string | undefined): ScenarioArg | undefined {
  return value === "1" || value === "2" || value === "3" ? value : undefined;
}

/**
 * Parse `argv` (already sliced past `node script`) into a {@link ParsedArgs}.
 * Pure: no side effects, no I/O. `activate`/`revert`/`verify` require a valid
 * `1|2|3` argument; the rest take none.
 */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const [rawCommand, rawScenario] = argv;

  if (rawCommand === undefined || rawCommand === "--help" || rawCommand === "-h" || rawCommand === "help") {
    return { ok: true, command: "help" };
  }

  switch (rawCommand) {
    case "activate":
    case "revert":
    case "verify": {
      const scenario = parseScenarioArg(rawScenario);
      if (!scenario) {
        return {
          ok: false,
          error: `Command "${rawCommand}" requires a scenario argument of 1, 2, or 3 (got ${rawScenario === undefined ? "none" : `"${rawScenario}"`}).`,
        };
      }
      return { ok: true, command: rawCommand, scenario };
    }
    case "baseline":
    case "status":
    case "destroy":
      return { ok: true, command: rawCommand };
    default:
      return { ok: false, error: `Unknown command: "${rawCommand}".` };
  }
}

// ---------------------------------------------------------------------------
// Deploy helper (shared by baseline / activate / revert)
// ---------------------------------------------------------------------------

/**
 * Render `state` into the context file + `--context` args and run `cdk deploy`
 * for the whole app non-interactively. The context file is written for operator
 * inspection; the `--context` args make the deploy self-contained.
 */
async function deployState(state: DesiredState, deps: CliDeps): Promise<CdkRunResult> {
  const ctx = renderContext(state);
  deps.writeContextFile(state, deps.contextPath);
  return deps.deploy({
    all: true,
    requireApprovalNever: true,
    context: contextToCliArgs(ctx),
  });
}

/** Print a structured failure report for a non-zero `cdk deploy`. */
function reportDeployFailure(stepLabel: string, result: CdkRunResult, deps: CliDeps): void {
  if (result.ok) {
    return;
  }
  const exit = result.exitCode === null ? "null" : String(result.exitCode);
  deps.errorLog(`[${stepLabel}] cdk deploy failed (exit code ${exit}).`);
  deps.errorLog(`  step: cdk deploy`);
  deps.errorLog(`  error: ${result.error}`);
  if (result.failedResource) {
    const { logicalId, resourceType, statusReason } = result.failedResource;
    const typePart = resourceType ? ` (${resourceType})` : "";
    const reasonPart = statusReason ? `: ${statusReason}` : "";
    deps.errorLog(`  failed resource: ${logicalId}${typePart}${reasonPart}`);
  }
  deps.errorLog(`  last-good state preserved; re-run "${stepLabel}" after addressing the error.`);
}

// ---------------------------------------------------------------------------
// Verification helper (shared by baseline / activate / revert / verify)
// ---------------------------------------------------------------------------

/** Outcome of a verification attempt, for exit-code computation by callers. */
interface VerifyReport {
  /** True when the probe + checks actually ran (verification was configured). */
  readonly ran: boolean;
  /** True when the observed outcome matched the expectation. */
  readonly success: boolean;
}

/**
 * Run the egress probe + drop checks for `scenario` and report the outcome.
 *
 * `expectTrigger` encodes the success condition: scenario activation expects the
 * firewall to DROP the affected egress (`trigger-observed`); baseline/revert
 * expect healthy egress (`trigger-not-observed`).
 *
 * When verification is not configured (missing env vars) the check is SKIPPED
 * with a clear message and `ran: false`, so a deploy is not failed merely
 * because the stack outputs were not exported.
 */
async function verifyAndReport(
  scenario: Scenario,
  expectTrigger: boolean,
  stepLabel: string,
  deps: CliDeps,
): Promise<VerifyReport> {
  const resolved = deps.resolveVerifyConfig(scenario, deps.env);
  if (!resolved.ok) {
    deps.log(`[${stepLabel}] verification skipped — missing ${resolved.missing.join(", ")}.`);
    deps.log(
      "  Export the deployed stack outputs (see bin/app.ts CfnOutputs) as the NF_* environment variables to enable verification.",
    );
    return { ran: false, success: false };
  }

  const result = await deps.verifyScenario(scenario, { ...resolved.config });

  if (result.kind === "probe-error") {
    deps.errorLog(
      `[${stepLabel}] verification could not run — probe error (${result.stage}): ${result.message}`,
    );
    return { ran: true, success: false };
  }

  const observed = result.kind === "trigger-observed";
  const success = observed === expectTrigger;
  const signals = result.details.observedSignals;
  const signalText = signals.length > 0 ? ` signals: ${signals.join(", ")}.` : "";

  if (expectTrigger) {
    if (observed) {
      deps.log(`[${stepLabel}] verified — firewall dropped the affected egress (trigger observed).${signalText}`);
    } else {
      deps.errorLog(
        `[${stepLabel}] verification did NOT observe the expected drop trigger within the requirement window (egress still succeeded).`,
      );
    }
  } else {
    if (!observed) {
      deps.log(`[${stepLabel}] verified — baseline egress is healthy (no drop trigger observed).`);
    } else {
      deps.errorLog(
        `[${stepLabel}] verification still observed a drop trigger after returning to baseline.${signalText}`,
      );
    }
  }

  return { ran: true, success };
}

/** Compute the exit code from a verification report. */
function verificationExit(report: VerifyReport, tolerantWhenNotRun: boolean): number {
  if (!report.ran) {
    return tolerantWhenNotRun ? EXIT_OK : EXIT_FAILURE;
  }
  return report.success ? EXIT_OK : EXIT_FAILURE;
}

// ---------------------------------------------------------------------------
// Command handlers (exported for unit testing)
// ---------------------------------------------------------------------------

/**
 * `baseline`: deploy the canonical working state, record it, then verify the
 * test workload's egress succeeds (R9.4 — the baseline verification the runbook
 * documents; here we deploy to baseline and confirm egress is healthy).
 */
export async function runBaseline(deps: CliDeps): Promise<number> {
  const state = baseline();
  const result = await deployState(state, deps);
  if (!result.ok) {
    reportDeployFailure("baseline", result, deps);
    return EXIT_FAILURE;
  }
  deps.writeState({ activeScenario: "none" }, deps.statePath);
  deps.log("[baseline] deployed baseline (activeScenario=none).");

  const report = await verifyAndReport("none", false, "baseline", deps);
  return verificationExit(report, true);
}

/**
 * `activate <n>`: enforce the single-active-scenario rule, deploy the scenario,
 * record the new state only after a successful deploy, then verify the trigger
 * (R9.1, R9.3, R9.5, R9.7, R8.3, R8.8).
 */
export async function runActivate(scenario: ScenarioArg, deps: CliDeps): Promise<number> {
  const current = deps.readState(deps.statePath);

  // R9.1 — re-activating the already-active scenario is a no-op success.
  if (current.activeScenario === scenario) {
    deps.log(`[activate ${scenario}] scenario ${scenario} is already active; nothing to do.`);
    return EXIT_OK;
  }

  // R9.5 — a different scenario is active; instruct revert-first.
  if (current.activeScenario !== "none") {
    deps.errorLog(
      `[activate ${scenario}] scenario ${current.activeScenario} is currently active. ` +
        `Only one scenario can be active at a time — run "scenarioctl revert ${current.activeScenario}" first, then activate ${scenario}.`,
    );
    return EXIT_FAILURE;
  }

  // Render context for the scenario.
  const state = desired(scenario);
  const result = await deployState(state, deps);
  if (!result.ok) {
    // R9.7 / R8.8 — report the failing step, preserve last-good state, exit non-zero.
    reportDeployFailure(`activate ${scenario}`, result, deps);
    return EXIT_FAILURE;
  }

  // Deploy succeeded: now persist the new active scenario.
  deps.writeState({ activeScenario: scenario }, deps.statePath);
  deps.log(`[activate ${scenario}] deployed scenario ${scenario}.`);

  // R9.3 — confirm the expected trigger occurred.
  const report = await verifyAndReport(scenario, true, `activate ${scenario}`, deps);
  return verificationExit(report, true);
}

/**
 * `revert <n>`: revert scenario `n` to baseline. Reverting a scenario that is
 * not the active one is a no-op success leaving the current state intact (R9.2).
 * Otherwise deploy baseline, record it, and verify egress is restored (R9.6).
 */
export async function runRevert(scenario: ScenarioArg, deps: CliDeps): Promise<number> {
  const current = deps.readState(deps.statePath);

  // R9.2 — reverting a non-active scenario is a no-op.
  if (current.activeScenario !== scenario) {
    if (current.activeScenario === "none") {
      deps.log(`[revert ${scenario}] scenario ${scenario} is not active; baseline already intact.`);
    } else {
      deps.log(
        `[revert ${scenario}] scenario ${scenario} is not active (scenario ${current.activeScenario} is active); nothing to revert.`,
      );
    }
    return EXIT_OK;
  }

  const state = baseline();
  const result = await deployState(state, deps);
  if (!result.ok) {
    reportDeployFailure(`revert ${scenario}`, result, deps);
    return EXIT_FAILURE;
  }

  deps.writeState({ activeScenario: "none" }, deps.statePath);
  deps.log(`[revert ${scenario}] reverted scenario ${scenario} to baseline.`);

  // R9.6 — confirm baseline egress is restored.
  const report = await verifyAndReport("none", false, `revert ${scenario}`, deps);
  return verificationExit(report, true);
}

/**
 * `verify <n>`: run the egress probe + drop checks for scenario `n` without
 * deploying. Exit code reflects whether the expected trigger was observed; if
 * verification is not configured this is treated as a failure (the operator
 * explicitly asked to verify and it could not run).
 */
export async function runVerify(scenario: ScenarioArg, deps: CliDeps): Promise<number> {
  const report = await verifyAndReport(scenario, true, `verify ${scenario}`, deps);
  return verificationExit(report, false);
}

/** `status`: print the persisted active scenario. */
export function runStatus(deps: CliDeps): number {
  const state = deps.readState(deps.statePath);
  deps.log(`activeScenario: ${state.activeScenario}`);
  return EXIT_OK;
}

/**
 * `destroy`: tear the whole environment down (R10.1–R10.3).
 *
 * Sequence:
 *   1. Read the persisted state. If a scenario is active, deploy baseline first
 *      so teardown starts from a clean baseline (the scenario's broken
 *      mid-flow routes / regressing rule changes are reverted before destroy).
 *      A failed revert-deploy is logged as a warning but does NOT abort the
 *      teardown — `cdk destroy` should still attempt to remove resources. The
 *      state file is then normalized to baseline.
 *   2. Run `cdk destroy --all --force`.
 *   3. On a clean destroy: report success ("no tagged resources remain"), write
 *      baseline state, and return {@link EXIT_OK} (R10.3).
 *   4. On a destroy failure: run a tag-based sweep (`Project = nf-devops-agent`)
 *      that continues past individual page failures, list every remaining tagged
 *      resource (arn + type), report the destroy error, note that teardown
 *      completed with failures, and return {@link EXIT_FAILURE} (R10.2).
 */
export async function runDestroy(deps: CliDeps): Promise<number> {
  // 1. Revert any active scenario to baseline before destroying.
  const current = deps.readState(deps.statePath);
  if (current.activeScenario !== "none") {
    deps.log(
      `[destroy] scenario ${current.activeScenario} is active; reverting to baseline before teardown.`,
    );
    const revertResult = await deployState(baseline(), deps);
    if (!revertResult.ok) {
      // Teardown must still proceed — a failed revert leaves the broken state
      // in place, but destroy removes the resources regardless.
      deps.errorLog(
        `[destroy] warning: reverting to baseline failed (${revertResult.error}); proceeding with destroy anyway.`,
      );
    }
  }
  // Normalize persisted state to baseline regardless of revert outcome — the
  // resources are about to be destroyed.
  deps.writeState({ activeScenario: "none" }, deps.statePath);

  // 2. Destroy the whole app non-interactively, with the baseline context so the
  //    synthesized app matches what is deployed.
  const result = await deps.destroy({
    all: true,
    force: true,
    context: contextToCliArgs(renderContext(baseline())),
  });

  // 3. Clean teardown.
  if (result.ok) {
    deps.writeState({ activeScenario: "none" }, deps.statePath);
    deps.log("[destroy] teardown complete; no tagged resources remain.");
    return EXIT_OK;
  }

  // 4. Destroy failed — report the error and sweep for tagged stragglers.
  const exit = result.exitCode === null ? "null" : String(result.exitCode);
  deps.errorLog(`[destroy] cdk destroy failed (exit code ${exit}).`);
  deps.errorLog(`  error: ${result.error}`);

  const sweep = await deps.sweepTaggedResources(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);

  for (const sweepError of sweep.errors) {
    deps.errorLog(`[destroy] tag sweep page error (continuing): ${sweepError}`);
  }

  if (sweep.resources.length === 0) {
    deps.errorLog(
      `[destroy] teardown completed with failures; no resources tagged ${PROJECT_TAG_KEY}=${PROJECT_TAG_VALUE} could be enumerated (they may already be gone or the sweep could not run).`,
    );
  } else {
    deps.errorLog(
      `[destroy] teardown completed with failures; ${sweep.resources.length} resource(s) tagged ${PROJECT_TAG_KEY}=${PROJECT_TAG_VALUE} remain:`,
    );
    for (const resource of sweep.resources) {
      const typePart = resource.type ? ` (${resource.type})` : "";
      deps.errorLog(`  - ${resource.arn}${typePart}`);
    }
    deps.errorLog(
      "  Delete the resources listed above manually, then re-run \"scenarioctl destroy\" to confirm none remain.",
    );
  }

  return EXIT_FAILURE;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Parse `argv` and dispatch to the matching handler, returning the process exit
 * code. Never calls `process.exit` itself — the entrypoint guard does.
 */
export async function main(
  argv: readonly string[],
  deps: CliDeps = defaultDeps(),
): Promise<number> {
  const parsed = parseArgs(argv);

  if (!parsed.ok) {
    deps.errorLog(parsed.error);
    deps.errorLog("");
    deps.errorLog(USAGE);
    return EXIT_FAILURE;
  }

  switch (parsed.command) {
    case "help":
      deps.log(USAGE);
      return EXIT_OK;
    case "baseline":
      return runBaseline(deps);
    case "activate":
      return runActivate(parsed.scenario, deps);
    case "revert":
      return runRevert(parsed.scenario, deps);
    case "verify":
      return runVerify(parsed.scenario, deps);
    case "status":
      return runStatus(deps);
    case "destroy":
      return runDestroy(deps);
  }
}

/* istanbul ignore next -- thin process entrypoint; the only place process.exit is called. */
if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error: unknown) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exit(EXIT_FAILURE);
    },
  );
}
