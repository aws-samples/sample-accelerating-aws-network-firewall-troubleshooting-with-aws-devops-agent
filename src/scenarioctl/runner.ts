/**
 * CDK process runner for the scenario control layer (side-effecting).
 *
 * This module is the single seam between `scenarioctl` and the AWS CDK CLI. It
 * spawns `cdk deploy` / `cdk destroy` as a child process, streams their output
 * through to the operator's terminal while capturing it, and turns the child's
 * exit into a discriminated {@link CdkRunResult} so the CLI (task 15) can branch
 * on success/failure without `try`/`catch` on control flow.
 *
 * Why a discriminated result instead of throwing:
 *   R1.6 and R9.7 require that on a failed deploy the tool *reports* the failing
 *   resource and reason and leaves the environment re-runnable (CDK/CFN rolls the
 *   stack back to its last stable state; this module performs no imperative
 *   mutation of its own). Returning `{ ok: false, ... }` lets the CLI print a
 *   clean failure report and exit non-zero without unwinding the stack through
 *   exceptions.
 *
 * Failure attribution (R1.6): on a non-zero exit we scan the captured CDK/CFN
 * output for the FIRST failing AWS CloudFormation resource and surface its logical
 * id, resource type, and status reason in {@link CdkRunResult.failedResource}.
 * Parsing is best-effort and defensive: if no resource line can be parsed, the
 * raw stderr (or stdout) is still returned in {@link CdkRunResult.error}.
 *
 * Testability: the child-process spawner is injectable via the `spawnFn` option
 * (defaulting to `child_process.spawn`), and {@link parseFailedResource} is a
 * pure exported function, so the parsing and result-shaping logic can be
 * exercised without spawning a real `cdk`.
 */

import { spawn as realSpawn, SpawnOptions } from "child_process";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Injectable spawn seam
// ---------------------------------------------------------------------------

/**
 * Minimal child-process surface this module relies on. The real `ChildProcess`
 * returned by `child_process.spawn` satisfies this; tests can supply a tiny fake
 * that emits `data`/`close`/`error` to drive {@link runCdk} deterministically.
 */
export interface ChildProcessLike {
  /** Captured standard output stream (`pipe` stdio), or null. */
  readonly stdout: NodeJS.ReadableStream | null;
  /** Captured standard error stream (`pipe` stdio), or null. */
  readonly stderr: NodeJS.ReadableStream | null;
  /** Subscribe to a spawn failure (e.g. the cdk binary was not found). */
  on(event: "error", listener: (error: Error) => void): this;
  /** Subscribe to the child closing, with its exit code (null if signalled). */
  on(event: "close", listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
}

/**
 * Signature of the spawner. Matches the relevant `child_process.spawn` overload
 * (`(command, args, options) => ChildProcess`) while returning the narrower
 * {@link ChildProcessLike} so test doubles need not implement all of
 * `ChildProcess`.
 */
export type SpawnFn = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => ChildProcessLike;

/** Default spawner: a thin wrapper over `child_process.spawn`. */
const defaultSpawn: SpawnFn = (command, args, options) => realSpawn(command, args, options);

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/**
 * The failing CloudFormation resource extracted from CDK/CFN output (R1.6). All
 * fields beyond `logicalId` are optional because parsing is best-effort.
 */
export interface FailedResource {
  /** The CloudFormation logical id of the resource that failed. */
  readonly logicalId: string;
  /** The resource type (e.g. `AWS::NetworkFirewall::Firewall`), when parsed. */
  readonly resourceType?: string;
  /** The CloudFormation status reason (the failure message), when parsed. */
  readonly statusReason?: string;
}

/**
 * Outcome of running the cdk CLI. Discriminated on `ok`:
 *   - `ok: true`  — the child exited 0; `stdout`/`stderr` carry the full output.
 *   - `ok: false` — the child failed to spawn (`exitCode: null`) or exited
 *     non-zero. `error` always holds a human-readable message (falling back to
 *     raw stderr/stdout), and `failedResource` is present when a failing CFN
 *     resource could be parsed from the output.
 */
export type CdkRunResult =
  | { readonly ok: true; readonly exitCode: 0; readonly stdout: string; readonly stderr: string }
  | {
      readonly ok: false;
      readonly exitCode: number | null;
      readonly stdout: string;
      readonly stderr: string;
      readonly error: string;
      readonly failedResource?: FailedResource;
    };

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Options shared by every cdk invocation. */
export interface CdkRunOptions {
  /**
   * Context key/value pairs rendered into repeated `--context key=value` args.
   * This is how the desired scenario state reaches the synthesized template.
   */
  readonly context?: Readonly<Record<string, string>>;
  /** Working directory for the cdk app (defaults to `process.cwd()`). */
  readonly appCwd?: string;
  /** Environment for the child (defaults to the parent `process.env`). */
  readonly env?: NodeJS.ProcessEnv;
  /** Extra raw args appended after the computed args (escape hatch). */
  readonly extraArgs?: readonly string[];
  /**
   * Pipe the child's stdout/stderr through to the parent process so operators
   * see live progress. Defaults to `true`. Output is captured regardless.
   */
  readonly echo?: boolean;
  /** Injectable spawner; defaults to `child_process.spawn`. */
  readonly spawnFn?: SpawnFn;
}

/** Options for {@link deploy} (`cdk deploy`). */
export interface CdkDeployOptions extends CdkRunOptions {
  /** Add `--require-approval never` (non-interactive deploy). */
  readonly requireApprovalNever?: boolean;
  /** Add `--all` to deploy every stack in the app. */
  readonly all?: boolean;
  /** Explicit stack names/ids to deploy (omit to deploy the app default). */
  readonly stacks?: readonly string[];
}

/** Options for {@link destroy} (`cdk destroy`). */
export interface CdkDestroyOptions extends CdkRunOptions {
  /** Add `--force` to skip the destructive-action confirmation prompt. */
  readonly force?: boolean;
  /** Add `--all` to destroy every stack in the app. */
  readonly all?: boolean;
  /** Explicit stack names/ids to destroy (omit to destroy the app default). */
  readonly stacks?: readonly string[];
}

// ---------------------------------------------------------------------------
// Command resolution
// ---------------------------------------------------------------------------

/**
 * Resolve how to invoke the cdk CLI. Prefers a locally installed
 * `node_modules/.bin/cdk` (searched under `appCwd`, the current working
 * directory, and this package's root) and falls back to `npx cdk`.
 */
export function resolveCdkCommand(appCwd?: string): { command: string; prefixArgs: string[] } {
  const isWindows = process.platform === "win32";
  const binName = isWindows ? "cdk.cmd" : "cdk";
  const searchRoots = [appCwd, process.cwd(), path.resolve(__dirname, "..", "..")].filter(
    (root): root is string => typeof root === "string" && root.length > 0,
  );

  for (const root of searchRoots) {
    const candidate = path.join(root, "node_modules", ".bin", binName);
    if (fs.existsSync(candidate)) {
      return { command: candidate, prefixArgs: [] };
    }
  }

  return { command: isWindows ? "npx.cmd" : "npx", prefixArgs: ["cdk"] };
}

/** Render a context record into repeated `--context key=value` argument pairs. */
function buildContextArgs(context?: Readonly<Record<string, string>>): string[] {
  if (!context) {
    return [];
  }
  const args: string[] = [];
  for (const [key, value] of Object.entries(context)) {
    args.push("--context", `${key}=${value}`);
  }
  return args;
}

// ---------------------------------------------------------------------------
// CloudFormation failure parsing (R1.6)
// ---------------------------------------------------------------------------

/** A whole cell that is a CloudFormation `*_FAILED` status (e.g. `CREATE_FAILED`). */
const FAILED_STATUS = /^[A-Z]+(?:_[A-Z]+)*_FAILED$/;

/** CFN's "this resource was cancelled because a sibling failed" noise reason. */
const CANCELLED_REASON = /resource creation cancelled/i;

/**
 * Parse the FIRST failing CloudFormation resource from captured CDK/CFN output.
 *
 * CDK prints progress/error lines shaped like:
 *
 *   `StackName | 3/10 | 12:00:00 AM | CREATE_FAILED | AWS::Some::Type | LogicalId (CfnId) reason...`
 *
 * Cells are pipe-delimited; the cell after the `*_FAILED` status is the resource
 * type, and the remaining cells hold `LogicalId (CfnId) reason`. To surface the
 * root cause rather than a cascaded cancellation, we prefer the first failing
 * line whose reason is present and is not "Resource creation cancelled", falling
 * back to the first failing line otherwise. Returns `undefined` when no failing
 * resource line can be parsed (callers should then rely on raw stderr).
 */
export function parseFailedResource(output: string): FailedResource | undefined {
  const candidates: FailedResource[] = [];

  for (const line of output.split(/\r?\n/)) {
    const cells = line.split("|").map((cell) => cell.trim());
    if (cells.length < 5) {
      continue;
    }
    const statusIndex = cells.findIndex((cell) => FAILED_STATUS.test(cell));
    if (statusIndex < 0 || statusIndex + 2 > cells.length) {
      continue;
    }

    const resourceType = cells[statusIndex + 1];
    const remainder = cells.slice(statusIndex + 2).join(" | ").trim();
    const { logicalId, statusReason } = parseLogicalAndReason(remainder);
    if (logicalId.length === 0) {
      continue;
    }

    const candidate: FailedResource = {
      logicalId,
      ...(resourceType.length > 0 ? { resourceType } : {}),
      ...(statusReason ? { statusReason } : {}),
    };
    candidates.push(candidate);
  }

  if (candidates.length === 0) {
    return undefined;
  }

  const rootCause = candidates.find(
    (candidate) =>
      candidate.statusReason !== undefined &&
      candidate.statusReason.length > 0 &&
      !CANCELLED_REASON.test(candidate.statusReason),
  );
  return rootCause ?? candidates[0];
}

/** Split a `LogicalId (CfnId) reason...` (or `LogicalId reason...`) tail. */
function parseLogicalAndReason(remainder: string): {
  logicalId: string;
  statusReason?: string;
} {
  if (remainder.length === 0) {
    return { logicalId: "" };
  }

  const withCfnId = remainder.match(/^(\S+)\s*\([^)]*\)\s*(.*)$/);
  if (withCfnId) {
    const reason = withCfnId[2].trim();
    return reason.length > 0 ? { logicalId: withCfnId[1], statusReason: reason } : { logicalId: withCfnId[1] };
  }

  const withoutCfnId = remainder.match(/^(\S+)\s*(.*)$/);
  if (withoutCfnId) {
    const reason = withoutCfnId[2].trim();
    return reason.length > 0
      ? { logicalId: withoutCfnId[1], statusReason: reason }
      : { logicalId: withoutCfnId[1] };
  }

  return { logicalId: remainder };
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/**
 * Spawn the cdk CLI with `args`, capturing (and, unless `echo` is false,
 * forwarding) its stdout/stderr, and resolve a {@link CdkRunResult} when the
 * child closes.
 *
 * The returned Promise never rejects: a spawn failure or a non-zero exit becomes
 * `{ ok: false, ... }` so the CLI can branch on the result. Context is appended
 * as repeated `--context key=value` pairs, followed by any `extraArgs`.
 */
export async function runCdk(args: readonly string[], options: CdkRunOptions = {}): Promise<CdkRunResult> {
  const spawnFn = options.spawnFn ?? defaultSpawn;
  const echo = options.echo ?? true;
  const { command, prefixArgs } = resolveCdkCommand(options.appCwd);
  const fullArgs = [...prefixArgs, ...args, ...buildContextArgs(options.context), ...(options.extraArgs ?? [])];

  return new Promise<CdkRunResult>((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;

    const finish = (result: CdkRunResult): void => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(result);
    };

    const child = spawnFn(command, fullArgs, {
      cwd: options.appCwd ?? process.cwd(),
      env: options.env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    child.stdout?.on("data", (chunk: Buffer | string) => {
      const text = chunk.toString();
      stdout += text;
      if (echo) {
        process.stdout.write(text);
      }
    });

    child.stderr?.on("data", (chunk: Buffer | string) => {
      const text = chunk.toString();
      stderr += text;
      if (echo) {
        process.stderr.write(text);
      }
    });

    child.on("error", (error: Error) => {
      finish({
        ok: false,
        exitCode: null,
        stdout,
        stderr,
        error: `Failed to spawn cdk via "${command}": ${error.message}`,
      });
    });

    child.on("close", (code: number | null) => {
      if (code === 0) {
        finish({ ok: true, exitCode: 0, stdout, stderr });
        return;
      }

      const failedResource = parseFailedResource(`${stdout}\n${stderr}`);
      const rawOutput = stderr.trim().length > 0 ? stderr.trim() : stdout.trim();
      const error =
        rawOutput.length > 0
          ? rawOutput
          : `cdk ${args[0] ?? "command"} exited with code ${code === null ? "null" : code}`;

      finish({
        ok: false,
        exitCode: code,
        stdout,
        stderr,
        error,
        ...(failedResource ? { failedResource } : {}),
      });
    });
  });
}

/**
 * Run `cdk deploy`. With `all` deploys every stack; otherwise deploys the
 * provided `stacks` (or the app default when none given). `requireApprovalNever`
 * adds `--require-approval never` for non-interactive runs.
 */
export function deploy(options: CdkDeployOptions = {}): Promise<CdkRunResult> {
  const args: string[] = ["deploy"];
  if (options.all) {
    args.push("--all");
  }
  if (options.stacks) {
    args.push(...options.stacks);
  }
  if (options.requireApprovalNever) {
    args.push("--require-approval", "never");
  }
  return runCdk(args, options);
}

/**
 * Run `cdk destroy`. With `all` destroys every stack; otherwise destroys the
 * provided `stacks` (or the app default when none given). `force` adds `--force`
 * to skip the interactive confirmation.
 */
export function destroy(options: CdkDestroyOptions = {}): Promise<CdkRunResult> {
  const args: string[] = ["destroy"];
  if (options.all) {
    args.push("--all");
  }
  if (options.stacks) {
    args.push(...options.stacks);
  }
  if (options.force) {
    args.push("--force");
  }
  return runCdk(args, options);
}
