/**
 * CDK context rendering for the scenario control layer.
 *
 * This module bridges the pure scenario state machine (`state.ts`) to AWS CDK.
 * It renders a {@link DesiredState} into the plain {@link ScenarioContext} object
 * the stacks read back, and writes that object to a JSON file on disk that the
 * CDK app loads into context (e.g. via `cdk.json`'s `context` block being merged
 * with, or the app reading, this generated file).
 *
 * Read pattern (how the stacks consume what this module writes):
 *   Each {@link ScenarioContext} field is rendered as a TOP-LEVEL context key, so
 *   a stack reads an individual value with:
 *
 *     const activeScenario = app.node.tryGetContext("activeScenario");
 *     const allowPriority  = app.node.tryGetContext("allowPriority");
 *     // ...one tryGetContext(<field name>) per ScenarioContext field.
 *
 * Purity contract: {@link renderContext} is pure (it just delegates to
 * `toContext`). The only side effect in this module is the filesystem write
 * performed by {@link writeContextFile}, which keeps rendering separable from
 * disk I/O so the rendered object can be asserted without touching the disk.
 */

import * as fs from "fs";
import * as path from "path";

import { DesiredState, ScenarioContext, toContext } from "./state";

/**
 * Default generated-context filename, written at the repository root. This name
 * is ignored by `.gitignore` (it must never be committed — it is regenerated
 * from the desired state on every scenario change).
 */
export const DEFAULT_CONTEXT_FILENAME = "cdk.context.generated.json";

/**
 * Absolute default path for the generated context file: the repository root
 * (two levels up from `src/scenarioctl/`) joined with
 * {@link DEFAULT_CONTEXT_FILENAME}.
 */
export const DEFAULT_CONTEXT_PATH = path.resolve(
  __dirname,
  "..",
  "..",
  DEFAULT_CONTEXT_FILENAME,
);

/**
 * Render a {@link DesiredState} into the plain {@link ScenarioContext} object the
 * stacks read back via `app.node.tryGetContext(...)`. Pure and JSON-serializable.
 */
export function renderContext(state: DesiredState): ScenarioContext {
  return toContext(state);
}

/**
 * Serialize a rendered {@link ScenarioContext} to the pretty-printed JSON string
 * that gets written to disk. Pure (no side effects) so callers and tests can
 * inspect the exact on-disk representation without touching the filesystem.
 *
 * The trailing newline keeps the file POSIX-friendly and diff-clean.
 */
export function serializeContext(state: DesiredState): string {
  return `${JSON.stringify(renderContext(state), null, 2)}\n`;
}

/**
 * Render `state` and write it as JSON to disk, returning the absolute path
 * written.
 *
 * @param state the desired state to render.
 * @param filePath optional target path; defaults to {@link DEFAULT_CONTEXT_PATH}
 *   (`<repo root>/cdk.context.generated.json`). Relative paths are resolved
 *   against the current working directory.
 * @returns the absolute path of the file that was written.
 */
export function writeContextFile(
  state: DesiredState,
  filePath: string = DEFAULT_CONTEXT_PATH,
): string {
  const resolved = path.resolve(filePath);
  fs.writeFileSync(resolved, serializeContext(state), { encoding: "utf8" });
  return resolved;
}
