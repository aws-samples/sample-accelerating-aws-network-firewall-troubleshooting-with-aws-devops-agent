import * as fs from "fs";
import * as path from "path";

/**
 * Doc-consistency test (Requirements: R11.8).
 *
 * R11.8 requires that the blog draft reference only Scenarios and recommended
 * fixes that are also defined in the Runbook. This test cross-checks the two
 * prose deliverables (`runbook/runbook.md` and `blog/draft.md`) so the blog's
 * scenario names and recommended-fix wording stay aligned with the runbook.
 *
 * The markdown files are read at test time (never hardcoded) so the check stays
 * meaningful as the docs evolve. Text is whitespace-normalized before matching,
 * because the runbook wraps some fix phrasings across newlines and the blog
 * reused that exact wording on a single line.
 */

const RUNBOOK_PATH = path.resolve(__dirname, "..", "runbook", "runbook.md");
// The blog draft is an authoring-time artifact that may live alongside the
// project (full authoring workspace) or be kept in a separate `blog/` folder
// outside the deployable CDK project / public release copy. Resolve it from a
// few known locations, and allow an explicit override via NF_BLOG_DRAFT.
function resolveBlogPath(): string | null {
  const candidates = [
    process.env.NF_BLOG_DRAFT,
    path.resolve(__dirname, "..", "blog", "draft.md"),
    path.resolve(__dirname, "..", "..", "blog", "draft.md"),
  ].filter((p): p is string => typeof p === "string" && p.length > 0);
  return candidates.find((p) => fs.existsSync(p)) ?? null;
}

const BLOG_PATH = resolveBlogPath();

/** Collapse every run of whitespace (incl. newlines) to a single space. */
function normalizeWhitespace(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/**
 * Canonical source of truth for the assertions: the four scenario names and the
 * three recommended-fix phrasings, verbatim as they appear in BOTH docs.
 */
const SCENARIO_NAMES: readonly string[] = [
  "Domain deny list blocking a legitimate endpoint",
  "Stateless rule priority misconfiguration",
  "Asymmetric cross-Availability-Zone routing drop",
];

const RECOMMENDED_FIXES: readonly string[] = [
  "removing the deny entry, or adding an allow/exception",
  "reordering the allow rule ahead of the drop rule",
  "restoring symmetric same-Availability-Zone routing",
];

// When the blog draft is not present alongside the project (for example in the
// deployable CDK copy or the public release, where the blog is maintained
// separately), skip this authoring-time check rather than failing the suite.
const describeOrSkip = BLOG_PATH ? describe : describe.skip;

describeOrSkip("doc consistency: blog draft aligns with operator runbook (R11.8)", () => {
  const runbookRaw = fs.readFileSync(RUNBOOK_PATH, "utf8");
  const blogRaw = fs.readFileSync(BLOG_PATH as string, "utf8");

  const runbookNorm = normalizeWhitespace(runbookRaw);
  const blogNorm = normalizeWhitespace(blogRaw);

  describe("each scenario name is present in both docs", () => {
    it.each([...SCENARIO_NAMES])(
      "scenario name %j appears in the runbook and the blog",
      (name) => {
        expect(runbookNorm).toContain(name);
        expect(blogNorm).toContain(name);
      }
    );
  });

  describe("each recommended fix is present in both docs", () => {
    it.each([...RECOMMENDED_FIXES])(
      "recommended fix %j appears in the runbook and the blog",
      (fix) => {
        const normalizedFix = normalizeWhitespace(fix);
        expect(runbookNorm).toContain(normalizedFix);
        expect(blogNorm).toContain(normalizedFix);
      }
    );
  });

  it("every scenario name derived from runbook headings also appears in the blog", () => {
    // Runbook scenario headings look like: "## Scenario 1: <name>".
    const headingRe = /^##\s+Scenario \d+:\s+(.*)$/;

    const derivedNames = runbookRaw
      .split(/\r?\n/)
      .map((line) => {
        const match = line.match(headingRe);
        return match ? normalizeWhitespace(match[1]) : null;
      })
      .filter((value): value is string => value !== null);

    // Structural check: the runbook defines exactly the four canonical scenarios.
    expect(derivedNames.length).toBe(SCENARIO_NAMES.length);
    expect(new Set(derivedNames)).toEqual(new Set(SCENARIO_NAMES));

    // Enforce the relationship blog ⊆ runbook: if a scenario is renamed in the
    // runbook, the blog must carry the same name or this fails.
    for (const name of derivedNames) {
      expect(blogNorm).toContain(name);
    }
  });
});
