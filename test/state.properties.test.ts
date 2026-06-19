/**
 * Property-based tests for the scenario state machine (`src/scenarioctl/state.ts`).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These tests exercise the pure decision logic the CDK stacks import, so the
 * invariants validated here (round-trip-to-baseline, idempotence, single-active
 * scenario, and the stateless-priority / stream-exception manifestations) are
 * the exact behaviors that drive the synthesized CloudFormation template.
 *
 * Each property runs with fast-check at `{ numRuns: 100 }`.
 */

import fc from "fast-check";
import {
  baseline,
  desired,
  toContext,
  Scenario,
  DesiredState,
} from "../src/scenarioctl/state";

/** All scenario selectors, including the `"none"` baseline. */
const ALL_SCENARIOS: readonly Scenario[] = ["none", "1", "2", "3"];

/** Arbitrary over every scenario selector. */
const anyScenario = fc.constantFrom<Scenario>(...ALL_SCENARIOS);

/**
 * Field-ownership map: the data fields each scenario is allowed to flip away
 * from baseline. `activeScenario` (the selector, set by every scenario) is
 * deliberately excluded — it is handled separately by the relevant properties.
 */
const OWNED: Record<Scenario, ReadonlyArray<keyof DesiredState>> = {
  none: [],
  "1": ["domainDenyActive"],
  "2": ["allowPriority", "dropPriority"],
  "3": ["asymmetricRoute"],
};

/**
 * The comparable data fields for the single-scenario invariant: every
 * `DesiredState` field except the always-changing selector.
 */
const COMPARABLE_FIELDS: ReadonlyArray<keyof DesiredState> = [
  "allowPriority",
  "dropPriority",
  "streamExceptionPolicy",
  "asymmetricRoute",
  "domainDenyActive",
  "logDestination",
];

describe("state.ts property tests", () => {
  // Feature: nf-devops-agent-incident-response, Property 4: Scenario round-trip to baseline
  it("Property 4: desired(n) then desired('none') equals baseline()", () => {
    fc.assert(
      fc.property(anyScenario, (n) => {
        // Apply scenario n, then revert to the baseline selector.
        desired(n);
        const reverted = desired("none");
        expect(reverted).toEqual(baseline());
      }),
      { numRuns: 100 }
    );
  });

  // Feature: nf-devops-agent-incident-response, Property 5: Activate idempotence
  it("Property 5: desired(n) and toContext(desired(n)) are stable across repeated calls", () => {
    fc.assert(
      fc.property(anyScenario, (n) => {
        expect(desired(n)).toEqual(desired(n));
        expect(toContext(desired(n))).toEqual(toContext(desired(n)));
      }),
      { numRuns: 100 }
    );
  });

  // Feature: nf-devops-agent-incident-response, Property 6: Single scenario invariant
  it("Property 6: distinct scenarios differ only in their own owned fields", () => {
    fc.assert(
      fc.property(anyScenario, anyScenario, (n, m) => {
        fc.pre(n !== m);
        const dn = desired(n);
        const dm = desired(m);
        const base = baseline();
        const owned = new Set<keyof DesiredState>([...OWNED[n], ...OWNED[m]]);
        for (const field of COMPARABLE_FIELDS) {
          if (owned.has(field)) {
            continue;
          }
          // A field owned by neither scenario must be untouched in both and
          // equal to baseline — no scenario silently changes another's fields.
          expect(dn[field]).toEqual(base[field]);
          expect(dm[field]).toEqual(base[field]);
          expect(dn[field]).toEqual(dm[field]);
        }
      }),
      { numRuns: 100 }
    );
  });

  // Feature: nf-devops-agent-incident-response, Property 7: Stateless priority invariant
  it("Property 7: desired('2') has allowPriority > dropPriority; baseline() has allowPriority < dropPriority", () => {
    fc.assert(
      fc.property(fc.constant(null), () => {
        const s2 = desired("2");
        expect(s2.allowPriority).toBeGreaterThan(s2.dropPriority);
        const base = baseline();
        expect(base.allowPriority).toBeLessThan(base.dropPriority);
      }),
      { numRuns: 100 }
    );
  });

  // Feature: nf-devops-agent-incident-response, Property 8: Asymmetric-route invariant
  it("Property 8: desired('3') flips asymmetricRoute=true and leaves streamExceptionPolicy at baseline; baseline() is asymmetricRoute=false", () => {
    fc.assert(
      fc.property(fc.constant(null), () => {
        const s3 = desired("3");
        const base = baseline();
        // Scenario 3 is routing-only: it flips asymmetricRoute and makes NO
        // firewall-policy change, so streamExceptionPolicy stays at baseline.
        expect(s3.asymmetricRoute).toBe(true);
        expect(s3.streamExceptionPolicy).toBe(base.streamExceptionPolicy);
        expect(["CONTINUE", "REJECT"]).toContain(base.streamExceptionPolicy);
        expect(base.asymmetricRoute).toBe(false);
      }),
      { numRuns: 100 }
    );
  });
});
