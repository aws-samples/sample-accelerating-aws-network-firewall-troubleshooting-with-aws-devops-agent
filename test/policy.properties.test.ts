/**
 * Property-based tests for the agent IAM policy builder (`src/scenarioctl/policy.ts`).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These tests exercise the pure `buildAgentPolicy` function the `agent-iam`
 * stack imports, so the least-privilege invariants validated here — no action
 * wildcards, read-only/no-mutation, and the conditional S3 read statement — are
 * the exact guarantees that drive the IAM policy document attached to the
 * `Agent_IAM_Role`.
 *
 * Each property runs with fast-check at `{ numRuns: 100 }`.
 */

import fc from "fast-check";
import {
  buildAgentPolicy,
  ALLOWED_ACTIONS,
  PolicyInputs,
} from "../src/scenarioctl/policy";
import { LogDestination } from "../src/scenarioctl/state";

/** Matches an action wildcard of the form `service:*` (e.g. `s3:*`). */
const SERVICE_WILDCARD = /^[a-z0-9-]+:\*$/;

/** Mutating verbs that must never appear in any granted action (R4.4). */
const MUTATING_VERB = /(Create|Update|Delete|Put|Associate|Disassociate|Tag|Untag|Modify)/;

/**
 * Arbitrary ARN-like string. Names are constrained to safe ARN characters so
 * the generated document is realistic, but the builder treats ARNs as opaque
 * resource strings — only the actions are under test.
 */
const arnName = fc
  .string({ minLength: 1, maxLength: 40 })
  .map((s) => s.replace(/[^A-Za-z0-9._-]/g, "-"))
  .map((s) => (s.length > 0 ? s : "x"));

/** ARN for a Network Firewall sub-resource (firewall, policy, rule group). */
const nfArn = arnName.map(
  (name) => `arn:aws:network-firewall:us-east-1:123456789012:firewall/${name}`
);

/** ARN for a CloudWatch Logs log group. */
const logGroupArn = arnName.map(
  (name) =>
    `arn:aws:logs:us-east-1:123456789012:log-group:/nf-devops-agent/${name}`
);

/** ARN for an S3 log bucket (always non-empty). */
const s3BucketArn = arnName.map((name) => `arn:aws:s3:::nf-agent-${name}`);

/**
 * Arbitrary over valid {@link PolicyInputs} for which `buildAgentPolicy` never
 * throws: when `logDestination === "s3"` a non-empty `s3BucketArn` is supplied;
 * when `cloudwatch`, the bucket ARN is either `null` or a value (the builder
 * ignores it in that branch).
 */
const policyInputs: fc.Arbitrary<PolicyInputs> = fc
  .record({
    firewallArn: nfArn,
    policyArn: nfArn,
    ruleGroupArns: fc.array(nfArn, { maxLength: 6 }),
    alertLogGroupArn: logGroupArn,
    flowLogGroupArn: logGroupArn,
    logDestination: fc.constantFrom<LogDestination>("cloudwatch", "s3"),
    // Either branch gets a candidate bucket ARN; the s3 branch requires it.
    bucketCandidate: fc.option(s3BucketArn, { nil: null }),
  })
  .map(({ bucketCandidate, ...rest }) => ({
    ...rest,
    // Guarantee a non-empty bucket ARN whenever the destination is S3 so the
    // builder never throws for valid generated inputs.
    s3BucketArn:
      rest.logDestination === "s3"
        ? bucketCandidate ?? "arn:aws:s3:::nf-agent-default"
        : bucketCandidate,
  }));

/** Flatten every statement's `Action` array into a single list of actions. */
function allActions(inputs: PolicyInputs): string[] {
  return buildAgentPolicy(inputs).Statement.flatMap((s) => [...s.Action]);
}

describe("policy.ts property tests", () => {
  // Feature: nf-devops-agent-incident-response, Property 1: No action wildcards
  it("Property 1: every Action is a literal in ALLOWED_ACTIONS; none is '*' or 'service:*'", () => {
    fc.assert(
      fc.property(policyInputs, (inputs) => {
        for (const action of allActions(inputs)) {
          // Each action is an exact member of the enumerated allowlist.
          expect(ALLOWED_ACTIONS.has(action)).toBe(true);
          // No bare wildcard and no `service:*` action wildcard.
          expect(action).not.toBe("*");
          expect(SERVICE_WILDCARD.test(action)).toBe(false);
        }
      }),
      { numRuns: 100 }
    );
  });

  // Feature: nf-devops-agent-incident-response, Property 2: Read-only / no mutation
  it("Property 2: no Action contains a mutating verb", () => {
    fc.assert(
      fc.property(policyInputs, (inputs) => {
        for (const action of allActions(inputs)) {
          expect(MUTATING_VERB.test(action)).toBe(false);
        }
      }),
      { numRuns: 100 }
    );
  });

  // Feature: nf-devops-agent-incident-response, Property 3: S3 statement is conditional
  it("Property 3: s3:GetObject/s3:ListBucket appear iff logDestination === 's3'; otherwise no s3:* action", () => {
    fc.assert(
      fc.property(policyInputs, (inputs) => {
        const actions = allActions(inputs);
        const s3Actions = actions.filter((a) => a.startsWith("s3:"));
        if (inputs.logDestination === "s3") {
          // The two S3 read actions are present exactly when the destination is S3.
          expect(s3Actions.sort()).toEqual(["s3:GetObject", "s3:ListBucket"]);
        } else {
          // No S3 action of any kind when the destination is CloudWatch.
          expect(s3Actions).toEqual([]);
        }
      }),
      { numRuns: 100 }
    );
  });
});
