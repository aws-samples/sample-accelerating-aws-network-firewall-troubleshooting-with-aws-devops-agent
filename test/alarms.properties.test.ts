/**
 * Property-based tests for the alarm-config builder (`src/scenarioctl/alarms.ts`).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These tests exercise the pure, side-effect-free alarm-config builder that the
 * CDK alarms stack imports, so the invariants validated here (Property 9 / R3.4)
 * are exactly the alarm parameters that get synthesized into CloudFormation.
 *
 * Property 9 runs with fast-check at `{ numRuns: 100 }`.
 */

import fc from "fast-check";
import {
  buildAlarmConfigs,
  makeAlarmConfig,
  AlarmConfig,
  BuildAlarmConfigsParams,
  DROPPED_PACKETS_METRIC,
} from "../src/scenarioctl/alarms";

/** Assert a single produced config satisfies all four Property 9 invariants. */
function expectInvariants(config: AlarmConfig): void {
  expect(config.threshold).toBeGreaterThan(0);
  expect(config.periodSeconds).toBeGreaterThan(0);
  expect(config.evaluationPeriods).toBeGreaterThanOrEqual(1);
  expect(config.datapointsToAlarm).toBeLessThanOrEqual(config.evaluationPeriods);
}

/**
 * Arbitrary over VALID builder params. Numeric fields use finite-number
 * arbitraries so the positive case never accidentally generates NaN/Infinity:
 *   - threshold      > 0
 *   - periodSeconds  > 0
 *   - evaluationPeriods >= 1
 *   - datapointsToAlarm in [1, evaluationPeriods]
 */
const validParams: fc.Arbitrary<BuildAlarmConfigsParams> = fc
  .record({
    threshold: fc.double({ min: Number.EPSILON, max: 1e9, noNaN: true, noDefaultInfinity: true }),
    periodSeconds: fc.integer({ min: 1, max: 86_400 }),
    evaluationPeriods: fc.integer({ min: 1, max: 100 }),
  })
  .chain(({ threshold, periodSeconds, evaluationPeriods }) =>
    fc
      .integer({ min: 1, max: evaluationPeriods })
      .map((datapointsToAlarm) => ({
        threshold,
        periodSeconds,
        evaluationPeriods,
        datapointsToAlarm,
      }))
  );

describe("alarms.ts property tests", () => {
  // Feature: nf-devops-agent-incident-response, Property 9: Alarm config invariants
  // (positive) — for all VALID generated params, both produced configs satisfy
  // threshold > 0, periodSeconds > 0, evaluationPeriods >= 1, and
  // datapointsToAlarm <= evaluationPeriods. Validates Requirements 3.4
  it("Property 9: buildAlarmConfigs returns dropped/rejected configs satisfying all invariants for valid params", () => {
    fc.assert(
      fc.property(validParams, (params) => {
        const { dropped, rejected } = buildAlarmConfigs(params);
        expectInvariants(dropped);
        expectInvariants(rejected);
        // The pair shares the same evaluation parameters and differs only in metric name.
        expect(dropped.datapointsToAlarm).toBeLessThanOrEqual(dropped.evaluationPeriods);
        expect(rejected.datapointsToAlarm).toBeLessThanOrEqual(rejected.evaluationPeriods);
        expect(dropped.metricName).toBe(DROPPED_PACKETS_METRIC);
        expect(dropped.metricName).not.toBe(rejected.metricName);
      }),
      { numRuns: 100 }
    );
  });

  // Feature: nf-devops-agent-incident-response, Property 9: Alarm config invariants
  // (negative) — the builder REJECTS (throws on) inputs violating any invariant.
  // Validates Requirements 3.4
  it("Property 9: buildAlarmConfigs throws on params that violate any invariant", () => {
    // Generators for individual invariant violations.
    const badThreshold = fc.double({ min: -1e9, max: 0, noNaN: true, noDefaultInfinity: true }); // <= 0
    const badPeriod = fc.integer({ min: -1000, max: 0 }); // <= 0
    const badEvalPeriods = fc.integer({ min: -1000, max: 0 }); // < 1

    const invalidParams: fc.Arbitrary<BuildAlarmConfigsParams> = fc.oneof(
      // threshold <= 0
      badThreshold.map((threshold) => ({ threshold })),
      // periodSeconds <= 0
      badPeriod.map((periodSeconds) => ({ periodSeconds })),
      // evaluationPeriods < 1
      badEvalPeriods.map((evaluationPeriods) => ({ evaluationPeriods })),
      // datapointsToAlarm > evaluationPeriods
      fc
        .integer({ min: 1, max: 50 })
        .chain((evaluationPeriods) =>
          fc
            .integer({ min: evaluationPeriods + 1, max: evaluationPeriods + 100 })
            .map((datapointsToAlarm) => ({ evaluationPeriods, datapointsToAlarm }))
        ),
      // NaN threshold
      fc.constant<BuildAlarmConfigsParams>({ threshold: Number.NaN }),
      // Infinite period
      fc.constant<BuildAlarmConfigsParams>({ periodSeconds: Number.POSITIVE_INFINITY }),
      // boolean-like value smuggled into a numeric field
      fc.boolean().map((b) => ({ evaluationPeriods: b as unknown as number }))
    );

    fc.assert(
      fc.property(invalidParams, (params) => {
        expect(() => buildAlarmConfigs(params)).toThrow();
      }),
      { numRuns: 100 }
    );
  });

  // Feature: nf-devops-agent-incident-response, Property 9: Alarm config invariants
  // (negative, single config) — makeAlarmConfig throws on invariant-violating
  // fields just as the builder does. Validates Requirements 3.4
  it("Property 9: makeAlarmConfig throws on a single config that violates an invariant", () => {
    const invalidFields = fc.oneof(
      fc.double({ min: -1e9, max: 0, noNaN: true, noDefaultInfinity: true }).map((threshold) => ({ threshold })),
      fc.integer({ min: -1000, max: 0 }).map((periodSeconds) => ({ periodSeconds })),
      fc.integer({ min: -1000, max: 0 }).map((evaluationPeriods) => ({ evaluationPeriods })),
      fc
        .integer({ min: 1, max: 50 })
        .chain((evaluationPeriods) =>
          fc
            .integer({ min: evaluationPeriods + 1, max: evaluationPeriods + 100 })
            .map((datapointsToAlarm) => ({ evaluationPeriods, datapointsToAlarm }))
        )
    );

    fc.assert(
      fc.property(invalidFields, (fields) => {
        expect(() => makeAlarmConfig({ metricName: DROPPED_PACKETS_METRIC, ...fields })).toThrow();
      }),
      { numRuns: 100 }
    );
  });
});
