/**
 * Amazon CloudWatch alarm-config builder (pure, side-effect-free).
 *
 * Ported from the now-deleted Python `scenarioctl/alarms.py` with its semantics
 * preserved (see PORTING-NOTES.md section 3). This module builds the two
 * AWS Network Firewall alarm configs (DroppedPackets and RejectedPackets) and
 * validates the alarm invariants on construction, throwing on any violating
 * input.
 *
 * Purity contract: every export here is pure — no filesystem, AWS, clock, or
 * other side effect. The CDK alarms stack imports these configs so the deployed
 * alarm parameters are exactly the property-tested ones (Property 9 / R3.4).
 */

/** CloudWatch comparison operators permitted for the firewall alarms. */
export type ComparisonOperator =
  | "GreaterThanOrEqualToThreshold"
  | "GreaterThanThreshold"
  | "LessThanThreshold"
  | "LessThanOrEqualToThreshold";

/** CloudWatch statistics permitted for the firewall alarms. */
export type Statistic =
  | "SampleCount"
  | "Average"
  | "Sum"
  | "Minimum"
  | "Maximum";

/** AWS Network Firewall metric namespace. */
export const NAMESPACE = "AWS/NetworkFirewall";

/** Metric name for the DroppedPackets alarm (R3.1). */
export const DROPPED_PACKETS_METRIC = "DroppedPackets";

/** Metric name for the RejectedPackets alarm (R3.2). */
export const REJECTED_PACKETS_METRIC = "RejectedPackets";

/** Default alarm threshold (a positive value greater than zero, R3.4). */
export const DEFAULT_THRESHOLD = 1;

/** Default evaluation period length, in seconds. */
export const DEFAULT_PERIOD_SECONDS = 60;

/** Default number of evaluation periods. */
export const DEFAULT_EVALUATION_PERIODS = 1;

/** Default datapoints-to-alarm count. */
export const DEFAULT_DATAPOINTS_TO_ALARM = 1;

/** Default comparison operator: fire when the metric meets or exceeds the threshold (R3.5). */
export const DEFAULT_COMPARISON_OPERATOR: ComparisonOperator =
  "GreaterThanOrEqualToThreshold";

/** Default statistic: sum drops across the per-AZ/engine metric streams. */
export const DEFAULT_STATISTIC: Statistic = "Sum";

/** The exact set of comparison operators an {@link AlarmConfig} may use. */
export const ALLOWED_COMPARISON_OPERATORS: ReadonlySet<string> = new Set<string>([
  "GreaterThanOrEqualToThreshold",
  "GreaterThanThreshold",
  "LessThanThreshold",
  "LessThanOrEqualToThreshold",
]);

/** The exact set of statistics an {@link AlarmConfig} may use. */
export const ALLOWED_STATISTICS: ReadonlySet<string> = new Set<string>([
  "SampleCount",
  "Average",
  "Sum",
  "Minimum",
  "Maximum",
]);

/**
 * A validated CloudWatch alarm configuration. Every field is `readonly`; a
 * config is only ever produced through {@link makeAlarmConfig} (directly or via
 * {@link buildAlarmConfigs}), so every `AlarmConfig` value satisfies the
 * invariants asserted by Property 9 / R3.4.
 */
export interface AlarmConfig {
  /** The CloudWatch metric this alarm watches (e.g. `DroppedPackets`). */
  readonly metricName: string;
  /** The metric namespace (`AWS/NetworkFirewall`). */
  readonly namespace: string;
  /** Positive threshold the metric is compared against (`> 0`). */
  readonly threshold: number;
  /** Evaluation period length in seconds (`> 0`). */
  readonly periodSeconds: number;
  /** Number of evaluation periods (`>= 1`). */
  readonly evaluationPeriods: number;
  /** Datapoints required to alarm (`>= 1` and `<= evaluationPeriods`). */
  readonly datapointsToAlarm: number;
  /** Comparison operator, a member of {@link ALLOWED_COMPARISON_OPERATORS}. */
  readonly comparisonOperator: ComparisonOperator;
  /** Statistic, a member of {@link ALLOWED_STATISTICS}. */
  readonly statistic: Statistic;
}

/**
 * Input to {@link makeAlarmConfig}. `metricName` is required; every other field
 * is optional and falls back to its design default. Numeric and enum fields are
 * also runtime-validated (not just compile-time typed) so values arriving from
 * untyped sources — CDK context JSON or property-test arbitraries — are rejected
 * when they violate the invariants.
 */
export interface AlarmConfigFields {
  readonly metricName: string;
  readonly namespace?: string;
  readonly threshold?: number;
  readonly periodSeconds?: number;
  readonly evaluationPeriods?: number;
  readonly datapointsToAlarm?: number;
  readonly comparisonOperator?: ComparisonOperator;
  readonly statistic?: Statistic;
}

/**
 * Shared parameters for {@link buildAlarmConfigs}. Identical to
 * {@link AlarmConfigFields} minus `metricName` (the builder fixes the metric
 * names itself). With no parameters, the design defaults are used.
 */
export type BuildAlarmConfigsParams = Omit<AlarmConfigFields, "metricName">;

/** The pair of alarm configs produced by {@link buildAlarmConfigs}. */
export interface AlarmConfigPair {
  /** Alarm on the DroppedPackets metric (R3.1). */
  readonly dropped: AlarmConfig;
  /** Alarm on the RejectedPackets metric (R3.2). */
  readonly rejected: AlarmConfig;
}

/**
 * Assert a field is a real, finite number. Rejects booleans explicitly (in
 * Python `bool` is an `int` subclass, so the ported semantics reject bool here)
 * and rejects `NaN` / non-finite values. Typed `unknown` so callers passing
 * untyped values still hit the runtime guard.
 *
 * @throws if `value` is a boolean, not a number, `NaN`, or non-finite.
 */
function assertFiniteNumber(fieldName: string, value: unknown): asserts value is number {
  if (typeof value === "boolean") {
    throw new Error(`Alarm config "${fieldName}" must be a number, not a boolean.`);
  }
  if (typeof value !== "number" || Number.isNaN(value) || !Number.isFinite(value)) {
    throw new Error(
      `Alarm config "${fieldName}" must be a finite number; got ${String(value)}.`,
    );
  }
}

/**
 * Validate an assembled {@link AlarmConfig} against the Property 9 / R3.4
 * invariants. Throws on the first violation.
 */
function validateAlarmConfig(config: AlarmConfig): void {
  assertFiniteNumber("threshold", config.threshold);
  assertFiniteNumber("periodSeconds", config.periodSeconds);
  assertFiniteNumber("evaluationPeriods", config.evaluationPeriods);
  assertFiniteNumber("datapointsToAlarm", config.datapointsToAlarm);

  if (!(config.threshold > 0)) {
    throw new Error(`Alarm "threshold" must be > 0; got ${config.threshold}.`);
  }
  if (!(config.periodSeconds > 0)) {
    throw new Error(`Alarm "periodSeconds" must be > 0; got ${config.periodSeconds}.`);
  }
  if (!(config.evaluationPeriods >= 1)) {
    throw new Error(
      `Alarm "evaluationPeriods" must be >= 1; got ${config.evaluationPeriods}.`,
    );
  }
  if (!(config.datapointsToAlarm >= 1)) {
    throw new Error(
      `Alarm "datapointsToAlarm" must be >= 1; got ${config.datapointsToAlarm}.`,
    );
  }
  if (!(config.datapointsToAlarm <= config.evaluationPeriods)) {
    throw new Error(
      `Alarm "datapointsToAlarm" (${config.datapointsToAlarm}) must be <= ` +
        `"evaluationPeriods" (${config.evaluationPeriods}).`,
    );
  }
  if (!ALLOWED_COMPARISON_OPERATORS.has(config.comparisonOperator)) {
    throw new Error(`Alarm "comparisonOperator" not allowed: ${String(config.comparisonOperator)}.`);
  }
  if (!ALLOWED_STATISTICS.has(config.statistic)) {
    throw new Error(`Alarm "statistic" not allowed: ${String(config.statistic)}.`);
  }
}

/**
 * Build a single {@link AlarmConfig}, filling any omitted field with its design
 * default and validating all invariants on construction (Property 9 / R3.4).
 *
 * @throws if any field violates an invariant — non-finite/NaN/boolean numbers,
 *   `threshold <= 0`, `periodSeconds <= 0`, `evaluationPeriods < 1`,
 *   `datapointsToAlarm < 1`, `datapointsToAlarm > evaluationPeriods`, or an
 *   out-of-set comparison operator / statistic.
 */
export function makeAlarmConfig(fields: AlarmConfigFields): AlarmConfig {
  const config: AlarmConfig = {
    metricName: fields.metricName,
    namespace: fields.namespace ?? NAMESPACE,
    threshold: fields.threshold ?? DEFAULT_THRESHOLD,
    periodSeconds: fields.periodSeconds ?? DEFAULT_PERIOD_SECONDS,
    evaluationPeriods: fields.evaluationPeriods ?? DEFAULT_EVALUATION_PERIODS,
    datapointsToAlarm: fields.datapointsToAlarm ?? DEFAULT_DATAPOINTS_TO_ALARM,
    comparisonOperator: fields.comparisonOperator ?? DEFAULT_COMPARISON_OPERATOR,
    statistic: fields.statistic ?? DEFAULT_STATISTIC,
  };
  validateAlarmConfig(config);
  return config;
}

/**
 * Build the DroppedPackets and RejectedPackets alarm configs as a
 * `{ dropped, rejected }` pair. Both configs share the same threshold/period/
 * evaluation parameters and differ only in `metricName`. With no arguments the
 * baseline pair (all design defaults) is produced; any supplied parameter that
 * violates an invariant causes this function to throw (via
 * {@link makeAlarmConfig}).
 *
 * @throws if any shared parameter violates an alarm invariant.
 */
export function buildAlarmConfigs(params: BuildAlarmConfigsParams = {}): AlarmConfigPair {
  return {
    dropped: makeAlarmConfig({ ...params, metricName: DROPPED_PACKETS_METRIC }),
    rejected: makeAlarmConfig({ ...params, metricName: REJECTED_PACKETS_METRIC }),
  };
}
