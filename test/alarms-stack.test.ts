/**
 * CDK assertion tests for `lib/alarms-stack.ts`.
 *
 * Feature: nf-devops-agent-incident-response
 *
 * The `AlarmsStack` only needs the deployed firewall's name (it scopes each
 * per-scenario metric's `Firewall` dimension with it), so these tests
 * instantiate it directly in a fresh `cdk.App` with a pinned environment and
 * synthesize `Template.fromStack(stack)`.
 *
 * The stack creates THREE alarms, all wired to one SNS topic. Scenario 1's
 * alarm watches the NATIVE `AWS/NetworkFirewall` `DroppedPackets` metric via a
 * metric-math expression that sums the per-AZ stateful streams (CloudWatch
 * cannot alarm on a SEARCH expression, so named metrics are summed instead).
 * Scenarios 2 and 3 watch custom `NfAgent/Workload` metrics (a plain
 * `cloudwatch.Metric`). Each alarm has an explicit `AlarmName`.
 *
 * The expected alarm parameters are NOT hard-coded here — they are derived from
 * `buildAlarmConfigs()` in `src/scenarioctl/alarms.ts`, the same property-tested
 * builder the stack itself consumes. The per-scenario AlarmName/MetricName pairs
 * are imported from `lib/workload-stack.ts` (the single source of truth for the
 * custom namespace + metric names). The assertions therefore stay in sync with
 * the deployed config and would fail if either drifted.
 *
 * Validates: Requirement 3.3 (each alarm publishes to the SNS topic on ALARM)
 * and the three per-scenario custom-metric alarms that name the scenario for the
 * webhook payload.
 */

import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { AlarmsStack } from "../lib/alarms-stack";
import { buildAlarmConfigs } from "../src/scenarioctl/alarms";
import { WORKLOAD_METRIC_NAMESPACE, SCENARIO_METRICS } from "../lib/workload-stack";

/** A pinned environment so synthesis is deterministic. */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

/** The concrete firewall name fed into the per-scenario metric dimensions. */
const FIREWALL_NAME = "test-firewall";

/** Build the AlarmsStack and return its synthesized template. */
function templateForAlarms(notificationEmail?: string): Template {
  const app = new cdk.App();
  const stack = new AlarmsStack(app, "TestAlarms", {
    env: ENV,
    firewallName: FIREWALL_NAME,
    ...(notificationEmail === undefined ? {} : { notificationEmail }),
  });
  return Template.fromStack(stack);
}

/** A single synthesized alarm's `Properties` (PascalCase, as in the CFN template). */
interface SynthAlarmProps {
  Threshold: number;
  EvaluationPeriods: number;
  DatapointsToAlarm: number;
  ComparisonOperator: string;
  AlarmName?: string;
  AlarmActions?: unknown[];
  MetricName?: string;
  Namespace?: string;
  Statistic?: string;
  Period?: number;
  Dimensions?: Array<{ Name: string; Value: unknown }>;
  Metrics?: unknown[];
}

/** The two custom per-scenario (AlarmName, MetricName) pairs (Scenarios 2 and 3). */
const CUSTOM_SCENARIO_ALARMS: ReadonlyArray<{ alarmName: string; metricName: string }> = [
  { alarmName: "Alarm-2", metricName: SCENARIO_METRICS.scenario2 },
  { alarmName: "Alarm-3", metricName: SCENARIO_METRICS.scenario3 },
];

describe("AlarmsStack CDK assertions", () => {
  // The expected parameters come from the SAME builder the stack uses, so the
  // test can never drift from the deployed config (R3.4 single source of truth).
  const { dropped } = buildAlarmConfigs();
  let template: Template;

  beforeAll(() => {
    template = templateForAlarms();
  });

  it("synthesizes exactly three CloudWatch alarms (one per scenario)", () => {
    template.resourceCountIs("AWS::CloudWatch::Alarm", 3);
  });

  it("synthesizes exactly one SNS topic for alarm notifications (R3.3)", () => {
    template.resourceCountIs("AWS::SNS::Topic", 1);
  });

  it("Scenario 1 alarm watches the NATIVE AWS Network Firewall DroppedPackets metric (metric math, not SEARCH)", () => {
    // The native alarm is backed by a metric-math expression summing the
    // per-AZ stateful DroppedPackets streams (a `Metrics` array). It must NOT
    // use a SEARCH expression (CloudWatch rejects SEARCH-backed alarms).
    const alarms = template.findResources("AWS::CloudWatch::Alarm");
    const native = Object.values(alarms).find(
      (r) => (r.Properties as SynthAlarmProps).AlarmName === "Alarm-1",
    );
    expect(native).toBeDefined();
    const props = native!.Properties as SynthAlarmProps;
    expect(Array.isArray(props.Metrics)).toBe(true);
    const metricsJson = JSON.stringify(props.Metrics);
    expect(metricsJson).toContain("AWS/NetworkFirewall");
    expect(metricsJson).toContain("DroppedPackets");
    expect(metricsJson).not.toContain("SEARCH(");
  });

  it("creates the two custom per-scenario alarms (Scenarios 2 and 3) on the NfAgent/Workload metrics", () => {
    for (const { alarmName, metricName } of CUSTOM_SCENARIO_ALARMS) {
      template.hasResourceProperties(
        "AWS::CloudWatch::Alarm",
        Match.objectLike({
          AlarmName: alarmName,
          MetricName: metricName,
          Namespace: WORKLOAD_METRIC_NAMESPACE,
          Statistic: "Sum",
          Dimensions: Match.arrayWith([Match.objectLike({ Name: "Firewall" })]),
        }),
      );
    }
  });

  it("configures the custom per-scenario alarms with the property-tested params (R3.4)", () => {
    const alarms = template.findResources("AWS::CloudWatch::Alarm");
    const customProps = Object.values(alarms)
      .map((r) => r.Properties as SynthAlarmProps)
      .filter((p) => p.MetricName !== undefined && p.Namespace === WORKLOAD_METRIC_NAMESPACE);
    expect(customProps).toHaveLength(2);

    const expectedNames = new Set(CUSTOM_SCENARIO_ALARMS.map((s) => s.alarmName));
    for (const props of customProps) {
      expect(expectedNames.has(props.AlarmName as string)).toBe(true);
      expect(props.Namespace).toBe(WORKLOAD_METRIC_NAMESPACE);
      expect(props.Statistic).toBe("Sum");
      expect(props.Period).toBe(dropped.periodSeconds);
      expect(props.Threshold).toBe(dropped.threshold);
      expect(props.EvaluationPeriods).toBe(dropped.evaluationPeriods);
      expect(props.DatapointsToAlarm).toBe(dropped.datapointsToAlarm);
      expect(props.ComparisonOperator).toBe("GreaterThanOrEqualToThreshold");
      expect(props.ComparisonOperator).toBe(dropped.comparisonOperator);
      expect(props.DatapointsToAlarm).toBeLessThanOrEqual(props.EvaluationPeriods);
    }
  });

  it("wires every alarm's AlarmActions to the SNS topic on ALARM (R3.3)", () => {
    template.hasResourceProperties(
      "AWS::CloudWatch::Alarm",
      Match.objectLike({
        AlarmActions: Match.anyValue(),
      }),
    );

    // All three alarms must have a non-empty AlarmActions array (each is wired).
    const alarms = template.findResources("AWS::CloudWatch::Alarm");
    const alarmProps = Object.values(alarms).map((r) => r.Properties as SynthAlarmProps);
    expect(alarmProps).toHaveLength(3);
    for (const props of alarmProps) {
      expect(Array.isArray(props.AlarmActions)).toBe(true);
      expect(props.AlarmActions!.length).toBeGreaterThanOrEqual(1);
    }
  });

  it("creates no SNS email subscription by default (no notificationEmail) (R3.3)", () => {
    // The default stack (no email) wires alarms straight to the topic with no
    // email subscription resource.
    template.resourceCountIs("AWS::SNS::Subscription", 0);
  });

  it("creates an email SNS subscription when notificationEmail is supplied (R3.3)", () => {
    const withEmail = templateForAlarms("ops@example.com");
    withEmail.resourceCountIs("AWS::SNS::Subscription", 1);
    withEmail.hasResourceProperties(
      "AWS::SNS::Subscription",
      Match.objectLike({
        Protocol: "email",
        Endpoint: "ops@example.com",
      }),
    );
  });
});
