/**
 * AlarmsStack — the three per-scenario Amazon CloudWatch alarms plus the Amazon
 * Simple Notification Service (Amazon SNS) topic they notify (Requirements
 * 3.1–3.5).
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Single source of truth for the alarm parameters.
 * ────────────────────────────────────────────────────────────────────────────
 * This stack does NOT hard-code threshold/period/evaluation values. It calls
 * {@link buildAlarmConfigs} from `src/scenarioctl/alarms.ts` — the same pure,
 * property-tested builder that Property 9 / R3.4 validates — and feeds the
 * returned `AlarmConfig` values straight into the `cloudwatch.Alarm`s. The
 * deployed alarm parameters are therefore EXACTLY the ones the property tests
 * exercise; the two can never drift.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Two alarm sources, one pipeline.
 * ────────────────────────────────────────────────────────────────────────────
 * Scenario 1's alarm watches the NATIVE AWS Network Firewall `DroppedPackets`
 * metric (namespace `AWS/NetworkFirewall`), collected across the firewall's
 * per-AZ/engine streams with a metric-math SEARCH expression so one alarm covers
 * the whole firewall. This is the prebuilt-metric path a reader can adopt with
 * no workload or canary. Scenarios 2 and 3 watch the workload health-check
 * daemon's custom per-check metrics in `NfAgent/Workload` (the application/canary
 * path). Demonstrating both shows that either alarm source feeds the same
 * SNS -> AWS Lambda -> AWS DevOps Agent pipeline. Every alarm name is generic
 * (`Alarm-1/2/3`) and carries no root-cause hint, so the agent must
 * investigate the firewall config and logs to find the cause.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Requires the firewall stack.
 * ────────────────────────────────────────────────────────────────────────────
 * This stack consumes the firewall stack's `firewallName` (passed by
 * `bin/app.ts`) to scope the custom-metric `Firewall` dimension. The only
 * cross-stack dependency direction is alarms -> firewall. Its test constructs a
 * firewall stack in the same app and passes the name in.
 */
import * as cdk from "aws-cdk-lib";
import { Duration, Tags } from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatch_actions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as sns from "aws-cdk-lib/aws-sns";
import * as sns_subscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import { Construct } from "constructs";

import { PROJECT_TAG_KEY, PROJECT_TAG_VALUE } from "./network-stack";
import { WORKLOAD_METRIC_NAMESPACE, SCENARIO_METRICS, SCENARIO_ALARM_NAMES } from "./workload-stack";
import {
  AlarmConfig,
  buildAlarmConfigs,
  ComparisonOperator as AlarmComparisonOperator,
} from "../src/scenarioctl/alarms";

/**
 * One per-scenario custom-metric alarm definition. The `alarmName` is what the
 * webhook payload carries to AWS DevOps Agent, so it must name the scenario.
 */
interface ScenarioAlarmSpec {
  /** Construct id within the stack. */
  readonly id: string;
  /** The CloudWatch alarm name (surfaced to the agent via the webhook). */
  readonly alarmName: string;
  /** The custom metric (in `NfAgent/Workload`) the health-check daemon publishes. */
  readonly metricName: string;
  /** Human-readable description of which scenario this alarm detects. */
  readonly description: string;
}

/**
 * Props for {@link AlarmsStack}. Takes the firewall name directly (from
 * `firewall.firewallName`) rather than the whole stack, for testability.
 */
export interface AlarmsStackProps extends cdk.StackProps {
  /** The deployed firewall's name (from `firewall.firewallName`); scopes the custom-metric `Firewall` dimension. */
  readonly firewallName: string;
  /**
   * Optional email address to subscribe to the SNS topic. When omitted (or an
   * empty string) no email subscription is created and the value falls back to
   * the `notificationEmail` CDK context value. An empty string means "no
   * subscription".
   */
  readonly notificationEmail?: string;
}

/**
 * Map an `alarms.ts` {@link AlarmComparisonOperator} string onto the CDK
 * `cloudwatch.ComparisonOperator` enum. The string values are identical to the
 * enum values, but this explicit table keeps the mapping type-safe and total.
 */
const COMPARISON_OPERATOR_MAP: Readonly<
  Record<AlarmComparisonOperator, cloudwatch.ComparisonOperator>
> = {
  GreaterThanOrEqualToThreshold: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
  GreaterThanThreshold: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
  LessThanThreshold: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
  LessThanOrEqualToThreshold: cloudwatch.ComparisonOperator.LESS_THAN_OR_EQUAL_TO_THRESHOLD,
};

/**
 * The alarms + SNS stack. Exposes the topic, the three per-scenario alarms, and
 * the topic ARN.
 *
 * Each per-scenario alarm watches one custom `NfAgent/Workload` metric the
 * workload's health-check daemon publishes (one metric per scenario). Because
 * native NF metrics cannot be dimensioned per scenario, the per-check custom
 * metrics are what let a distinct alarm — and therefore a distinct alarm NAME in
 * the webhook payload — tell AWS DevOps Agent exactly which scenario broke. All
 * three alarms publish to the same SNS topic, which the webhook bridge Lambda
 * subscribes to.
 */
export class AlarmsStack extends cdk.Stack {
  /** The SNS topic alarms publish to in ALARM state (R3.3). */
  public readonly topic: sns.Topic;
  /** The three per-scenario alarms, keyed by construct id (one per custom metric). */
  public readonly scenarioAlarms: cloudwatch.Alarm[];
  /** The SNS topic ARN (convenience for outputs/downstream references). */
  public readonly topicArn: string;

  constructor(scope: Construct, id: string, props: AlarmsStackProps) {
    super(scope, id, props);

    // ── Alarm parameters: the property-tested configs, not hand-rolled values ──
    // buildAlarmConfigs() returns { dropped, rejected }; both share threshold/
    // period/evaluation parameters and differ only in metricName (R3.4). The
    // per-scenario alarms reuse the shared period/evaluation/datapoints.
    const { dropped } = buildAlarmConfigs();

    // ── SNS topic (R3.3) ──
    this.topic = new sns.Topic(this, "AlarmTopic", {
      displayName: "nf-devops-agent firewall alarms",
    });
    const snsAction = new cloudwatch_actions.SnsAction(this.topic);

    // Optional email subscription: prop first, then `notificationEmail` context;
    // an empty string (the cdk.json default) means "no subscription".
    const notificationEmail =
      props.notificationEmail ?? (this.node.tryGetContext("notificationEmail") as string | undefined);
    if (typeof notificationEmail === "string" && notificationEmail.trim() !== "") {
      this.topic.addSubscription(new sns_subscriptions.EmailSubscription(notificationEmail));
    }

    // ── Per-scenario alarms ──
    // Scenario 1 uses a NATIVE AWS Network Firewall metric (DroppedPackets in
    // AWS/NetworkFirewall), summed across the firewall's AZ/engine streams with
    // a metric-math SEARCH expression so a single alarm covers the whole
    // firewall. This shows the prebuilt-metric path a reader can adopt directly.
    // Scenarios 2 and 3 use the workload's custom per-check metrics (the
    // application/canary path), so the post demonstrates BOTH alarm sources
    // feeding the same pipeline. Every alarm name is generic (Alarm-1/2/3)
    // and carries no root-cause hint, so AWS DevOps Agent must investigate.
    const nativeAlarm1 = this.buildNativeFirewallAlarm(
      {
        id: "Alarm1",
        alarmName: SCENARIO_ALARM_NAMES.scenario1,
        description:
          "AWS Network Firewall is dropping packets above the expected baseline (native DroppedPackets metric).",
      },
      props.firewallName,
      dropped,
    );
    nativeAlarm1.addAlarmAction(snsAction);

    const customSpecs: ScenarioAlarmSpec[] = [
      {
        id: "Alarm2",
        alarmName: SCENARIO_ALARM_NAMES.scenario2,
        metricName: SCENARIO_METRICS.scenario2,
        description:
          "A workload connectivity health check is failing (egress to a monitored endpoint is being dropped).",
      },
      {
        id: "Alarm3",
        alarmName: SCENARIO_ALARM_NAMES.scenario3,
        metricName: SCENARIO_METRICS.scenario3,
        description:
          "A workload connectivity health check is failing (egress to a monitored endpoint is being dropped).",
      },
    ];

    const customAlarms = customSpecs.map((spec) => {
      const alarm = this.buildScenarioAlarm(spec, props.firewallName, dropped);
      alarm.addAlarmAction(snsAction);
      return alarm;
    });

    this.scenarioAlarms = [nativeAlarm1, ...customAlarms];

    // ── Exported props ──
    this.topicArn = this.topic.topicArn;

    // Tag every resource in the stack for the teardown sweep (Requirement 10).
    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);
  }

  /**
   * Build the Scenario 1 alarm on the NATIVE AWS Network Firewall metric.
   *
   * `DroppedPackets` (namespace `AWS/NetworkFirewall`) is emitted per
   * `FirewallName` x `AvailabilityZone` x `Engine`. A CloudWatch alarm cannot be
   * backed by a SEARCH expression (SEARCH returns many series), so this sums the
   * named per-AZ stateful streams with a small metric-math expression into one
   * series the alarm can watch. The stateful engine is where domain/rule drops
   * occur, so a domain-deny drop raises this firewall-wide stateful drop count.
   *
   * Threshold: a healthy firewall shows only sporadic background drops (0-1
   * packets/min observed at baseline), while an active domain-deny drop adds the
   * workload's repeated probe handshakes (tens of packets/min). The threshold
   * sits between the two so normal noise never fires it. Override via the
   * `nativeDropThreshold` context value for a noisier environment.
   */
  private buildNativeFirewallAlarm(
    spec: { id: string; alarmName: string; description: string },
    firewallName: string,
    config: AlarmConfig,
  ): cloudwatch.Alarm {
    const region = cdk.Stack.of(this).region;
    const periodSeconds = config.periodSeconds;
    const period = Duration.seconds(periodSeconds);
    // The firewall spans two AZs (required for Scenario 3). Sum the STATEFUL
    // DroppedPackets stream from each AZ: that engine is where domain/rule drops
    // land. Named metrics (not SEARCH) so the expression is alarm-compatible.
    const droppedA = new cloudwatch.Metric({
      namespace: "AWS/NetworkFirewall",
      metricName: "DroppedPackets",
      dimensionsMap: { FirewallName: firewallName, AvailabilityZone: `${region}a`, Engine: "Stateful" },
      statistic: "Sum",
      period,
    });
    const droppedB = new cloudwatch.Metric({
      namespace: "AWS/NetworkFirewall",
      metricName: "DroppedPackets",
      dimensionsMap: { FirewallName: firewallName, AvailabilityZone: `${region}b`, Engine: "Stateful" },
      statistic: "Sum",
      period,
    });
    const droppedAcrossFirewall = new cloudwatch.MathExpression({
      expression: "a + b",
      usingMetrics: { a: droppedA, b: droppedB },
      label: "FirewallStatefulDroppedPackets",
      period,
    });

    // Threshold above baseline noise (default 10; override with context).
    const ctxThreshold = Number(this.node.tryGetContext("nativeDropThreshold"));
    const nativeThreshold = Number.isFinite(ctxThreshold) && ctxThreshold > 0 ? ctxThreshold : 10;

    return new cloudwatch.Alarm(this, spec.id, {
      alarmName: spec.alarmName,
      metric: droppedAcrossFirewall,
      threshold: nativeThreshold,
      evaluationPeriods: config.evaluationPeriods,
      datapointsToAlarm: config.datapointsToAlarm,
      comparisonOperator: COMPARISON_OPERATOR_MAP[config.comparisonOperator],
      alarmDescription: spec.description,
      // No data = no drops reported yet; not a breach.
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
  }

  /**
   * Build one per-scenario alarm on a custom `NfAgent/Workload` metric the
   * health-check daemon publishes (value `1` on a firewall-drop timeout). The
   * alarm fires when the failure count is `>= 1` over the period; its
   * `alarmName` names the scenario so the webhook payload identifies it. Reuses
   * the property-tested period/evaluation/datapoints from the shared config.
   */
  private buildScenarioAlarm(
    spec: ScenarioAlarmSpec,
    firewallName: string,
    config: AlarmConfig,
  ): cloudwatch.Alarm {
    const metric = new cloudwatch.Metric({
      namespace: WORKLOAD_METRIC_NAMESPACE,
      metricName: spec.metricName,
      dimensionsMap: { Firewall: firewallName },
      statistic: "Sum",
      period: Duration.seconds(config.periodSeconds),
    });

    return new cloudwatch.Alarm(this, spec.id, {
      alarmName: spec.alarmName,
      metric,
      threshold: config.threshold,
      evaluationPeriods: config.evaluationPeriods,
      datapointsToAlarm: config.datapointsToAlarm,
      comparisonOperator: COMPARISON_OPERATOR_MAP[config.comparisonOperator],
      alarmDescription: spec.description,
      // No data = the health check has not reported yet; not a breach.
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
  }
}
