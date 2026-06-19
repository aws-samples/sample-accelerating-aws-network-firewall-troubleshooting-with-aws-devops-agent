/**
 * WorkloadStack — the Amazon EC2 test workload plus the health-check daemon that
 * publishes one custom Amazon CloudWatch metric per scenario (Requirement 1,
 * Requirement 9, and the per-scenario alarm design).
 *
 * Provisions a minimal `t3.micro` instance in **protected subnet A** (the
 * isolated tier whose `0.0.0.0/0` route the firewall stack points at the
 * AWS Network Firewall endpoint). Every egress request from this instance is routed
 * through a Network Firewall endpoint, so the three break-fix scenarios manifest
 * as drops on its traffic.
 *
 * Health-check daemon (publishes per-check custom metrics):
 *   A systemd service runs a loop that probes one target per scenario and
 *   publishes a custom CloudWatch metric per check to the `NfAgent/Workload`
 *   namespace, dimensioned by `Firewall = <firewallName>`. A failed probe
 *   publishes `1` (Count); a healthy probe publishes `0`. The alarms stack puts
 *   one alarm on each of these four metrics, so the alarm that fires names the
 *   scenario:
 *     - Scenario 1 → DomainReachabilityFailures (curl the SaaS domain)
 *     - Scenario 2 → StatelessRuleFailures      (TCP connect to the Amazon Keyspaces TLS test class)
 *     - Scenario 3 → AsymmetricFlowFailures      (curl a long-lived HTTPS flow)
 *   A probe is counted as failed when curl exits with a connection timeout
 *   (exit 28) — the signature of a firewall drop — so a destination that merely
 *   refuses or resets the connection is not a false positive.
 *
 *   On every cycle the daemon also reads the live state of the three scenario
 *   CloudWatch alarms (one `DescribeAlarms` call over the CloudWatch interface
 *   endpoint) and writes the per-scenario card state to a local JSON file
 *   (`/opt/nf-agent/status.json`) FROM THAT alarm state. So the status-page card
 *   reflects the EXACT alarm state AWS DevOps Agent sees: it flips when the alarm
 *   flips and clears when the alarm clears, regardless of how the fix was applied
 *   (the scenario script's revert, or a CLI command run on the agent's advice).
 *
 * Live status page (a browser view of the per-scenario alarm state):
 *   A second systemd service runs a tiny Python HTTP server on
 *   {@link STATUS_PAGE_PORT} that renders one green/red box per scenario from
 *   `status.json`. The status-page ALB (`lib/status-page-stack.ts`) fronts it on
 *   public HTTP :80 so an operator can watch a scenario flip red in the browser.
 *
 * Reachability without SSH (design "SSM reachability"):
 *   - The instance is managed exclusively through **AWS Systems Manager (SSM)**: no SSH key pair, no
 *     public IP. SSM control traffic reaches it over interface VPC endpoints
 *     that bypass the firewall, so it stays reachable even while egress through
 *     the firewall is deliberately broken.
 *   - The instance role grants `AmazonSSMManagedInstanceCore`, a scoped
 *     `cloudwatch:PutMetricData` for the `NfAgent/Workload` namespace, and a
 *     `cloudwatch:DescribeAlarms` scoped to the `Alarm-*` alarms (so the
 *     page can mirror the live alarm state).
 *
 * Cross-stack contract: this stack consumes the VPC and the protected subnet
 * from the network stack, and the firewall name (for the metric dimension), as
 * props. `bin/app.ts` passes `network.vpc`, `network.protectedSubnets[0]`, and
 * `firewall.firewallName`.
 */
import * as cdk from "aws-cdk-lib";
import { Tags } from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as iam from "aws-cdk-lib/aws-iam";
import * as s3assets from "aws-cdk-lib/aws-s3-assets";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as path from "path";
import * as fs from "fs";
import { Construct } from "constructs";

/** Re-export the project tag from the network stack's single source of truth. */
import { PROJECT_TAG_KEY, PROJECT_TAG_VALUE } from "./network-stack";

/** The custom CloudWatch namespace the health-check daemon publishes to. */
export const WORKLOAD_METRIC_NAMESPACE = "NfAgent/Workload";

/**
 * The TCP port the workload's status-page web server listens on. The
 * status-page ALB (see `lib/status-page-stack.ts`) forwards public HTTP :80
 * traffic to the instance on this port, and the workload security group allows
 * the ALB security group inbound on it. A non-privileged port so the web-server
 * systemd unit need not run with extra capabilities.
 */
export const STATUS_PAGE_PORT = 8080;

/**
 * Default basic-auth username for the status page + webhook-config UI. The
 * username can be overridden via the `statusPageUsername` context value. The
 * password is always randomly generated into AWS Secrets Manager at deploy
 * (there is no plaintext-password override).
 */
export const DEFAULT_STATUS_PAGE_USERNAME = "admin";

/** AWS Secrets Manager secret holding the status-page login password (randomly generated at deploy). */
export const STATUS_PAGE_SECRET_NAME = "nf-devops-agent-statuspage-login";

/**
 * The Secrets Manager secret the webhook-config form writes to. Matches
 * {@link WEBHOOK_SECRET_NAME} in `lib/webhook-stack.ts`; duplicated here as a
 * constant so the workload can scope its write IAM to a deterministic ARN
 * without a cross-stack dependency on the webhook stack.
 */
export const WEBHOOK_SECRET_NAME = "nf-devops-agent-webhook-credentials";

/** The per-scenario custom metric names (one alarm each in the alarms stack). */
export const SCENARIO_METRICS = {
  scenario1: "DomainReachabilityFailures",
  scenario2: "StatelessRuleFailures",
  scenario3: "AsymmetricFlowFailures",
} as const;

/**
 * The per-scenario CloudWatch alarm names. Shared by the alarms stack (which
 * creates them) and the workload health-check daemon (which reads their live
 * `StateValue` each cycle so the status page mirrors the EXACT alarm state AWS
 * DevOps Agent sees). Keeping them here keeps the producer and the reader in
 * sync — rename once, both follow.
 */
export const SCENARIO_ALARM_NAMES = {
  scenario1: "Alarm-1",
  scenario2: "Alarm-2",
  scenario3: "Alarm-3",
} as const;

/**
 * Default probe targets per scenario.
 *
 * Scenarios 1 and 3 work out of the box against real, reachable HTTPS endpoints,
 * so their checks read green at baseline and flip red only when you break the
 * scenario. Scenario 2 targets a synthetic port by design, so there is no
 * universal public endpoint that answers at baseline — point it
 * at an endpoint reachable from YOUR account (see the per-field notes and the
 * README "Health-check probe targets" section).
 *
 * A probe counts as failed ONLY when curl exits 28 (connection timeout) — the
 * signature of a firewall drop. A DNS failure or connection refusal is NOT a
 * failure, which is why Scenario 1's target must be a real, resolvable domain.
 */
const DEFAULTS = {
  // NOTE: the probe targets below are INTENTIONAL references to real AWS service
  // endpoints, not example placeholders. The scenarios demonstrate a real
  // firewall drop, so each target must be reachable and resolvable at baseline
  // and only break when its scenario is activated. Documented in SECURITY.md.
  /**
   * Scenario 1: the SaaS domain on 443. `bin/app.ts` overrides this with
   * `https://<saasTestDomain>` so the probe always hits the SAME domain the
   * firewall denylist blocks. Must be real and resolvable (default `docs.aws.amazon.com`).
   */
  domainTargetUrl: "https://docs.aws.amazon.com",
  /**
   * Scenario 2: the designated stateless test class — TCP port 9142 (Amazon
   * Keyspaces over TLS). The probe opens a TCP connection to the regional
   * Amazon Keyspaces (for Apache Cassandra) endpoint
   * (`cassandra.<region>.amazonaws.com:9142`), a public AWS service endpoint
   * that answers on 9142 over TLS, so the check is green at baseline and flips
   * red only when the stateless priority inversion drops port-9142 egress.
   * Empty by default so the builder fills in the deploy region; override with a
   * `host:port` value (a TCP connect, not an HTTP request) to use another target.
   */
  statelessTargetUrl: "",
  /** Scenario 3: a real, reachable HTTPS endpoint whose mid-flow packets the asymmetric drop breaks. */
  asymmetricTargetUrl: "https://aws.amazon.com",
  /**
   * Control probe: a real, reachable HTTPS endpoint that is NOT the target of
   * any scenario rule. It measures the health of the egress PATH itself, so the
   * status page can tell an isolated rule failure (Scenarios 1/2, control still
   * green) apart from a subnet-wide egress outage (Scenario 3 flips the whole
   * protected-subnet route cross-AZ, so the control probe fails too). When the
   * control probe is failing, the page explains the other reds as collateral of
   * the routing fault rather than their own conditions firing. Page-only: it is
   * NOT published as a CloudWatch metric, so it adds no alarm.
   */
  controlTargetUrl: "https://sts.amazonaws.com",
} as const;

/** How often the health-check daemon probes each target, in seconds. */
const PROBE_INTERVAL_SECONDS = 30;
/** curl per-probe timeout, in seconds (a timeout is the firewall-drop signal). */
const PROBE_CURL_TIMEOUT_SECONDS = 8;

/**
 * Props for {@link WorkloadStack}.
 */
export interface WorkloadStackProps extends cdk.StackProps {
  /** The Sample_VPC the workload attaches to (from the network stack). */
  readonly vpc: ec2.IVpc;
  /** Protected subnet A — `network.protectedSubnets[0]`. */
  readonly protectedSubnet: ec2.ISubnet;
  /** The deployed firewall name (the `Firewall` metric dimension), from `firewall.firewallName`. */
  readonly firewallName: string;
  /** Override the Scenario 1 domain probe target (default a placeholder SaaS domain). */
  readonly domainTargetUrl?: string;
  /** Override the Scenario 2 stateless-class probe target (default `host:port` TCP connect to the regional Amazon Keyspaces TLS endpoint, port 9142). */
  readonly statelessTargetUrl?: string;
  /** Override the Scenario 3 asymmetric-flow probe target. */
  readonly asymmetricTargetUrl?: string;
  /** Override the control probe target (default an AWS HTTPS endpoint not used by any scenario). */
  readonly controlTargetUrl?: string;
  /**
   * Basic-auth username for the status page + webhook-config UI (default
   * {@link DEFAULT_STATUS_PAGE_USERNAME}). The page and the config form are
   * served only behind this credential.
   */
  readonly statusPageUsername?: string;
}

/**
 * The EC2 test workload stack. Exposes {@link instanceId} for outputs and the
 * `scenarioctl verify` probe, plus the metric namespace it publishes to.
 */
export class WorkloadStack extends cdk.Stack {
  /** The test workload instance. */
  public readonly instance: ec2.Instance;
  /** The instance id — surfaced as a CfnOutput and used by the verify probe. */
  public readonly instanceId: string;
  /** The instance's egress-only security group. */
  public readonly securityGroup: ec2.SecurityGroup;
  /** The SSM-enabled instance role (also grants scoped PutMetricData). */
  public readonly instanceRole: iam.Role;
  /** The custom metric namespace the health-check daemon publishes to. */
  public readonly metricNamespace: string;
  /** Secrets Manager secret holding the status-page login password (generated at deploy). */
  public readonly statusPageSecret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: WorkloadStackProps) {
    super(scope, id, props);

    this.metricNamespace = WORKLOAD_METRIC_NAMESPACE;

    // Status-page login password: always randomly generated into AWS Secrets
    // Manager at deploy (never hard-coded, never a CloudFormation output, never
    // passed through `unsafePlainText`). The status server reads it from Secrets
    // Manager at runtime and holds it only in memory (never written to disk);
    // scripts/deploy.sh fetches it to print the effective password once. To
    // rotate, update the secret in Secrets Manager directly.
    this.statusPageSecret = new secretsmanager.Secret(this, "StatusPageLogin", {
      secretName: STATUS_PAGE_SECRET_NAME,
      description: "Status-page login password for the AWS Network Firewall with AWS DevOps Agent sample (generated at deploy).",
      generateSecretString: {
        passwordLength: 20,
        // URL/cookie/JSON-safe: no quotes, slashes, backslashes, or other
        // characters that would complicate the login form or the webhook form.
        excludePunctuation: true,
        excludeCharacters: "\"'\\/@`$&|<>{}",
        requireEachIncludedType: true,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Instance role: the SSM-agent baseline plus a tightly-scoped
    // PutMetricData restricted to the NfAgent/Workload namespace (the health
    // checks publish there; nothing else).
    this.instanceRole = new iam.Role(this, "WorkloadInstanceRole", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      description: "SSM-managed role for the AWS Network Firewall sample test workload and health checks",
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore"),
      ],
    });
    this.instanceRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "PublishHealthCheckMetrics",
        effect: iam.Effect.ALLOW,
        actions: ["cloudwatch:PutMetricData"],
        // Acknowledged exception: cloudwatch:PutMetricData is not resource-scopable
        // per the AWS API (it has no resource ARN), so Resource must be "*". This
        // is a resource wildcard, not an action wildcard, and is the minimal
        // viable scope: access is constrained to the "NfAgent/Workload" namespace
        // via the cloudwatch:namespace condition key below. See SECURITY.md.
        resources: ["*"],
        conditions: {
          // ...so constrain it to this namespace instead.
          StringEquals: { "cloudwatch:namespace": WORKLOAD_METRIC_NAMESPACE },
        },
      }),
    );
    // Read the live state of the three per-scenario alarms so the status page can
    // mirror the EXACT alarm state AWS DevOps Agent sees (card flips when the
    // alarm flips, clears when the alarm clears — regardless of HOW the fix was
    // applied). Scoped to the NfAgent alarm ARNs. The read goes over the
    // CloudWatch interface endpoint, so it succeeds even when a scenario (notably
    // Scenario 3) drops all firewall egress.
    this.instanceRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ReadScenarioAlarmState",
        effect: iam.Effect.ALLOW,
        actions: ["cloudwatch:DescribeAlarms"],
        resources: [
          cdk.Stack.of(this).formatArn({
            service: "cloudwatch",
            resource: "alarm",
            arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
            resourceName: "Alarm-*",
          }),
        ],
      }),
    );
    // The webhook-config form on the status page writes the DevOps Agent webhook
    // URL + signing secret into the webhook-credentials secret. Scope the
    // read/write to that one secret (name + the 6-char suffix Secrets Manager
    // appends) so the operator can paste the values in the UI instead of running
    // the AWS CLI by hand.
    this.instanceRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ManageWebhookSecret",
        effect: iam.Effect.ALLOW,
        actions: [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DescribeSecret",
        ],
        resources: [
          cdk.Stack.of(this).formatArn({
            service: "secretsmanager",
            resource: "secret",
            arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
            resourceName: `${WEBHOOK_SECRET_NAME}-*`,
          }),
        ],
      }),
    );
    // The status server reads the generated login password from its secret at boot.
    this.statusPageSecret.grantRead(this.instanceRole);

    // Egress-only security group (SSM 443 to the interface endpoints + probe
    // egress through the firewall); NO inbound rules.
    this.securityGroup = new ec2.SecurityGroup(this, "WorkloadSecurityGroup", {
      vpc: props.vpc,
      description: "Egress-only security group for the AWS Network Firewall sample test workload",
      allowAllOutbound: true,
    });

    // Status-page assets (icons + the page server) ship as a CDK Amazon Simple
    // Storage Service (Amazon S3) asset and
    // user data downloads them to /opt/nf-agent. The official AWS icons (~23 KB)
    // and the page server together far exceed the EC2 user-data 16 KB limit, so
    // they cannot be inlined. The page server is generated here (it depends only
    // on build-time constants) and written into the asset directory at synth
    // time, next to the committed nf_icons.py.
    const assetDir = path.join(__dirname, "..", "assets", "status-page");
    // Write the generated server atomically (temp file + rename) so a concurrent
    // reader never observes a half-written file. The CDK test suite constructs
    // this stack from several test files that Jest runs in parallel worker
    // processes, each regenerating this same deterministic file; a plain
    // writeFileSync can be truncated mid-read by another worker. rename(2) within
    // the same directory is atomic on POSIX, so readers always see a complete
    // (and identical) file.
    const statusServerPath = path.join(assetDir, "statuspage.py");
    const tmpPath = `${statusServerPath}.${process.pid}.tmp`;
    fs.writeFileSync(tmpPath, this.buildStatusServer(), "utf8");
    fs.renameSync(tmpPath, statusServerPath);
    const pageAsset = new s3assets.Asset(this, "StatusPageAsset", {
      path: assetDir,
    });
    pageAsset.grantRead(this.instanceRole);

    // Health-check daemon: a systemd service running a loop that probes each
    // scenario target and publishes its custom metric (1 on a firewall-drop
    // timeout, else 0). Installed via user data on first boot.
    const userData = this.buildHealthCheckUserData(props, pageAsset);
    this.instance = new ec2.Instance(this, "WorkloadInstance", {
      vpc: props.vpc,
      vpcSubnets: { subnets: [props.protectedSubnet] },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      role: this.instanceRole,
      securityGroup: this.securityGroup,
      userData,
      // No keyName / keyPair: the instance is reachable only via SSM.
    });

    this.instanceId = this.instance.instanceId;

    // Tag every resource in the stack for the teardown sweep (Requirement 10).
    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);
  }

  /**
   * Build the user data that installs and starts the health-check daemon and
   * the status-page web server. The daemon loops every
   * {@link PROBE_INTERVAL_SECONDS}, probing each scenario's target with curl and
   * publishing the per-scenario custom metric: `1` when the probe times out (the
   * firewall-drop signature, curl exit 28), else `0`. On every cycle it also
   * writes the four results to `/opt/nf-agent/status.json`. A second systemd unit
   * runs a tiny Python HTTP server on {@link STATUS_PAGE_PORT} that renders a
   * green/red box per scenario from that file (the ALB fronts it on :80).
   */
  private buildHealthCheckUserData(props: WorkloadStackProps, pageAsset: s3assets.Asset): ec2.UserData {
    const ud = ec2.UserData.forLinux();
    const region = cdk.Stack.of(this).region;
    const ns = WORKLOAD_METRIC_NAMESPACE;
    const fw = props.firewallName;
    const alarm1 = SCENARIO_ALARM_NAMES.scenario1;
    const alarm2 = SCENARIO_ALARM_NAMES.scenario2;
    const alarm3 = SCENARIO_ALARM_NAMES.scenario3;

    const domainUrl = props.domainTargetUrl ?? DEFAULTS.domainTargetUrl;
    // Scenario 2 default: the regional Amazon Keyspaces TLS endpoint (port 9142),
    // a public AWS service endpoint. Region-aware so it tracks the deploy region.
    const statelessUrl =
      props.statelessTargetUrl ||
      DEFAULTS.statelessTargetUrl ||
      `cassandra.${region}.amazonaws.com:9142`;
    const asymmetricUrl = props.asymmetricTargetUrl ?? DEFAULTS.asymmetricTargetUrl;
    const controlUrl = props.controlTargetUrl ?? DEFAULTS.controlTargetUrl;

    // The health-check script. Each cycle it runs the per-scenario egress probes
    // (publishing the custom metrics that drive the alarms) and the page-only
    // control probe, then reads the LIVE state of the three CloudWatch alarms and
    // writes /opt/nf-agent/status.json from THAT. So the status page mirrors the
    // exact alarm state AWS DevOps Agent sees: a card flips when its alarm flips
    // and clears when the alarm clears, no matter how the fix was applied (the
    // script's revert, or a CLI command the operator runs on the agent's advice).
    const script = [
      "#!/bin/bash",
      "set -u",
      `REGION="${region}"`,
      `NS="${ns}"`,
      `FW="${fw}"`,
      `INTERVAL=${PROBE_INTERVAL_SECONDS}`,
      `TIMEOUT=${PROBE_CURL_TIMEOUT_SECONDS}`,
      `DOMAIN_URL="${domainUrl}"`,
      `STATELESS_URL="${statelessUrl}"`,
      `ASYMMETRIC_URL="${asymmetricUrl}"`,
      `CONTROL_URL="${controlUrl}"`,
      `ALARM1="${alarm1}"`,
      `ALARM2="${alarm2}"`,
      `ALARM3="${alarm3}"`,
      'STATUS_FILE="/opt/nf-agent/status.json"',
      "",
      "put_metric() {",
      "  # $1 = metric name, $2 = value (0|1)",
      "  # Bounded with `timeout` so a wedged egress path can never hang the loop;",
      "  # metric traffic uses the CloudWatch interface endpoint (bypasses the",
      "  # firewall) so this normally succeeds even when a scenario drops egress.",
      '  timeout 15 aws cloudwatch put-metric-data --region "$REGION" --namespace "$NS" \\',
      '    --metric-name "$1" --value "$2" --unit Count \\',
      '    --dimensions Firewall="$FW" >/dev/null 2>&1 || true',
      "}",
      "",
      "# Run a scenario probe and publish its metric. A curl timeout (exit 28) is",
      "# the firewall-drop signature -> publish 1, else 0. This metric is what the",
      "# alarm evaluates; the PAGE state is read back from the alarm (read_alarm_states).",
      "probe() {",
      "  # $1 = metric name, $2 = url.",
      '  curl -sS -o /dev/null --max-time "$TIMEOUT" "$2" >/dev/null 2>&1',
      "  code=$?",
      '  if [ "$code" -eq 28 ]; then RESULT=1; else RESULT=0; fi',
      '  put_metric "$1" "$RESULT"',
      "}",
      "",
      "# Stateless-class probe (Scenario 2): a raw TCP connect to host:port, used",
      "# because the target is the Amazon Keyspaces TLS endpoint (port 9142), which",
      "# expects a TLS/CQL handshake, not HTTP, so curl is not appropriate. A",
      "# connection that cannot be established within the timeout is the firewall-drop",
      "# signature -> publish 1, else 0. Uses bash's /dev/tcp.",
      "probe_tcp() {",
      "  # $1 = metric name, $2 = host:port.",
      '  local host="${2%%:*}" port="${2##*:}"',
      '  if timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/${host}/${port}" >/dev/null 2>&1; then',
      "    RESULT=0",
      "  else",
      "    RESULT=1",
      "  fi",
      '  put_metric "$1" "$RESULT"',
      "}",
      "",
      "# Control probe: same drop detection, but publishes NO metric (page-only).",
      "# Measures the health of the egress PATH itself (no scenario rule targets it),",
      "# so the page can tell an isolated rule failure from a subnet-wide outage.",
      "probe_control() {",
      "  # $1 = url. Sets RESULT to 1 on a firewall-drop timeout, else 0.",
      '  curl -sS -o /dev/null --max-time "$TIMEOUT" "$1" >/dev/null 2>&1',
      "  code=$?",
      '  if [ "$code" -eq 28 ]; then RESULT=1; else RESULT=0; fi',
      "}",
      "",
      "# Read the live state of the three scenario alarms in one DescribeAlarms",
      "# call (over the CloudWatch interface endpoint, so it works even when a",
      "# scenario drops all firewall egress). A scenario is 'failing' for the page",
      "# IFF its alarm is in ALARM. INSUFFICIENT_DATA / OK both render healthy. On",
      "# any read error we KEEP the previous values (set by the caller) rather than",
      "# flapping the page.",
      "read_alarm_states() {",
      "  # Sets A1/A2/A3 to 0|1 (1 = ALARM). Leaves them unchanged on error.",
      '  local out',
      '  out=$(timeout 15 aws cloudwatch describe-alarms --region "$REGION" \\',
      '    --alarm-names "$ALARM1" "$ALARM2" "$ALARM3" \\',
      `    --query 'MetricAlarms[].[AlarmName,StateValue]' --output text 2>/dev/null)`,
      '  [ -z "$out" ] && return 1',
      '  local name state',
      '  while read -r name state; do',
      '    [ -z "$name" ] && continue',
      '    local v=0; [ "$state" = "ALARM" ] && v=1',
      '    case "$name" in',
      '      "$ALARM1") A1=$v ;;',
      '      "$ALARM2") A2=$v ;;',
      '      "$ALARM3") A3=$v ;;',
      '    esac',
      '  done <<< "$out"',
      '  return 0',
      "}",
      "",
      "write_status() {",
      "  # $1..$3 = scenario 1..3 PAGE state (0|1, from the alarm); $4 = control",
      "  # probe result (0|1). `control_failing` lets the page explain a subnet-wide",
      "  # egress outage (Scenario 3 blast radius) vs an isolated rule failure.",
      '  cat > "$STATUS_FILE" <<STATUSEOF',
      "{",
      '  "firewall": "$FW",',
      '  "updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",',
      '  "control_failing": $4,',
      '  "scenarios": [',
      `    {"id": 1, "name": "Domain deny list", "metric": "AWS/NetworkFirewall DroppedPackets", "condition": "Firewall dropping the monitored domain on its allow/deny rules", "failing": $1},`,
      `    {"id": 2, "name": "Stateless rule priority", "metric": "${SCENARIO_METRICS.scenario2}", "condition": "Stateless rules dropping the monitored traffic class", "failing": $2},`,
      `    {"id": 3, "name": "Asymmetric routing", "metric": "${SCENARIO_METRICS.scenario3}", "condition": "Return traffic dropped by asymmetric cross-Availability-Zone routing", "failing": $3}`,
      "  ]",
      "}",
      "STATUSEOF",
      "}",
      "",
      "# Page state per scenario, seeded healthy and updated from the alarms.",
      "A1=0; A2=0; A3=0",
      "# Seed an initial status file so the page renders before the first cycle.",
      "write_status 0 0 0 0",
      "",
      "while true; do",
      `  probe "${SCENARIO_METRICS.scenario1}" "$DOMAIN_URL"`,
      `  probe_tcp "${SCENARIO_METRICS.scenario2}" "$STATELESS_URL"`,
      `  probe "${SCENARIO_METRICS.scenario3}" "$ASYMMETRIC_URL"`,
      '  probe_control "$CONTROL_URL"; CTRL=$RESULT',
      '  # Drive the page from the live alarm state (the same signal DevOps Agent',
      '  # sees), not the raw probe, so a fix applied any way clears the cards.',
      '  read_alarm_states',
      '  write_status "$A1" "$A2" "$A3" "$CTRL"',
      '  sleep "$INTERVAL"',
      "done",
    ].join("\n");

    // (The status-page web server is generated by buildStatusServer() and ships
    // as an S3 asset; user data downloads it rather than inlining it.)
    return this.assembleUserData(ud, pageAsset, script, props);
  }

  /**
   * Build the status-page web server: a tiny stdlib Python HTTP server that
   * reads `status.json` and renders the egress-path topology + one card per
   * scenario. Generated from build-time constants and written into the CDK S3
   * asset directory at synth time (it is too large, with the AWS icons, to
   * inline in EC2 user data).
   */
  private buildStatusServer(): string {
    const statusServer = `#!/usr/bin/env python3
"""AWS Network Firewall status page: renders status.json as green/red scenario
cards, behind a login form, with a webhook configuration form that writes the
AWS DevOps Agent webhook URL and signing secret into AWS Secrets Manager."""
import json, html, base64, subprocess, urllib.parse, hmac, hashlib, time, os, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = ${STATUS_PAGE_PORT}
STATUS_FILE = "/opt/nf-agent/status.json"
CONFIG_FILE = "/opt/nf-agent/config.json"

# Runtime config (login username + region + secret names). Written by EC2 user
# data at boot. It carries NO password: the login password is read from AWS
# Secrets Manager at runtime (see _fetch_login_password) and held only in memory,
# never written to disk.
def load_config():
    try:
        with open(CONFIG_FILE) as f:
            c = json.load(f)
    except Exception:
        c = {}
    cfg = {
        "username": c.get("username", "admin"),
        "region": c.get("region", "us-east-1"),
        "webhookSecretName": c.get("webhookSecretName", "nf-devops-agent-webhook-credentials"),
        "statusPageSecretName": c.get("statusPageSecretName", "nf-devops-agent-statuspage-login"),
    }
    return cfg

CONFIG = load_config()

# Read the generated login password from AWS Secrets Manager at runtime and keep
# it in memory only (never persisted to disk). boto3 is not installed for the
# system python on the AMI, so use the preinstalled AWS CLI, the same mechanism
# the webhook secret reader uses. If the password cannot be read (for example the
# instance role is not ready yet at first boot), the server refuses to start; the
# systemd unit restarts it every 5s, so it self-heals once the secret is readable.
def _fetch_login_password():
    try:
        out = subprocess.run(
            ["aws", "secretsmanager", "get-secret-value",
             "--secret-id", CONFIG["statusPageSecretName"],
             "--region", CONFIG["region"],
             "--query", "SecretString", "--output", "text"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode == 0:
            return (out.stdout or "").strip()
    except Exception:
        pass
    return ""

LOGIN_PASSWORD = _fetch_login_password()
if not LOGIN_PASSWORD:
    raise SystemExit(
        "FATAL: could not read the status-page password from AWS Secrets Manager "
        "secret '" + CONFIG["statusPageSecretName"] + "'. The password is generated "
        "at deploy and read at runtime; refusing to start without it. systemd will "
        "retry."
    )

# Session handling: a styled in-page login form sets a signed, time-limited
# cookie (HMAC over username+expiry). No browser basic-auth popup. The signing
# key is per-process random, so restarting the server invalidates sessions.
SESSION_TTL_SECONDS = 12 * 60 * 60
SESSION_KEY = os.urandom(32)
COOKIE_NAME = "nfsession"

def _make_token():
    exp = str(int(time.time()) + SESSION_TTL_SECONDS)
    msg = (CONFIG["username"] + "|" + exp).encode("utf-8")
    sig = hmac.new(SESSION_KEY, msg, hashlib.sha256).hexdigest()
    raw = CONFIG["username"] + "|" + exp + "|" + sig
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")

def _valid_token(token):
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        user, exp, sig = raw.split("|", 2)
        expected = hmac.new(SESSION_KEY, (user + "|" + exp).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        return int(exp) > int(time.time())
    except Exception:
        return False

def _check_login(username, password):
    # Constant-time comparison of both fields.
    u_ok = hmac.compare_digest(username or "", CONFIG["username"])
    p_ok = hmac.compare_digest(password or "", LOGIN_PASSWORD)
    return u_ok and p_ok

# ---- CSRF protection for state-changing POSTs (the /config webhook form) ----
# A stateless CSRF token bound to the caller's session: HMAC(session_token) under
# the per-process key. The token is embedded as a hidden field when the form is
# rendered and re-verified on POST. Because it is derived from the session cookie
# (which an attacker's site cannot read under SameSite=Lax + HttpOnly), a forged
# cross-site POST cannot carry a valid token.
def _csrf_token(session_token):
    if not session_token:
        return ""
    return hmac.new(SESSION_KEY, ("csrf|" + session_token).encode("utf-8"), hashlib.sha256).hexdigest()

def _csrf_ok(session_token, presented):
    expected = _csrf_token(session_token)
    return bool(expected) and bool(presented) and hmac.compare_digest(presented, expected)

# ---- Login rate limiting (per source IP, in-memory, best-effort) ----
# Slows online brute-force against the shared login. Tracks recent failures per
# client IP; after a threshold the login is briefly refused with HTTP 429. State
# is per-process and resets on restart, which is fine for a single-instance
# sample. Not a substitute for a strong password or a CIDR/WAF restriction.
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300
LOGIN_LOCKOUT_SECONDS = 60
_login_failures = {}  # ip -> [timestamps]
_login_lock = threading.Lock()

def _login_locked_out(ip):
    now = time.time()
    with _login_lock:
        hits = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
        _login_failures[ip] = hits
        if len(hits) >= LOGIN_MAX_FAILURES:
            # Locked out until the oldest counted failure ages past the lockout.
            return (now - hits[-LOGIN_MAX_FAILURES]) < LOGIN_LOCKOUT_SECONDS
    return False

def _record_login_failure(ip):
    now = time.time()
    with _login_lock:
        hits = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
        hits.append(now)
        _login_failures[ip] = hits

def _clear_login_failures(ip):
    with _login_lock:
        _login_failures.pop(ip, None)

# Official AWS architecture icons (base64 data URIs). Shipped alongside this
# server as /opt/nf-agent/nf_icons.py via a CDK S3 asset (too large to inline in
# EC2 user data). Fall back to empty strings if the module is somehow absent so
# the page still renders.
try:
    import sys
    sys.path.insert(0, "/opt/nf-agent")
    import nf_icons
    ICON_EC2 = nf_icons.ICON_EC2
    ICON_NFW = nf_icons.ICON_NFW
    ICON_S3 = nf_icons.ICON_S3
    ICON_ELB = nf_icons.ICON_ELB
    ICON_INET = nf_icons.ICON_INET
    ICON_NAT = nf_icons.ICON_NAT
    ICON_CF = nf_icons.ICON_CF
    ICON_IGW = nf_icons.ICON_IGW
    ICON_CW = nf_icons.ICON_CW
    ICON_SNS = nf_icons.ICON_SNS
    ICON_LAMBDA = nf_icons.ICON_LAMBDA
    ICON_AGENT = nf_icons.ICON_AGENT
    ICON_AWS = nf_icons.ICON_AWS
    ICON_KEYSPACES = nf_icons.ICON_KEYSPACES
except Exception:
    ICON_EC2 = ICON_NFW = ICON_S3 = ICON_ELB = ICON_INET = ICON_NAT = ICON_CF = ""
    ICON_IGW = ICON_CW = ICON_SNS = ICON_LAMBDA = ICON_AGENT = ICON_AWS = ICON_KEYSPACES = ""

CSS = (
    "*{box-sizing:border-box}"
    "html,body{height:100%}"
    "body{font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif;margin:0;overflow:hidden;"
    "background:radial-gradient(1200px 700px at 50% -10%,#15243a 0%,#0c1626 55%,#0a121f 100%);"
    "color:#eaf0f8}"
    # Full-viewport flex column: header, topology (flexes to fill), card row.
    ".wrap{max-width:1240px;height:100vh;margin:0 auto;display:flex;flex-direction:column;"
    "gap:clamp(8px,1.4vh,16px);padding:clamp(12px,2.2vh,26px) clamp(16px,3vw,30px)}"
    ".head{flex:0 0 auto;display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}"
    ".headtext{min-width:0}"
    # #live wraps the refreshable content (banner + topology + cards) and must
    # itself be a flex column that fills the remaining height, so the topology
    # can flex to fit and the page needs no scroll (matches the pre-fragment layout).
    "#live{flex:1 1 auto;min-height:0;display:flex;flex-direction:column;gap:clamp(8px,1.4vh,16px)}"
    ".headactions{display:flex;align-items:center;gap:10px;flex:0 0 auto}"
    ".hbtn{display:inline-flex;align-items:center;gap:7px;text-decoration:none;cursor:pointer;"
    "font-size:clamp(11px,1.4vh,13px);font-weight:600;line-height:1;white-space:nowrap;"
    "padding:9px 14px;border-radius:9px;border:1px solid #2f6fd0;"
    "background:linear-gradient(180deg,#2a8af6,#1f6fe0);color:#fff;"
    "box-shadow:0 4px 12px rgba(20,60,120,0.35);transition:filter .15s ease}"
    ".hbtn:hover{filter:brightness(1.08)}"
    ".hbtn-ghost{background:#142337;border:1px solid #2c4a6a;color:#cdd9ea;box-shadow:none}"
    ".hbtn-ghost:hover{background:#19293f}"
    "h1{font-size:clamp(17px,2.2vh,23px);font-weight:650;margin:0 0 3px;letter-spacing:-0.01em}"
    ".sub{color:#8a9cb3;font-size:clamp(11px,1.5vh,13px);margin:0}"
    ".sub b{color:#bcd0ea;font-weight:600}"
    # Topology fills the remaining space; the SVG letterboxes to fit (no scroll).
    ".topo{flex:1 1 auto;min-height:0;display:flex;flex-direction:column;"
    "background:linear-gradient(180deg,#13233a 0%,#0f1d31 100%);border:1px solid #243a55;"
    "border-radius:16px;padding:clamp(10px,1.6vh,18px) clamp(12px,1.6vw,20px);box-shadow:0 14px 34px rgba(4,10,20,0.45)}"
    ".topo h3{margin:0 0 2px;font-size:clamp(12px,1.7vh,14px);font-weight:650;color:#eaf0f8;letter-spacing:-0.005em;flex:0 0 auto;text-align:center}"
    ".topo p{margin:0 0 4px;font-size:clamp(10px,1.4vh,12px);color:#8a9cb3;line-height:1.45;flex:0 0 auto;text-align:center}"
    # Two-row caption legend: each row is label + path + colour note, easy to scan.
    ".topolegend{flex:0 0 auto;display:flex;flex-direction:column;align-items:center;gap:5px;margin:2px 0 6px}"
    ".tlrow{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:8px;font-size:clamp(10px,1.35vh,12px);line-height:1.3;text-align:center}"
    ".tlk{flex:0 0 auto;font-weight:700;color:#cdd9ea;text-transform:uppercase;letter-spacing:0.03em;font-size:clamp(9px,1.2vh,10.5px)}"
    ".tlpath{color:#9fb2c9;font-family:ui-monospace,Menlo,monospace;font-size:clamp(9.5px,1.3vh,11.5px)}"
    ".tlnote{color:#8a9cb3;display:inline-flex;align-items:center;gap:6px}"
    ".swatch{width:9px;height:9px;border-radius:2.5px;flex:0 0 auto;display:inline-block}"
    ".sw-red{background:#ff5b52} .sw-amber{background:#ffd23f}"
    ".topo svg{flex:1 1 auto;min-height:0;width:100%;height:100%;display:block}"
    ".topo .ttl{fill:#eaf0f8;font:650 12px 'Segoe UI',system-ui,Arial,sans-serif}"
    ".topo .sub2{fill:#8a9cb3;font:500 10px ui-monospace,Menlo,monospace}"
    ".topo .grp{font:700 10.5px 'Segoe UI',system-ui,Arial,sans-serif;letter-spacing:0.04em;text-transform:uppercase}"
    ".topo .grpcidr{font:500 9.5px ui-monospace,Menlo,monospace}"
    ".topo .elbl{fill:#cdd9ea;font:600 9.5px 'Segoe UI',system-ui,Arial,sans-serif}"
    ".topo .leg{fill:#aebccf;font:600 13px 'Segoe UI',system-ui,Arial,sans-serif}"
    # Three scenario cards across the bottom (responsive: collapse to 1 col when narrow).
    ".grid{flex:0 0 auto;display:grid;grid-template-columns:repeat(3,1fr);gap:clamp(10px,1.4vw,16px)}"
    ".card{position:relative;border-radius:14px;padding:clamp(11px,1.5vh,16px) 16px;"
    "background:linear-gradient(180deg,#172A42 0%,#13233742 100%),#142337;"
    "border:1px solid #243a55;box-shadow:0 10px 26px rgba(4,10,20,0.4);overflow:hidden}"
    ".card::before{content:'';position:absolute;left:0;top:0;height:4px;width:100%;background:#2f4a6a}"
    ".card.ok::before{background:linear-gradient(90deg,#2ecc71,#27c768)}"
    ".card.bad::before{background:linear-gradient(90deg,#ff5b52,#e7372b)}"
    ".card.warn::before{background:linear-gradient(90deg,#ffd23f,#f1b412)}"
    ".card h2{font-size:clamp(12px,1.6vh,13px);margin:0 0 9px;font-weight:600;color:#dce6f4;letter-spacing:-0.005em}"
    ".card h2 .n{color:#7d93ad;font-weight:700;margin-right:6px}"
    ".badge{display:inline-flex;align-items:center;gap:9px;font-size:clamp(12px,1.5vh,13px);font-weight:650;letter-spacing:0.01em}"
    ".dot{width:10px;height:10px;border-radius:50%;flex:0 0 auto}"
    ".ok .dot{background:#2ee06f;box-shadow:0 0 0 4px rgba(46,224,111,0.16),0 0 10px #2ee06f} .ok .badge{color:#86e6ad}"
    ".bad .dot{background:#ff5b52;box-shadow:0 0 0 4px rgba(255,91,82,0.16),0 0 10px #ff5b52} .bad .badge{color:#ff9d96}"
    ".warn .dot{background:#ffd23f;box-shadow:0 0 0 4px rgba(255,210,63,0.16),0 0 10px #ffd23f} .warn .badge{color:#ffe08a}"
    ".metric{display:block;color:#6f879f;font-size:10px;margin-top:8px;font-family:ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:0.02em}"
    ".note{display:block;color:#ffe08a;font-size:10.5px;margin-top:8px;line-height:1.4}"
    ".banner{flex:0 0 auto;border-radius:12px;padding:clamp(8px,1.2vh,13px) 18px;"
    "background:linear-gradient(180deg,#3a2c10 0%,#2c2009 100%);"
    "border:1px solid #6b4e1f;color:#ffe2a3;font-size:clamp(11px,1.4vh,12.5px);line-height:1.45;"
    "box-shadow:0 10px 26px rgba(4,10,20,0.4)}"
    ".banner b{color:#fff1cf;font-weight:650}"
    "@media (max-width:760px){.grid{grid-template-columns:1fr}}"
)

# Topology palette.
T_GREEN = "#2ee06f"
T_RED = "#ff5b52"
T_AMBER = "#ffd23f"
T_IDLE = "#3a5170"
T_LINE = "#2c4a6a"

def leg_color(s, control_failing):
    sid = str(s.get("id"))
    failing = bool(s.get("failing"))
    # Subnet-wide egress outage (control probe down) = the Scenario 3 blast
    # radius. The control probe is a live probe with NO alarm lag, so drive this
    # mode off it directly and ignore per-alarm transition ordering (alarm 3 can
    # reach ALARM a cycle after alarms 1 and 2). Scenario 3 is the root cause
    # (red); 1 and 2 are collateral (amber).
    if control_failing:
        return T_RED if sid == "3" else T_AMBER
    if not failing:
        return T_GREEN
    return T_RED

def _card(cx, cy, icon, title, sub, accent, icon_px=46):
    # An icon-only rounded card with a colored status ring, and the label BELOW
    # the card (so long hostnames are never clipped by the card width). (cx, cy)
    # is the card CENTER.
    cw = icon_px + 30
    ch = icon_px + 30
    x, y = cx - cw / 2.0, cy - ch / 2.0
    iy = cy - icon_px / 2.0
    parts = [
        '<rect x="' + f"{x:.0f}" + '" y="' + f"{y:.0f}" + '" width="' + f"{cw:.0f}" + '" height="' + f"{ch:.0f}" + '" rx="15" '
        'fill="#0f1f35" stroke="' + accent + '" stroke-width="1.6"/>',
        '<image href="' + icon + '" x="' + f"{cx - icon_px / 2.0:.0f}" + '" y="' + f"{iy:.0f}" + '" width="' + str(icon_px) + '" height="' + str(icon_px) + '"/>',
        # label below the card
        '<text x="' + f"{cx:.0f}" + '" y="' + f"{y + ch + 16:.0f}" + '" text-anchor="middle" class="ttl">' + title + '</text>',
    ]
    if sub:
        parts.append('<text x="' + f"{cx:.0f}" + '" y="' + f"{y + ch + 29:.0f}" + '" text-anchor="middle" class="sub2">' + sub + '</text>')
    return "".join(parts)

def _curve(x1, y1, x2, y2, color, eid):
    # A smooth horizontal bezier (S-curve) from (x1,y1) to (x2,y2), with an id so
    # a flow dot can animate along it.
    mx = (x1 + x2) / 2.0
    d = 'M' + f"{x1:.0f},{y1:.0f}" + ' C' + f"{mx:.0f},{y1:.0f} {mx:.0f},{y2:.0f} {x2:.0f},{y2:.0f}"
    return ('<path id="' + eid + '" d="' + d + '" fill="none" stroke="' + color + '" stroke-width="3.5" '
            'stroke-linecap="round" marker-end="url(#arrow-' + color.lstrip('#') + ')"/>')

def _flowdot(eid, color, dur="2.6s", delay="0s"):
    # A packet dot that travels along edge eid. Used ONLY on healthy (green)
    # edges to show live, flowing traffic; a broken edge is a static red line.
    return (
        # soft glow trail (drawn first, under the core dot)
        '<circle r="9" fill="' + color + '" opacity="0">'
        '<animateMotion dur="' + dur + '" begin="' + delay + '" repeatCount="indefinite">'
        '<mpath href="#' + eid + '"/></animateMotion>'
        '<animate attributeName="opacity" dur="' + dur + '" begin="' + delay + '" repeatCount="indefinite" '
        'values="0;0.20;0.20;0.20;0" keyTimes="0;0.1;0.5;0.9;1"/></circle>'
        # core dot
        '<circle r="4.5" fill="#ffffff" opacity="0">'
        '<animateMotion dur="' + dur + '" begin="' + delay + '" repeatCount="indefinite">'
        '<mpath href="#' + eid + '"/></animateMotion>'
        '<animate attributeName="opacity" dur="' + dur + '" begin="' + delay + '" repeatCount="indefinite" '
        'values="0;1;1;1;0" keyTimes="0;0.1;0.5;0.9;1"/></circle>'
    )

def _pill(cx, cy, text, color):
    # A centered rounded "pill" label, colored per state.
    w = 12 + len(text) * 6.2
    x = cx - w / 2.0
    return (
        '<g>'
        '<rect x="' + f"{x:.1f}" + '" y="' + f"{cy - 10:.0f}" + '" width="' + f"{w:.1f}" + '" height="20" rx="10" '
        'fill="#0b1726" stroke="' + color + '" stroke-width="1.2"/>'
        '<text x="' + f"{cx:.0f}" + '" y="' + f"{cy + 4:.0f}" + '" text-anchor="middle" class="elbl" fill="' + color + '">' + text + '</text>'
        '</g>'
    )

def _arrowmarker(color):
    cid = 'arrow-' + color.lstrip('#')
    return ('<marker id="' + cid + '" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            'markerHeight="7" orient="auto-start-reverse">'
            '<path d="M0,0 L10,5 L0,10 z" fill="' + color + '"/></marker>')

def _grouplabel(x, y, label, cidr, color):
    out = ('<text x="' + str(x) + '" y="' + str(y) + '" class="grp" fill="' + color + '">' + label + '</text>')
    if cidr:
        out += ('<text x="' + str(x) + '" y="' + str(y + 13) + '" class="grpcidr" fill="' + color + '" opacity="0.85">' + cidr + '</text>')
    return out

def _groupbox(x, y, w, h, color, dash=True):
    da = ' stroke-dasharray="6 5"' if dash else ''
    return ('<rect x="' + str(x) + '" y="' + str(y) + '" width="' + str(w) + '" height="' + str(h) + '" rx="14" '
            'fill="' + color + '" fill-opacity="0.045" stroke="' + color + '" stroke-width="1.4"' + da + ' opacity="0.95"/>')

def topology(scenarios, control_failing):
    by_id = {str(s.get("id")): s for s in scenarios}
    s1 = by_id.get("1", {"id": 1})
    s2 = by_id.get("2", {"id": 2})
    s3 = by_id.get("3", {"id": 3})
    c1, c2, c3 = leg_color(s1, control_failing), leg_color(s2, control_failing), leg_color(s3, control_failing)
    any_failing = any(bool(x.get("failing")) for x in (s1, s2, s3))
    # The trunk (workload -> firewall -> NAT -> IGW) is the shared egress PATH.
    # It breaks (red) only under a subnet-wide routing fault (Scenario 3).
    trunk = T_RED if control_failing else T_GREEN
    fw_accent = T_RED if control_failing else "#4aa3ff"
    # Pipeline accent: lit (amber) while any alarm is firing, idle otherwise.
    pipe = T_AMBER if any_failing else T_IDLE

    W, H = 980, 620
    # ---- DATA PLANE (top) ----
    vpc_y, vpc_h = 52, 300
    dataMidY = vpc_y + vpc_h / 2.0    # 202
    midY = int(dataMidY)
    wlX, fwX, natX, igwX = 120, 332, 540, 690
    tgtX = 884
    tgtY = [int(dataMidY - 112), int(dataMidY), int(dataMidY + 112)]
    half = 38
    thalf = 33
    igwHalf = 30

    used = set([trunk, fw_accent, c1, c2, c3, pipe])
    markers = "".join(_arrowmarker(c) for c in used)

    svg = ['<svg viewBox="0 0 ' + str(W) + ' ' + str(H) + '" preserveAspectRatio="xMidYMid meet" role="img" aria-label="VPC egress path and alarm pipeline">']
    svg.append('<defs>' + markers + '</defs>')

    # ---- VPC + three EQUAL, vertically-centered subnet boxes ----
    svg.append(_groupbox(20, vpc_y, 632, vpc_h, "#8c5bff"))
    svg.append(_grouplabel(36, vpc_y + 24, "VPC", "10.0.0.0/16", "#a984ff"))
    sb_w, sb_h = 168, 172
    sb_y = int(dataMidY - sb_h / 2.0)
    sb_x = [40, 250, 460]
    svg.append(_groupbox(sb_x[0], sb_y, sb_w, sb_h, "#1bd39a"))
    svg.append(_grouplabel(sb_x[0] + 14, sb_y + 22, "PROTECTED SUBNET", "10.0.4.0/24", "#2fe0a8"))
    svg.append(_groupbox(sb_x[1], sb_y, sb_w, sb_h, "#ff8a4c"))
    svg.append(_grouplabel(sb_x[1] + 14, sb_y + 22, "FIREWALL SUBNET", "10.0.2.0/24", "#ff9d66"))
    svg.append(_groupbox(sb_x[2], sb_y, sb_w, sb_h, "#bf8cff"))
    svg.append(_grouplabel(sb_x[2] + 14, sb_y + 22, "PUBLIC SUBNET", "10.0.0.0/24", "#cda3ff"))
    svg.append('<text x="' + str(tgtX) + '" y="' + str(vpc_y + 22) + '" text-anchor="middle" class="grp" fill="#8298b3">INTERNET</text>')

    # ---- Trunk edges: workload -> firewall -> NAT -> IGW ----
    flow = []
    svg.append(_curve(wlX + half, midY, fwX - half, midY, trunk, "e_t1"))
    svg.append(_pill((wlX + fwX) / 2.0, midY - 28, "inspect", trunk))
    svg.append(_curve(fwX + half, midY, natX - half, midY, trunk, "e_t2"))
    svg.append(_pill((fwX + natX) / 2.0, midY - 28, "egress", trunk))
    svg.append(_curve(natX + half, midY, igwX - igwHalf, midY, trunk, "e_t3"))
    if trunk == T_GREEN:
        flow.append(_flowdot("e_t1", T_GREEN, "2.6s", "0s"))
        flow.append(_flowdot("e_t2", T_GREEN, "2.6s", "0.5s"))
        flow.append(_flowdot("e_t3", T_GREEN, "2.6s", "1.0s"))

    # ---- internet gateway -> three targets (the per-scenario legs) ----
    legs = [(tgtY[0], c1, "HTTPS", 0.45, "e_l1"), (tgtY[1], c2, "TLS", 0.5, "e_l2"), (tgtY[2], c3, "HTTPS", 0.55, "e_l3")]
    for ty, color, lbl, t, eid in legs:
        x1, x2 = igwX + igwHalf, tgtX - thalf
        svg.append(_curve(x1, midY, x2, ty, color, eid))
        px = x1 + (x2 - x1) * t
        py = midY + (ty - midY) * t
        svg.append(_pill(px, py, lbl, color))
        if color == T_GREEN:
            flow.append(_flowdot(eid, T_GREEN, "2.6s", "1.4s"))

    # ---- ALARM PIPELINE (bottom): CloudWatch -> SNS -> Lambda -> DevOps Agent ----
    # EC2 publishes per-check metrics DOWN to CloudWatch; when a probe fails the
    # alarm pipeline lights up all the way to AWS DevOps Agent.
    pipeY = 512
    cwX, snsX, lmbX, agtX = 120, 360, 580, 820
    # Row label: vertical (rotated) so it sits to the LEFT of the pipeline and is
    # centered on the line, like a swimlane label, instead of floating above it.
    svg.append('<text x="26" y="' + str(pipeY) + '" transform="rotate(-90 26 ' + str(pipeY) + ')" '
               'text-anchor="middle" class="grp" fill="#8298b3">ALARM PIPELINE</text>')
    # EC2 -> CloudWatch (metrics), vertical drop from the workload node.
    svg.append(_curve(wlX, midY + half, cwX, pipeY - 40, pipe, "e_m1"))
    # Center the label on the vertical line (wlX == cwX), at the line's midpoint.
    svg.append(_pill((wlX + cwX) / 2.0, (midY + half + pipeY - 40) / 2.0, "metrics", pipe))
    # CloudWatch -> SNS -> Lambda -> DevOps Agent
    svg.append(_curve(cwX + 40, pipeY, snsX - 40, pipeY, pipe, "e_p1"))
    svg.append(_pill((cwX + snsX) / 2.0, pipeY - 26, "alarm", pipe))
    svg.append(_curve(snsX + 40, pipeY, lmbX - 40, pipeY, pipe, "e_p2"))
    svg.append(_pill((snsX + lmbX) / 2.0, pipeY - 26, "notify", pipe))
    svg.append(_curve(lmbX + 40, pipeY, agtX - 40, pipeY, pipe, "e_p3"))
    svg.append(_pill((lmbX + agtX) / 2.0, pipeY - 26, "signed webhook", pipe))
    if any_failing:
        # Light the pipeline with flowing amber dots when an alarm is active.
        flow.append(_flowdot("e_m1", T_AMBER, "2.2s", "0s"))
        flow.append(_flowdot("e_p1", T_AMBER, "2.2s", "0.4s"))
        flow.append(_flowdot("e_p2", T_AMBER, "2.2s", "0.8s"))
        flow.append(_flowdot("e_p3", T_AMBER, "2.2s", "1.2s"))

    # Flow dots above lines, below nodes.
    svg.append("".join(flow))

    # ---- Data-plane nodes ----
    svg.append(_card(wlX, midY, ICON_EC2, "Workload", "Amazon EC2", trunk))
    svg.append(_card(fwX, midY, ICON_NFW, "Network Firewall", "policy + rules", fw_accent))
    svg.append(_card(natX, midY, ICON_NAT, "NAT gateway", "egress", trunk))
    svg.append(_card(igwX, midY, ICON_IGW, "Internet", "gateway", trunk, icon_px=34))
    svg.append(_card(tgtX, tgtY[0], ICON_AWS, "docs.aws.amazon.com", "HTTPS :443", c1, icon_px=34))
    svg.append(_card(tgtX, tgtY[1], ICON_KEYSPACES, "Amazon Keyspaces", "TLS :9142", c2, icon_px=34))
    svg.append(_card(tgtX, tgtY[2], ICON_AWS, "aws.amazon.com", "HTTPS :443", c3, icon_px=34))

    # ---- Pipeline nodes ----
    svg.append(_card(cwX, pipeY, ICON_CW, "CloudWatch", "alarm", pipe, icon_px=40))
    svg.append(_card(snsX, pipeY, ICON_SNS, "SNS", "topic", pipe, icon_px=40))
    svg.append(_card(lmbX, pipeY, ICON_LAMBDA, "Lambda", "webhook bridge", pipe, icon_px=40))
    svg.append(_card(agtX, pipeY, ICON_AGENT, "DevOps Agent", "investigates", pipe, icon_px=40))

    # ---- Legend ----
    ly = H - 12
    svg.append('<g transform="translate(218,0)">')
    svg.append('<circle cx="30" cy="' + str(ly) + '" r="6" fill="' + T_GREEN + '"/><text x="44" y="' + str(ly + 4) + '" class="leg">healthy</text>')
    svg.append('<circle cx="142" cy="' + str(ly) + '" r="6" fill="' + T_RED + '"/><text x="156" y="' + str(ly + 4) + '" class="leg">dropped (root cause)</text>')
    svg.append('<circle cx="358" cy="' + str(ly) + '" r="6" fill="' + T_AMBER + '"/><text x="372" y="' + str(ly + 4) + '" class="leg">collateral / alarm active</text>')
    svg.append('</g>')
    svg.append('</svg>')

    return ('<div class="topo"><h3>How a firewall drop reaches AWS DevOps Agent</h3>'
            '<div class="topolegend">'
            '<div class="tlrow"><span class="tlk">Top row, traffic</span>'
            '<span class="tlpath">Workload &rarr; Network Firewall &rarr; NAT gateway &rarr; internet gateway &rarr; target</span>'
            '<span class="tlnote"><span class="swatch sw-red"></span>a leg turns red where the firewall drops it</span></div>'
            '<div class="tlrow"><span class="tlk">Bottom row, detection</span>'
            '<span class="tlpath">CloudWatch metric &rarr; alarm &rarr; SNS &rarr; webhook Lambda &rarr; DevOps Agent</span>'
            '<span class="tlnote"><span class="swatch sw-amber"></span>the row turns amber while an alarm is active</span></div>'
            '</div>'
            + "".join(svg) + '</div>')

    return ('<div class="topo"><h3>VPC egress path</h3>'
            '<p>Workload traffic leaves through the Network Firewall and NAT gateway to each target. '
            'A red segment is exactly where the firewall is dropping.</p>'
            + "".join(svg) + '</div>')

def card(s, control_failing):
    sid = str(s.get("id"))
    failing = bool(s.get("failing"))
    # When the control probe reports a subnet-wide egress outage, render the
    # Scenario 3 blast radius directly off that signal so the page is internally
    # consistent the instant the banner appears. The control probe has no alarm
    # lag, whereas the three alarms can transition a cycle apart (alarm 3 often
    # last), which would otherwise briefly show the banner with Scenario 3 still
    # green. Under the outage: Scenario 3 is the root cause, 1 and 2 collateral.
    if control_failing:
        if sid == "3":
            cls, state = "bad", "DROPPED"
            collateral = False
        else:
            cls, state = "warn", "UNREACHABLE (collateral)"
            collateral = True
    elif not failing:
        cls, state, collateral = "ok", "Healthy", False
    else:
        cls, state, collateral = "bad", "DROPPED", False
    name = html.escape(str(s.get("name")))
    metric = html.escape(str(s.get("metric")))
    condition = html.escape(str(s.get("condition", "")))
    note = ""
    if collateral:
        note = (
            '<span class="note">This scenario\\'s own condition is NOT firing. '
            'The Scenario 3 routing change took the whole egress path down, so this '
            'probe times out as collateral.</span>'
        )
    elif cls == "bad":
        note = '<span class="note">Condition: ' + condition + '</span>'
    # Cards sit 3-across in the bottom row; no special centering needed.
    return (
        '<div class="card ' + cls + '"><h2><span class="n">Scenario ' + str(s.get("id")) + '</span>' + name + '</h2>'
        '<span class="badge"><span class="dot"></span>' + state + '</span>'
        '<span class="metric">' + metric + '</span>' + note + '</div>'
    )

def render_architecture():
    # Architecture-only view: the topology diagram with no scenario cards and no
    # banner, all paths shown healthy. Shows the data path and alarm pipeline
    # without the per-scenario status. Served at /architecture.
    try:
        with open(STATUS_FILE) as f:
            data = json.load(f)
    except Exception:
        data = {"firewall": "(starting)", "updated": "-"}
    fw = html.escape(str(data.get("firewall")))
    # Neutral scenarios (all healthy) so no leg renders red/amber.
    neutral = [
        {"id": 1, "failing": False},
        {"id": 2, "failing": False},
        {"id": 3, "failing": False},
    ]
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>AWS Network Firewall &#8212; architecture</title><style>' + CSS + '</style></head>'
        '<body><div class="wrap">'
        '<div class="head">'
        '<div class="headtext">'
        '<h1>AWS Network Firewall &#8212; (the sample workload)</h1>'
        '<p class="sub">Firewall: ' + fw + ' &middot; architecture and alarm pipeline</p>'
        '</div>'
        '</div>'
        '<div id="live">'
        + topology(neutral, False)
        + '</div>'
        '</div></body></html>'
    )

def render():
    try:
        with open(STATUS_FILE) as f:
            data = json.load(f)
    except Exception:
        data = {"firewall": "(starting)", "updated": "-", "scenarios": [], "control_failing": 0}
    fw = html.escape(str(data.get("firewall")))
    updated = html.escape(str(data.get("updated")))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>AWS Network Firewall with AWS DevOps Agent</title><style>' + CSS + '</style></head>'
        '<body><div class="wrap">'
        '<div class="head">'
        '<div class="headtext">'
        '<h1>AWS Network Firewall &#8212; (the sample workload)</h1>'
        '<p class="sub">Firewall: ' + fw + ' &middot; updated <span id="updated">' + updated + '</span> &middot; auto-refresh 10s</p>'
        '</div>'
        '<div class="headactions">'
        '<a class="hbtn" href="/config">&#9881; Configure webhook</a>'
        '<a class="hbtn hbtn-ghost" href="/logout">Sign out</a>'
        '</div>'
        '</div>'
        '<div id="live">' + render_live(data) + '</div>'
        '</div>'
        # Refresh in place: fetch only the inner fragment and swap it, so the
        # document, CSS, and SVG container never reload (no resize flash). Falls
        # back gracefully if a fetch fails (keeps the last good view).
        '<script>'
        'setInterval(function(){'
        'fetch("/fragment",{cache:"no-store"}).then(function(r){'
        'if(!r.ok)throw 0;return r.text();}).then(function(t){'
        'document.getElementById("live").innerHTML=t;'
        'var u=document.querySelector("#live [data-updated]");'
        'if(u){document.getElementById("updated").textContent=u.getAttribute("data-updated");}'
        '}).catch(function(){});'
        '},10000);'
        '</script>'
        '</body></html>'
    )

def render_live(data):
    # The inner, refreshable content: banner + topology + cards. Served both
    # inside the full page and from /fragment for in-place updates.
    control_failing = bool(data.get("control_failing"))
    cards = "".join(card(s, control_failing) for s in data.get("scenarios", []))
    updated = html.escape(str(data.get("updated")))
    banner = ""
    if control_failing:
        banner = (
            '<div class="banner"><b>Subnet-wide egress outage detected.</b> '
            'A control probe to an endpoint no scenario rule targets is also failing, so the '
            'egress <b>path</b> is down, not one traffic class. This is the Scenario 3 '
            'scope: the asymmetric route makes every flow drop, so all three alarms fire at '
            'once and DevOps Agent correlates them to the single routing root cause. Scenario '
            '1 and 2 below are <b>collateral</b>; their own conditions are not firing.</div>'
        )
    return (
        '<span data-updated="' + updated + '" style="display:none"></span>'
        + banner
        + topology(data.get("scenarios", []), control_failing)
        + '<div class="grid">' + cards + '</div>'
    )

# ---- webhook secret (Secrets Manager) read/write via the AWS CLI ----
def read_webhook_secret():
    # Returns (configured_bool, url_or_empty). Never returns the secret value.
    try:
        out = subprocess.run(
            ["aws", "secretsmanager", "get-secret-value",
             "--secret-id", CONFIG["webhookSecretName"],
             "--region", CONFIG["region"],
             "--query", "SecretString", "--output", "text"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode != 0:
            return (False, "")
        data = json.loads(out.stdout.strip())
        url = data.get("webhookUrl", "")
        secret = data.get("webhookSecret", "")
        configured = bool(url) and url != "REPLACE_ME" and bool(secret) and secret != "REPLACE_ME"
        return (configured, url if configured else "")
    except Exception:
        return (False, "")

def write_webhook_secret(url, secret):
    # Writes {webhookUrl, webhookSecret} JSON to the secret. Returns (ok, msg).
    # Pass the payload through a 0600 temp file with --secret-string file://...
    # rather than as a direct CLI argument. A literal --secret-string <json>
    # would place the signing secret on the command line, where it is briefly
    # visible in the process list (/proc/*/cmdline) to anyone who can inspect the
    # instance. The file is created with owner-only permissions and removed in a
    # finally block. (boto3 is not installed for the system python on the AMI, so
    # we keep using the preinstalled AWS CLI.)
    payload = json.dumps({"webhookUrl": url, "webhookSecret": secret})
    fd, tmp_path = tempfile.mkstemp(prefix="nf-webhook-", suffix=".json")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(payload)
        out = subprocess.run(
            ["aws", "secretsmanager", "put-secret-value",
             "--secret-id", CONFIG["webhookSecretName"],
             "--region", CONFIG["region"],
             "--secret-string", "file://" + tmp_path],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode != 0:
            return (False, (out.stderr or "unknown error").strip()[:300])
        return (True, "")
    except Exception as e:
        return (False, str(e)[:300])
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

CONFIG_CSS = (
    ".cfgwrap{max-width:760px;margin:0 auto;padding:clamp(16px,4vh,40px) clamp(16px,4vw,32px)}"
    ".cfgcard{background:linear-gradient(180deg,#13233a 0%,#0f1d31 100%);border:1px solid #243a55;"
    "border-radius:16px;padding:clamp(18px,3vh,30px);box-shadow:0 14px 34px rgba(4,10,20,0.45)}"
    ".cfgcard h1{font-size:21px;margin:0 0 6px;letter-spacing:-0.01em}"
    ".cfgcard p{color:#8a9cb3;font-size:13px;line-height:1.5;margin:0 0 18px}"
    ".cfgcard label{display:block;font-size:12.5px;font-weight:600;color:#cdd9ea;margin:14px 0 6px}"
    ".cfgcard input{width:100%;padding:10px 12px;border-radius:9px;border:1px solid #2c4a6a;"
    "background:#0b1726;color:#eaf0f8;font-size:13px;font-family:ui-monospace,Menlo,monospace}"
    ".cfgcard input:focus{outline:none;border-color:#4aa3ff}"
    ".cfgbtn{margin-top:20px;display:inline-flex;align-items:center;gap:8px;border:none;cursor:pointer;"
    "background:linear-gradient(90deg,#2a8af6,#1f6fe0);color:#fff;font-size:14px;font-weight:650;"
    "padding:11px 20px;border-radius:10px}"
    ".cfgmsg{padding:11px 14px;border-radius:10px;font-size:13px;margin:0 0 18px;line-height:1.45}"
    ".cfgmsg.ok{background:#10331f;border:1px solid #1f6b3e;color:#a3f0c2}"
    ".cfgmsg.err{background:#3a1414;border:1px solid #6b1f1f;color:#ffb0a8}"
    ".cfgmsg.state{background:#1a2a40;border:1px solid #2c4a6a;color:#bcd0ea}"
    ".cfglink{display:inline-block;margin-top:18px;color:#7fb4ff;font-size:13px;text-decoration:none}"
    ".cfgback{display:inline-block;margin-bottom:18px;color:#7fb4ff;font-size:13px;text-decoration:none}"
)

LOGIN_CSS = (
    ".loginwrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}"
    ".logincard{width:100%;max-width:400px;background:linear-gradient(180deg,#13233a 0%,#0f1d31 100%);"
    "border:1px solid #243a55;border-radius:18px;padding:clamp(22px,4vh,36px);box-shadow:0 20px 50px rgba(4,10,20,0.55)}"
    ".loginbrand{display:flex;align-items:center;gap:9px;font-size:12.5px;font-weight:700;letter-spacing:0.04em;"
    "text-transform:uppercase;color:#8aa6c8;margin-bottom:18px}"
    ".logindot{width:9px;height:9px;border-radius:50%;background:#2ee06f;box-shadow:0 0 0 4px rgba(46,224,111,0.16),0 0 10px #2ee06f}"
    ".logincard h1{font-size:23px;margin:0 0 6px;letter-spacing:-0.01em}"
    ".logincard p{color:#8a9cb3;font-size:13px;line-height:1.5;margin:0 0 18px}"
    # The login form needs its own label/input layout (the .cfgcard rules don't reach here).
    ".logincard form{display:block}"
    ".logincard label{display:block;font-size:12.5px;font-weight:600;color:#cdd9ea;margin:14px 0 6px}"
    ".logincard input{display:block;width:100%;box-sizing:border-box;padding:10px 12px;border-radius:9px;"
    "border:1px solid #2c4a6a;background:#0b1726;color:#eaf0f8;font-size:14px;"
    "font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif}"
    ".logincard input:focus{outline:none;border-color:#4aa3ff}"
    ".logincard .cfgbtn{width:100%;justify-content:center;margin-top:22px}"
)

def render_config(session_token="", success="", error=""):
    configured, current_url = read_webhook_secret()
    csrf = _csrf_token(session_token)
    if configured:
        state = ('<div class="cfgmsg state"><b>Status:</b> a webhook is configured. '
                 'Current URL <code>' + html.escape(current_url) + '</code>. '
                 'Submitting below overwrites it.</div>')
    else:
        state = ('<div class="cfgmsg state"><b>Status:</b> no webhook configured yet. '
                 'The alarm pipeline skips delivery until you save the values below.</div>')
    msg = ""
    if success:
        msg = '<div class="cfgmsg ok">' + html.escape(success) + '</div>'
    elif error:
        msg = '<div class="cfgmsg err">' + html.escape(error) + '</div>'
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>Configure webhook | AWS Network Firewall with AWS DevOps Agent</title><style>' + CSS + CONFIG_CSS + '</style></head>'
        '<body><div class="cfgwrap">'
        '<a class="cfgback" href="/">&larr; Back to status</a>'
        '<div class="cfgcard">'
        '<h1>AWS DevOps Agent webhook</h1>'
        '<p>Create the webhook in your AWS DevOps Agent Space (Capabilities &rarr; Webhooks &rarr; Add), '
        'then paste its URL and signing secret here. They are written to the '
        '<code>' + html.escape(CONFIG["webhookSecretName"]) + '</code> secret in AWS Secrets Manager, '
        'which the alarm bridge AWS Lambda function reads to sign and deliver each incident. The secret value is never shown back.</p>'
        + state + msg +
        '<form method="POST" action="/config">'
        '<input type="hidden" name="csrf" value="' + csrf + '">'
        '<label for="webhookUrl">Webhook URL</label>'
        '<input id="webhookUrl" name="webhookUrl" type="url" placeholder="https://...amazonaws.com/webhook/..." required>'
        '<label for="webhookSecret">Signing secret</label>'
        '<input id="webhookSecret" name="webhookSecret" type="password" placeholder="paste the signing secret" required>'
        '<button class="cfgbtn" type="submit">Save to AWS Secrets Manager</button>'
        '</form>'
        '</div></div></body></html>'
    )

def render_login(error=""):
    msg = '<div class="cfgmsg err">' + html.escape(error) + '</div>' if error else ''
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>Sign in | AWS Network Firewall with AWS DevOps Agent</title><style>' + CSS + CONFIG_CSS + LOGIN_CSS + '</style></head>'
        '<body><div class="loginwrap">'
        '<div class="logincard">'
        '<div class="loginbrand"><span class="logindot"></span>AWS Network Firewall with AWS DevOps Agent</div>'
        '<h1>Sign in</h1>'
        '<p>Use the credentials shown in your deploy output. The deploy prints them '
        'as <b>Page login</b>; the username is the <code>StatusPageUsername</code> output '
        'and the password is read from the AWS Secrets Manager secret named by the '
        '<code>StatusPagePasswordSecret</code> output.</p>'
        + msg +
        '<form method="POST" action="/login">'
        '<label for="username">Username</label>'
        '<input id="username" name="username" type="text" autocomplete="username" autofocus required>'
        '<label for="password">Password</label>'
        '<input id="password" name="password" type="password" autocomplete="current-password" required>'
        '<button class="cfgbtn" type="submit">Sign in</button>'
        '</form>'
        '</div></div></body></html>'
    )

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # ---- cookie session auth ----
    def _session_ok(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith(COOKIE_NAME + "="):
                return _valid_token(part[len(COOKIE_NAME) + 1:])
        return False

    def _session_token(self):
        # Return the raw session-cookie value (used to derive the CSRF token), or "".
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith(COOKIE_NAME + "="):
                return part[len(COOKIE_NAME) + 1:]
        return ""

    def _client_ip(self):
        # The page sits behind CloudFront + ALB; honor X-Forwarded-For when set,
        # else fall back to the socket peer. Best-effort, for rate limiting only.
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        try:
            return self.client_address[0]
        except Exception:
            return "unknown"

    def _send(self, body, ctype="text/html; charset=utf-8", code=200, headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location, headers=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        # Health check is unauthenticated so the ALB can probe it.
        if self.path == "/healthz":
            self._send(b"ok", "text/plain")
            return
        path = self.path.split("?", 1)[0]
        if path == "/login":
            # Already signed in -> go to the dashboard.
            if self._session_ok():
                self._redirect("/")
            else:
                self._send(render_login())
            return
        if path == "/logout":
            # Clear the cookie and show the login page again.
            self._redirect("/login", headers={
                "Set-Cookie": COOKIE_NAME + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure",
            })
            return
        if not self._session_ok():
            self._redirect("/login")
            return
        if path == "/config":
            self._send(render_config(self._session_token()))
        elif path == "/architecture":
            self._send(render_architecture())
        elif path == "/fragment":
            try:
                with open(STATUS_FILE) as f:
                    data = json.load(f)
            except Exception:
                data = {"firewall": "(starting)", "updated": "-", "scenarios": [], "control_failing": 0}
            self._send(render_live(data))
        else:
            self._send(render())

    def _read_form(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return urllib.parse.parse_qs(raw)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/login":
            ip = self._client_ip()
            if _login_locked_out(ip):
                self._send(
                    render_login(error="Too many failed attempts. Wait a minute and try again."),
                    code=429,
                )
                return
            form = self._read_form()
            username = (form.get("username", [""])[0] or "").strip()
            password = form.get("password", [""])[0] or ""
            if _check_login(username, password):
                _clear_login_failures(ip)
                self._redirect("/", headers={
                    "Set-Cookie": COOKIE_NAME + "=" + _make_token() +
                    "; Path=/; Max-Age=" + str(SESSION_TTL_SECONDS) + "; HttpOnly; SameSite=Lax; Secure",
                })
            else:
                _record_login_failure(ip)
                self._send(render_login(error="Invalid username or password."), code=401)
            return
        # Everything else requires a session.
        if not self._session_ok():
            self._redirect("/login")
            return
        if path != "/config":
            self._send("Not found", "text/plain", code=404)
            return
        form = self._read_form()
        # CSRF: the form must carry the token bound to this session.
        if not _csrf_ok(self._session_token(), (form.get("csrf", [""])[0] or "")):
            self._send(render_config(error="Your session expired or the request could not be verified. Reload the page and try again."), code=403)
            return
        webhook_url = (form.get("webhookUrl", [""])[0] or "").strip()
        webhook_secret = (form.get("webhookSecret", [""])[0] or "").strip()
        if not webhook_url or not webhook_secret:
            self._send(render_config(self._session_token(), error="Both the webhook URL and the signing secret are required."))
            return
        ok, msg = write_webhook_secret(webhook_url, webhook_secret)
        if ok:
            self._send(render_config(self._session_token(), success="Webhook configuration saved to Secrets Manager. The alarm pipeline will use it on the next alarm."))
        else:
            self._send(render_config(self._session_token(), error="Could not save to Secrets Manager: " + msg))

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
`;

    return statusServer;
  }

  /**
   * Assemble the EC2 user data: download the status-page asset (icons + server),
   * write the health-check script, install the systemd units, and start them.
   */
  private assembleUserData(
    ud: ec2.UserData,
    pageAsset: s3assets.Asset,
    script: string,
    props: WorkloadStackProps,
  ): ec2.UserData {
    const region = cdk.Stack.of(this).region;
    const username = props.statusPageUsername ?? DEFAULT_STATUS_PAGE_USERNAME;
    // The login password is NOT baked into user data and NOT written to disk. The
    // status server reads it from Secrets Manager at runtime (the secret is
    // generated at deploy). Config here carries only non-secret values: the
    // username, region, and the names of the secrets the server reads at runtime.
    const configJson = JSON.stringify({
      username,
      region,
      webhookSecretName: WEBHOOK_SECRET_NAME,
      statusPageSecretName: STATUS_PAGE_SECRET_NAME,
    });
    const configB64 = Buffer.from(configJson, "utf8").toString("base64");
    ud.addCommands(
      "set -euxo pipefail",
      "mkdir -p /opt/nf-agent",
      "dnf install -y unzip jq >/dev/null 2>&1 || yum install -y unzip jq >/dev/null 2>&1 || true",
      // Write the non-secret status-server config (username + region + secret
      // names). The login password is never written here; the server reads it
      // from Secrets Manager at runtime and holds it only in memory.
      `echo ${configB64} | base64 -d > /opt/nf-agent/config.json`,
      "chmod 600 /opt/nf-agent/config.json",
      // Download the status-page assets (the AWS-icon module + the page server)
      // from the CDK S3 asset. They total well over the EC2 user-data 16 KB
      // limit, so they ship as an asset directory rather than inlined here.
      `aws s3 cp s3://${pageAsset.s3BucketName}/${pageAsset.s3ObjectKey} /tmp/nf-status-page.zip --region ${region}`,
      "unzip -o /tmp/nf-status-page.zip -d /opt/nf-agent",
      "chmod +x /opt/nf-agent/statuspage.py || true",
      // Write the health-check script (small enough to inline).
      `cat > /opt/nf-agent/healthcheck.sh <<'NFAGENTEOF'\n${script}\nNFAGENTEOF`,
      "chmod +x /opt/nf-agent/healthcheck.sh",
      // systemd unit so the health-check daemon runs on boot and restarts on failure.
      "cat > /etc/systemd/system/nf-agent-healthcheck.service <<'NFUNITEOF'\n" +
        "[Unit]\n" +
        "Description=AWS Network Firewall sample per-scenario health-check daemon\n" +
        "After=network-online.target\n" +
        "Wants=network-online.target\n\n" +
        "[Service]\n" +
        "ExecStart=/opt/nf-agent/healthcheck.sh\n" +
        "Restart=always\n" +
        "RestartSec=5\n\n" +
        "[Install]\n" +
        "WantedBy=multi-user.target\n" +
        "NFUNITEOF",
      // systemd unit for the status-page web server.
      "cat > /etc/systemd/system/nf-agent-statuspage.service <<'NFPAGEUNITEOF'\n" +
        "[Unit]\n" +
        "Description=AWS Network Firewall sample workload status page\n" +
        "After=network-online.target\n" +
        "Wants=network-online.target\n\n" +
        "[Service]\n" +
        "ExecStart=/usr/bin/python3 /opt/nf-agent/statuspage.py\n" +
        "Restart=always\n" +
        "RestartSec=5\n\n" +
        "[Install]\n" +
        "WantedBy=multi-user.target\n" +
        "NFPAGEUNITEOF",
      "systemctl daemon-reload",
      "systemctl enable --now nf-agent-healthcheck.service",
      "systemctl enable --now nf-agent-statuspage.service",
      // Force a restart of both services on every user-data run. `enable --now`
      // is a no-op if the unit is already running (e.g. after a reboot that
      // re-runs user data), which would leave the OLD script/server code in
      // memory. An explicit restart guarantees the freshly written code is the
      // code actually running.
      "systemctl restart nf-agent-healthcheck.service",
      "systemctl restart nf-agent-statuspage.service",
    );

    return ud;
  }
}
