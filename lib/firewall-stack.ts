/**
 * FirewallStack — the AWS Network Firewall, its policy, and the three rule
 * groups, plus the firewall-endpoint route wiring (Requirements 1.2, 5.1, 6.1,
 * 7.1, 7.2, 8.1).
 *
 * AWS Network Firewall has **no L2 constructs** in `aws-cdk-lib`, so every
 * firewall resource here is an L1 `Cfn*` construct from
 * `aws-cdk-lib/aws-networkfirewall`:
 *
 *   - `CfnFirewall`        — one firewall across BOTH firewall subnets (1 NF
 *                            endpoint per AZ).
 *   - `CfnFirewallPolicy`  — `aws:forward_to_sfe` stateless defaults,
 *                            `STRICT_ORDER` stateful engine, `aws:drop_established`
 *                            stateful default, and a `CONTINUE` stream exception
 *                            policy. The policy is the same in every scenario;
 *                            Scenario 3 breaks egress via asymmetric cross-AZ
 *                            routing (network stack), not a policy change.
 *   - `CfnRuleGroup` ×3:
 *       * `rg-stateless-priority` (STATELESS) — the Scenario 2 logic: an
 *         allow(pass) rule and a drop rule for the same designated test traffic
 *         class, with priorities taken from `allowPriority`/`dropPriority` so
 *         Scenario 2 inverts them (baseline allow=100 < drop=200 → pass wins;
 *         Scenario 2 allow=200 > drop=100 → drop wins).
 *       * `rg-stateful-baseline` (STATEFUL, STRICT_ORDER) — Suricata `pass`
 *         rules for the probe's legitimate HTTP/HTTPS egress.
 *       * `rg-domain` (STATEFUL) — Suricata domain list; baseline denies only a
 *         never-used placeholder domain (permissive); Scenario 1 adds the
 *         designated SaaS domain to the denylist.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Requires a NetworkStack.
 * ────────────────────────────────────────────────────────────────────────────
 * This stack consumes the network stack's `vpc`, `firewallSubnets`,
 * `protectedSubnetRouting`, and `ingressEdgeRouteTableId` props (passed by
 * `bin/app.ts`). The only cross-stack dependency direction is firewall ->
 * network. It cannot synthesize without those props — its test (task 7.2)
 * constructs a NetworkStack in the same app and passes them in.
 *
 * Firewall-endpoint route wiring (the network stack's CHICKEN-AND-EGG CONTRACT):
 * the protected-subnet `0.0.0.0/0` egress route and the IGW edge (ingress)
 * route must target the **Network Firewall VPC endpoint**, which only exists
 * after this stack creates the `CfnFirewall`. This stack therefore adds those
 * `ec2.CfnRoute`s itself, resolving the per-AZ endpoint id from the firewall's
 * `attrEndpointIds` (see {@link FirewallStack} `endpointIdForAz`).
 */
import * as cdk from "aws-cdk-lib";
import { Tags } from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as networkfirewall from "aws-cdk-lib/aws-networkfirewall";
import { Construct } from "constructs";

import {
  PROJECT_TAG_KEY,
  PROJECT_TAG_VALUE,
  ProtectedSubnetRouting,
  PublicSubnetReturnRouting,
} from "./network-stack";
import { ScenarioContext, StreamExceptionPolicy } from "../src/scenarioctl/state";

/** Fixed resource names for this sample (single deployment per account/region). */
const FIREWALL_NAME = "nf-devops-agent";
const FIREWALL_POLICY_NAME = "nf-devops-agent-policy";
const RG_STATELESS_NAME = "rg-stateless-priority";
const RG_STATEFUL_BASELINE_NAME = "rg-stateful-baseline";
const RG_DOMAIN_NAME = "rg-domain";

/**
 * Default SaaS test domain when none is supplied via context (cdk.json overrides).
 * INTENTIONAL real AWS endpoint (not an example placeholder): Scenario 1 needs a
 * reachable, resolvable domain that is healthy at baseline and only drops once
 * the firewall denylist is applied. Documented in SECURITY.md.
 */
const DEFAULT_SAAS_TEST_DOMAIN = "docs.aws.amazon.com";

/**
 * Designated STATELESS test traffic class (Scenario 2). TCP destination port 9142
 * (Amazon Keyspaces over TLS) so this class never overlaps Scenario 1's or
 * Scenario 3's HTTPS domain traffic (443) — the single-scenario invariant means
 * each scenario owns a distinct manifestation. The egress probe (task 14) opens a
 * TCP connection to this port against the regional Amazon Keyspaces (for Apache
 * Cassandra) endpoint (`cassandra.<region>.amazonaws.com`), a public AWS service
 * endpoint that answers on 9142 over TLS at baseline. Nothing else in this sample
 * egresses on port 9142, so the `0.0.0.0/0` destination cleanly scopes this one
 * class WITHOUT pinning a destination IP — isolation comes from the unique port,
 * so a regional-endpoint IP change never breaks it.
 */
const STATELESS_TEST_DEST_CIDR = "0.0.0.0/0";
const STATELESS_TEST_DEST_PORT = 9142;
/** IANA protocol number for TCP. */
const PROTO_TCP = 6;

/**
 * A placeholder domain the test workload never contacts. Baseline `rg-domain`
 * denies only this, so the denylist exists and is permissive at baseline; the
 * designated SaaS domain stays reachable until Scenario 1 adds it (R5.1).
 */
const PLACEHOLDER_BLOCKED_DOMAIN = "blocked.placeholder.invalid";

/** Stateless rule-group reference priority within the policy. */
const STATELESS_REF_PRIORITY = 1;
/**
 * Strict-order stateful rule-group reference priorities within the policy.
 *
 * The DOMAIN denylist MUST be evaluated BEFORE the baseline pass rules. Under
 * STRICT_ORDER the lower reference priority is evaluated first, and the baseline
 * group contains a broad `pass tcp ... 443` that would otherwise allow an HTTPS
 * flow to a denied domain before the denylist is ever consulted (first match
 * wins). Putting the domain group ahead (lower number) lets a denied domain be
 * dropped first, with everything else falling through to the baseline pass.
 */
const STATEFUL_DOMAIN_REF_PRIORITY = 100;
const STATEFUL_BASELINE_REF_PRIORITY = 200;

/**
 * Props for {@link FirewallStack}. Accepts the relevant NetworkStack props
 * directly (rather than the whole stack) for testability, plus the resolved
 * scenario context. When `scenarioContext` is omitted the stack falls back to
 * reading the values from CDK context so it synthesizes standalone.
 */
export interface FirewallStackProps extends cdk.StackProps {
  /** The Sample_VPC (from `network.vpc`). */
  readonly vpc: ec2.IVpc;
  /** Firewall subnets in AZ order (from `network.firewallSubnets`); one NF endpoint per subnet. */
  readonly firewallSubnets: ec2.ISubnet[];
  /** Per-protected-subnet routing contract (from `network.protectedSubnetRouting`). */
  readonly protectedSubnetRouting: ProtectedSubnetRouting[];
  /** Per-public-subnet return-routing contract (from `network.publicSubnetReturnRouting`). */
  readonly publicSubnetReturnRouting: PublicSubnetReturnRouting[];
  /** IGW edge (ingress) route table id (from `network.ingressEdgeRouteTableId`). */
  readonly ingressEdgeRouteTableId: string;
  /** Resolved scenario context (from `state.ts` `toContext`). Optional — falls back to CDK context. */
  readonly scenarioContext?: ScenarioContext;
}

/** Tolerant boolean coercion (context values may arrive as the string "true"/"false"). */
function toBool(value: unknown, fallback: boolean): boolean {
  if (value === undefined || value === null) return fallback;
  return value === true || value === "true";
}

/** Tolerant number coercion (context values may arrive as strings or be absent). */
function toNumber(value: unknown, fallback: number): number {
  if (value === undefined || value === null || value === "") return fallback;
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * The Network Firewall stack. Exposes the firewall, its name, and the firewall/
 * policy/rule-group ARNs that downstream stacks consume:
 *   - logging stack (task 8) needs `firewallArn` / `firewallName`,
 *   - alarms stack (task 9) needs `firewallName`,
 *   - agent-iam stack (task 10) needs `firewallArn` / `policyArn` / `ruleGroupArns`.
 */
export class FirewallStack extends cdk.Stack {
  /** The L1 Network Firewall across both firewall subnets. */
  public readonly firewall: networkfirewall.CfnFirewall;
  /** The firewall's descriptive name. */
  public readonly firewallName: string;
  /** The firewall ARN (`attrFirewallArn`). */
  public readonly firewallArn: string;
  /** The firewall policy ARN (`attrFirewallPolicyArn`). */
  public readonly policyArn: string;
  /** The three rule groups' ARNs (stateless-priority, stateful-baseline, domain). */
  public readonly ruleGroupArns: string[];
  /** The stateless priority rule group (Scenario 2). */
  public readonly statelessRuleGroup: networkfirewall.CfnRuleGroup;
  /** The strict-order stateful baseline rule group. */
  public readonly statefulBaselineRuleGroup: networkfirewall.CfnRuleGroup;
  /** The domain-list rule group (Scenario 1). */
  public readonly domainRuleGroup: networkfirewall.CfnRuleGroup;
  /** The firewall policy. */
  public readonly policy: networkfirewall.CfnFirewallPolicy;

  constructor(scope: Construct, id: string, props: FirewallStackProps) {
    super(scope, id, props);

    // ── Resolve scenario-driven values (prop first, then CDK context, then default) ──
    const ctx = props.scenarioContext;

    const rawStreamExceptionPolicy =
      ctx?.streamExceptionPolicy ?? this.node.tryGetContext("streamExceptionPolicy");
    // Per the design: DROP only when explicitly DROP (Scenario 3), else CONTINUE.
    const streamExceptionPolicy: StreamExceptionPolicy =
      rawStreamExceptionPolicy === "DROP" ? "DROP" : "CONTINUE";

    const allowPriority = toNumber(
      ctx?.allowPriority ?? this.node.tryGetContext("allowPriority"),
      100,
    );
    const dropPriority = toNumber(
      ctx?.dropPriority ?? this.node.tryGetContext("dropPriority"),
      200,
    );

    const domainDenyActive = toBool(
      ctx?.domainDenyActive ?? this.node.tryGetContext("domainDenyActive"),
      false,
    );

    // saasTestDomain is deployment config (not part of ScenarioContext) — read from context.
    const saasTestDomain: string =
      this.node.tryGetContext("saasTestDomain") ?? DEFAULT_SAAS_TEST_DOMAIN;

    // Note: `asymmetricRoute` (Scenario 3) is already baked into the network
    // stack's `protectedSubnetRouting[i].firewallEndpointAz`, so this stack only
    // routes each protected subnet to `firewallEndpointAz` — no need to re-resolve it here.

    // ── rg-stateless-priority (STATELESS) — Scenario 2 ──
    // Two rules matching the SAME designated test class; only their priorities differ.
    // Baseline allow(100) < drop(200) → pass wins; Scenario 2 inverts → drop wins.
    const testClassMatch: networkfirewall.CfnRuleGroup.MatchAttributesProperty = {
      protocols: [PROTO_TCP],
      sources: [{ addressDefinition: props.vpc.vpcCidrBlock }],
      destinations: [{ addressDefinition: STATELESS_TEST_DEST_CIDR }],
      destinationPorts: [{ fromPort: STATELESS_TEST_DEST_PORT, toPort: STATELESS_TEST_DEST_PORT }],
    };
    this.statelessRuleGroup = new networkfirewall.CfnRuleGroup(this, "StatelessPriorityRuleGroup", {
      ruleGroupName: RG_STATELESS_NAME,
      type: "STATELESS",
      capacity: 100,
      description: "Scenario 2: allow + drop rules for the designated stateless test traffic class",
      ruleGroup: {
        rulesSource: {
          statelessRulesAndCustomActions: {
            statelessRules: [
              {
                priority: allowPriority,
                ruleDefinition: { actions: ["aws:pass"], matchAttributes: testClassMatch },
              },
              {
                priority: dropPriority,
                ruleDefinition: { actions: ["aws:drop"], matchAttributes: testClassMatch },
              },
            ],
          },
        },
      },
    });

    // ── rg-stateful-baseline (STATEFUL, STRICT_ORDER) ──
    // The baseline passes established L7 traffic so legitimate HTTP/HTTPS egress
    // (and its return packets) flow. The pass rules require an ESTABLISHED flow
    // (`flow:to_server, established`) so the handshake completes — the policy's
    // `aws:drop_established` default allows the L3/L4 handshake precisely so the
    // stateful engine can establish the connection and read the TLS SNI / HTTP
    // Host that the domain group inspects. Because the domain rule group has the
    // LOWER reference priority it is evaluated FIRST, so a denied SNI is dropped
    // before these passes allow the remaining traffic through.
    const baselineStatefulRules = [
      'pass tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Allow established TLS egress"; flow:to_server, established; sid:1000002; rev:1;)',
      'pass http $HOME_NET any -> $EXTERNAL_NET any (msg:"Allow established HTTP egress"; flow:to_server, established; sid:1000001; rev:1;)',
    ];
    const statefulRulesString = baselineStatefulRules.join("\n");
    this.statefulBaselineRuleGroup = new networkfirewall.CfnRuleGroup(this, "StatefulBaselineRuleGroup", {
      ruleGroupName: RG_STATEFUL_BASELINE_NAME,
      type: "STATEFUL",
      capacity: 100,
      description: "Strict-order pass rules for the probe's legitimate egress",
      ruleGroup: {
        statefulRuleOptions: { ruleOrder: "STRICT_ORDER" },
        rulesSource: { rulesString: statefulRulesString },
      },
    });

    // ── rg-domain (STATEFUL, STRICT_ORDER) — Scenario 1 ──
    // EXPLICIT Suricata denylist (not the AWS-generated DENYLIST). Matching the
    // documented working pattern, we drop on the TLS SNI (`ssl_state:client_hello;
    // tls.sni`) and the HTTP Host (`http.host`) for each denied domain, on an
    // ESTABLISHED to-server flow so the SNI/Host is available. Baseline denies
    // only a never-used placeholder (permissive, SaaS domain reachable);
    // Scenario 1 prepends the designated SaaS domain (R5.1). Under STRICT_ORDER
    // this group is evaluated before the baseline passes, so a denied domain is
    // dropped first.
    const domainDropRules = (
      domain: string,
      tlsSid: number,
      httpSid: number,
      label: string,
    ): string[] => [
      `drop tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; content:"${domain}"; startswith; nocase; endswith; msg:"S1 domain denylist (${label})"; flow:to_server, established; sid:${tlsSid}; rev:1;)`,
      `drop http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"${domain}"; startswith; endswith; msg:"S1 domain denylist HTTP (${label})"; flow:to_server, established; sid:${httpSid}; rev:1;)`,
    ];
    // Placeholder rules always present (keeps the group valid + permissive).
    const placeholderRules = domainDropRules(PLACEHOLDER_BLOCKED_DOMAIN, 2000001, 2000011, "placeholder");
    // Scenario 1: the SaaS domain rules come first, then the placeholder rules.
    const domainRulesArray = domainDenyActive
      ? [...domainDropRules(saasTestDomain, 2000002, 2000012, "SaaS domain"), ...placeholderRules]
      : placeholderRules;
    const domainRulesString = domainRulesArray.join("\n");
    this.domainRuleGroup = new networkfirewall.CfnRuleGroup(this, "DomainRuleGroup", {
      ruleGroupName: RG_DOMAIN_NAME,
      type: "STATEFUL",
      capacity: 100,
      description: "Scenario 1: explicit Suricata SNI/Host domain denylist (SaaS domain added when domainDenyActive)",
      ruleGroup: {
        statefulRuleOptions: { ruleOrder: "STRICT_ORDER" },
        rulesSource: {
          rulesString: domainRulesString,
        },
      },
    });

    // ── CfnFirewallPolicy ──
    this.policy = new networkfirewall.CfnFirewallPolicy(this, "FirewallPolicy", {
      firewallPolicyName: FIREWALL_POLICY_NAME,
      firewallPolicy: {
        statelessDefaultActions: ["aws:forward_to_sfe"],
        statelessFragmentDefaultActions: ["aws:forward_to_sfe"],
        // drop_established (not drop_strict): allow the L3/L4 handshake so the
        // stateful engine can establish the connection and read the TLS SNI /
        // HTTP Host, which domain-list rule groups require. Established packets
        // that no pass rule allows are dropped.
        statefulDefaultActions: ["aws:drop_established"],
        statefulEngineOptions: {
          ruleOrder: "STRICT_ORDER",
          // Always CONTINUE in this sample. Scenario 3 breaks egress via asymmetric
          // cross-AZ routing (in the network stack), not a policy change, so the
          // policy itself never changes.
          streamExceptionPolicy: streamExceptionPolicy,
        },
        statelessRuleGroupReferences: [
          { priority: STATELESS_REF_PRIORITY, resourceArn: this.statelessRuleGroup.attrRuleGroupArn },
        ],
        statefulRuleGroupReferences: [
          { priority: STATEFUL_BASELINE_REF_PRIORITY, resourceArn: this.statefulBaselineRuleGroup.attrRuleGroupArn },
          { priority: STATEFUL_DOMAIN_REF_PRIORITY, resourceArn: this.domainRuleGroup.attrRuleGroupArn },
        ],
      },
    });

    // ── CfnFirewall (one endpoint per firewall subnet, in AZ order) ──
    const firewallAzs = props.firewallSubnets.map((s) => s.availabilityZone);
    this.firewall = new networkfirewall.CfnFirewall(this, "Firewall", {
      firewallName: FIREWALL_NAME,
      firewallPolicyArn: this.policy.attrFirewallPolicyArn,
      vpcId: props.vpc.vpcId,
      subnetMappings: props.firewallSubnets.map((s) => ({ subnetId: s.subnetId })),
      deleteProtection: false,
      firewallPolicyChangeProtection: false,
      subnetChangeProtection: false,
    });

    // ── Resolve a firewall-endpoint id by AZ ──
    // `attrEndpointIds` is a list of "<az>:<vpce-id>" strings. We pass
    // `subnetMappings` in `firewallSubnets` order, so endpoint i corresponds to
    // `firewallAzs[i]`; we map each AZ to its index and select+split to take the
    // vpce-id half. (AZ values are concrete at synth time for an `ec2.Vpc`, so
    // this lookup is a build-time map, not a CFN intrinsic.)
    const azToIndex = new Map<string, number>();
    firewallAzs.forEach((az, i) => azToIndex.set(az, i));
    const endpointIdForAz = (az: string): string => {
      const index = azToIndex.get(az);
      if (index === undefined) {
        throw new Error(
          `No firewall endpoint for AZ "${az}"; known firewall AZs: ${firewallAzs.join(", ")}`,
        );
      }
      return cdk.Fn.select(1, cdk.Fn.split(":", cdk.Fn.select(index, this.firewall.attrEndpointIds)));
    };

    // ── Wire the firewall-endpoint routes (network stack's CHICKEN-AND-EGG CONTRACT) ──
    props.protectedSubnetRouting.forEach((r, i) => {
      // Egress: 0.0.0.0/0 -> firewall endpoint in firewallEndpointAz (same AZ at
      // baseline; the OTHER AZ when Scenario 3 asymmetric routing is active).
      new ec2.CfnRoute(this, `ProtectedEgress${i}`, {
        routeTableId: r.routeTableId,
        destinationCidrBlock: "0.0.0.0/0",
        vpcEndpointId: endpointIdForAz(r.firewallEndpointAz),
      });
      // Ingress (symmetric return): protected CIDR -> firewall endpoint in the
      // subnet's own AZ (always same-AZ; the asymmetry lives only on egress).
      new ec2.CfnRoute(this, `IngressEdge${i}`, {
        routeTableId: props.ingressEdgeRouteTableId,
        destinationCidrBlock: r.cidr,
        vpcEndpointId: endpointIdForAz(r.availabilityZone),
      });
    });

    // ── Return routes (NAT-gateway return path through a firewall endpoint) ──
    // For each protected subnet, a return route is placed in the public subnet
    // of its egress AZ (where the NAT handling the flow lives) and targets the
    // protected subnet's OWN-AZ firewall endpoint. At baseline egress and return
    // share the same-AZ endpoint (symmetric — the stateful engine sees both
    // directions, so Scenario 1's TLS SNI inspection works). Under Scenario 3
    // the egress endpoint (other AZ) and this return endpoint (own AZ) differ:
    // the own-AZ endpoint never observed the flow's SYN, so the TCP handshake
    // never completes and egress is dropped — Scenario 3's asymmetric-flow
    // failure. This is purely a routing fault; the firewall policy is unchanged.
    // See PublicSubnetReturnRouting in network-stack.ts.
    props.publicSubnetReturnRouting.forEach((r, i) => {
      new ec2.CfnRoute(this, `PublicReturn${i}`, {
        routeTableId: r.routeTableId,
        destinationCidrBlock: r.protectedCidr,
        vpcEndpointId: endpointIdForAz(r.endpointAz),
      });
    });

    // ── Exported props ──
    this.firewallName = FIREWALL_NAME;
    this.firewallArn = this.firewall.attrFirewallArn;
    this.policyArn = this.policy.attrFirewallPolicyArn;
    this.ruleGroupArns = [
      this.statelessRuleGroup.attrRuleGroupArn,
      this.statefulBaselineRuleGroup.attrRuleGroupArn,
      this.domainRuleGroup.attrRuleGroupArn,
    ];

    // Tag every resource in the stack for the teardown sweep (Requirement 10).
    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);
  }
}
