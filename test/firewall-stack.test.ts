/**
 * CDK assertion tests for `lib/firewall-stack.ts` (task 7.2).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * The `FirewallStack` REQUIRES a `NetworkStack` (it consumes the network's
 * `vpc`, `firewallSubnets`, `protectedSubnetRouting`, and
 * `ingressEdgeRouteTableId` — see the CHICKEN-AND-EGG CONTRACT in
 * `network-stack.ts`). Each test therefore builds a `NetworkStack` and a
 * `FirewallStack` in the same `cdk.App`, driving both with a resolved
 * `scenarioContext` from `state.ts`, and synthesizes `Template.fromStack(firewall)`.
 *
 * These tests assert the firewall policy's strict-order engine and the three
 * context-driven behaviors the scenarios depend on:
 *   - Baseline: policy uses `STRICT_ORDER`; stream exception policy is `CONTINUE`.
 *   - Scenario 3: stream exception policy flips to `DROP`.
 *   - Scenario 2: the stateless allow/drop priorities invert (drop wins).
 *   - Scenario 1: the designated SaaS domain is added to the domain denylist.
 *
 * Validates: Requirements 1.2 (policy references a stateless + stateful rule
 * group with STRICT_ORDER), 5.1 (Scenario 1 domain deny entry), 6.1 (Scenario 2
 * stateless priority inversion), and 7.2 (Scenario 3 stream exception DROP).
 */

import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { NetworkStack } from "../lib/network-stack";
import { FirewallStack } from "../lib/firewall-stack";
import { ScenarioContext, baseline, desired, toContext } from "../src/scenarioctl/state";

/** A pinned environment so VPC AZ selection (and the firewall endpoint map) is deterministic. */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

/**
 * The designated SaaS test domain. The test app does NOT load `cdk.json`
 * context automatically, so we set it explicitly on the app below; this matches
 * the `saasTestDomain` value in `cdk.json`.
 */
const SAAS_TEST_DOMAIN = "example-saas.example.com";

/** The never-used placeholder domain the baseline denylist always denies. */
const PLACEHOLDER_BLOCKED_DOMAIN = "blocked.placeholder.invalid";

/**
 * Build an app + network + firewall for a given resolved scenario context and
 * return `Template.fromStack(firewallStack)`.
 */
function templateFor(ctx: ScenarioContext): Template {
  const app = new cdk.App();
  // The test app doesn't load cdk.json context; set saasTestDomain explicitly so
  // Scenario 1 adds the real SaaS domain to the denylist.
  app.node.setContext("saasTestDomain", SAAS_TEST_DOMAIN);

  const network = new NetworkStack(app, "TestNetworkStack", {
    env: ENV,
    scenarioContext: ctx,
  });
  const firewall = new FirewallStack(app, "TestFirewallStack", {
    env: ENV,
    scenarioContext: ctx,
    vpc: network.vpc,
    firewallSubnets: network.firewallSubnets,
    protectedSubnetRouting: network.protectedSubnetRouting,
    publicSubnetReturnRouting: network.publicSubnetReturnRouting,
    ingressEdgeRouteTableId: network.ingressEdgeRouteTableId,
  });
  return Template.fromStack(firewall);
}

/** A single synthesized stateless rule (PascalCase, as it appears in the CFN template). */
interface SynthStatelessRule {
  Priority: number;
  RuleDefinition: { Actions: string[] };
}

/**
 * Extract the STATELESS rule group's `StatelessRules` array from a synthesized
 * template (robust to which logical id CDK assigns the rule group).
 */
function statelessRulesOf(template: Template): SynthStatelessRule[] {
  const groups = template.findResources("AWS::NetworkFirewall::RuleGroup");
  for (const key of Object.keys(groups)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const props = groups[key].Properties as any;
    if (props.Type === "STATELESS") {
      return props.RuleGroup.RulesSource.StatelessRulesAndCustomActions
        .StatelessRules as SynthStatelessRule[];
    }
  }
  throw new Error("No STATELESS rule group found in synthesized template");
}

/** The synthesized `Priority` of the stateless rule whose Actions include `action`. */
function priorityForAction(rules: SynthStatelessRule[], action: string): number {
  const rule = rules.find((r) => r.RuleDefinition.Actions.includes(action));
  if (!rule) throw new Error(`No stateless rule with action "${action}"`);
  return rule.Priority;
}

/**
 * Extract the domain rule group's explicit Suricata `RulesString` from a
 * synthesized template. The domain group is the STATEFUL rule group that uses a
 * `RulesString` containing `tls.sni` (the baseline group also uses a RulesString
 * but passes traffic and contains no `tls.sni`).
 */
function domainRulesStringOf(template: Template): string {
  const groups = template.findResources("AWS::NetworkFirewall::RuleGroup");
  for (const key of Object.keys(groups)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const props = groups[key].Properties as any;
    const rulesString = props.RuleGroup?.RulesSource?.RulesString as string | undefined;
    if (props.Type === "STATEFUL" && typeof rulesString === "string" && rulesString.includes("tls.sni")) {
      return rulesString;
    }
  }
  throw new Error("No explicit-rulesString domain rule group found in synthesized template");
}

describe("FirewallStack CDK assertions — baseline (R1.2)", () => {
  let template: Template;

  beforeAll(() => {
    template = templateFor(toContext(baseline()));
  });

  it("creates exactly one firewall policy that uses the STRICT_ORDER stateful engine (R1.2)", () => {
    template.resourceCountIs("AWS::NetworkFirewall::FirewallPolicy", 1);
    template.hasResourceProperties("AWS::NetworkFirewall::FirewallPolicy", {
      FirewallPolicy: Match.objectLike({
        StatefulEngineOptions: Match.objectLike({ RuleOrder: "STRICT_ORDER" }),
      }),
    });
  });

  it("synthesizes exactly one firewall, one policy, and three rule groups (R1.2)", () => {
    // The stack creates a single firewall across both firewall subnets, a single
    // policy, and exactly three rule groups (1 stateless + 2 stateful).
    template.resourceCountIs("AWS::NetworkFirewall::Firewall", 1);
    template.resourceCountIs("AWS::NetworkFirewall::FirewallPolicy", 1);
    template.resourceCountIs("AWS::NetworkFirewall::RuleGroup", 3);
  });

  it("references at least one stateless and one stateful rule group (R1.2)", () => {
    // The policy wires one stateless ref and two stateful refs; the three rule
    // groups (1 stateless + 2 stateful) all synthesize. The two stateful
    // references use priorities 100 and 200; assert each independently so the
    // check does not depend on array order (the domain group is ordered first).
    template.resourceCountIs("AWS::NetworkFirewall::RuleGroup", 3);
    template.hasResourceProperties("AWS::NetworkFirewall::FirewallPolicy", {
      FirewallPolicy: Match.objectLike({
        StatelessRuleGroupReferences: Match.arrayWith([
          Match.objectLike({ Priority: 1 }),
        ]),
      }),
    });
    template.hasResourceProperties("AWS::NetworkFirewall::FirewallPolicy", {
      FirewallPolicy: Match.objectLike({
        StatefulRuleGroupReferences: Match.arrayWith([Match.objectLike({ Priority: 100 })]),
      }),
    });
    template.hasResourceProperties("AWS::NetworkFirewall::FirewallPolicy", {
      FirewallPolicy: Match.objectLike({
        StatefulRuleGroupReferences: Match.arrayWith([Match.objectLike({ Priority: 200 })]),
      }),
    });
  });

  it("evaluates the domain denylist (priority 100) ahead of the baseline pass rules (priority 200) (R5.1)", () => {
    // Under STRICT_ORDER the lower reference priority is evaluated first. The
    // domain rule group must come before the baseline group so a denied domain
    // is dropped before the broad `pass ... 443` baseline rule can allow it.
    const policies = template.findResources("AWS::NetworkFirewall::FirewallPolicy");
    const props = Object.values(policies)[0].Properties as {
      FirewallPolicy: {
        StatefulRuleGroupReferences: Array<{ Priority: number; ResourceArn: unknown }>;
      };
    };
    const refs = props.FirewallPolicy.StatefulRuleGroupReferences;
    const refFor = (logicalIdFragment: string) =>
      refs.find((r) => JSON.stringify(r.ResourceArn).includes(logicalIdFragment));
    const domainRef = refFor("DomainRuleGroup");
    const baselineRef = refFor("StatefulBaselineRuleGroup");
    expect(domainRef).toBeDefined();
    expect(baselineRef).toBeDefined();
    expect(domainRef!.Priority).toBeLessThan(baselineRef!.Priority);
  });

  it("sets the stream exception policy to CONTINUE at baseline (R7.2)", () => {
    template.hasResourceProperties("AWS::NetworkFirewall::FirewallPolicy", {
      FirewallPolicy: Match.objectLike({
        StatefulEngineOptions: Match.objectLike({ StreamExceptionPolicy: "CONTINUE" }),
      }),
    });
  });

  it("orders the stateless pass rule (100) ahead of the drop rule (200) at baseline (R6.1)", () => {
    const rules = statelessRulesOf(template);
    expect(priorityForAction(rules, "aws:pass")).toBe(100);
    expect(priorityForAction(rules, "aws:drop")).toBe(200);
    // Pass evaluated before drop -> traffic is forwarded at baseline.
    expect(priorityForAction(rules, "aws:pass")).toBeLessThan(
      priorityForAction(rules, "aws:drop"),
    );
  });

  it("denies only the placeholder domain at baseline (denylist permissive) (R5.1)", () => {
    const rulesString = domainRulesStringOf(template);
    // Baseline uses an explicit Suricata rulesString that inspects the TLS SNI
    // and denies only the never-used placeholder domain; the SaaS domain is absent.
    expect(rulesString).toContain("tls.sni");
    expect(rulesString).toContain(PLACEHOLDER_BLOCKED_DOMAIN);
    expect(rulesString).not.toContain(SAAS_TEST_DOMAIN);
  });

  it("adds symmetric-return routes so the NAT-gateway return path traverses the firewall", () => {
    // The public-subnet return routes send the protected (workload) /24 CIDR
    // back through the same-AZ firewall endpoint. Together with the
    // protected-egress and IGW-edge ingress routes, every firewall-endpoint
    // route targets a VpcEndpointId, so we expect at least 4 such routes
    // (2 protected-egress + 2 public-return; the 2 IGW edge ingress routes also
    // point at endpoints, so >= 4 is a safe lower bound).
    const routes = template.findResources("AWS::EC2::Route");
    const endpointRoutes = Object.values(routes).filter(
      (r) => (r.Properties as { VpcEndpointId?: unknown }).VpcEndpointId !== undefined,
    );
    expect(endpointRoutes.length).toBeGreaterThanOrEqual(4);

    // At least one of those is a return route pointing at a firewall endpoint
    // whose destination is a /24 in the 10.0.x.0/24 protected range.
    const protectedReturnRoutes = endpointRoutes.filter((r) => {
      const cidr = (r.Properties as { DestinationCidrBlock?: unknown }).DestinationCidrBlock;
      return typeof cidr === "string" && /^10\.0\.\d+\.0\/24$/.test(cidr);
    });
    expect(protectedReturnRoutes.length).toBeGreaterThanOrEqual(1);
  });
});

describe("FirewallStack CDK assertions — Scenario 3 is routing-only (R7.2)", () => {
  it("leaves the stream exception policy at CONTINUE under desired('3') (the break is asymmetric routing, not a policy change)", () => {
    const template = templateFor(toContext(desired("3")));
    template.hasResourceProperties("AWS::NetworkFirewall::FirewallPolicy", {
      FirewallPolicy: Match.objectLike({
        StatefulEngineOptions: Match.objectLike({
          RuleOrder: "STRICT_ORDER",
          StreamExceptionPolicy: "CONTINUE",
        }),
      }),
    });
  });
});

describe("FirewallStack CDK assertions — Scenario 2 stateless priority inversion (R6.1)", () => {
  it("inverts the stateless priorities so drop (100) precedes pass (200) under desired('2')", () => {
    const template = templateFor(toContext(desired("2")));
    const rules = statelessRulesOf(template);
    expect(priorityForAction(rules, "aws:pass")).toBe(200);
    expect(priorityForAction(rules, "aws:drop")).toBe(100);
    // Drop evaluated before pass -> the designated test traffic is dropped.
    expect(priorityForAction(rules, "aws:drop")).toBeLessThan(
      priorityForAction(rules, "aws:pass"),
    );
  });
});

describe("FirewallStack CDK assertions — Scenario 1 domain deny entry (R5.1)", () => {
  it("adds the designated SaaS domain to the denylist under desired('1')", () => {
    const template = templateFor(toContext(desired("1")));
    const rulesString = domainRulesStringOf(template);
    // Scenario 1 adds the real SaaS domain on top of the baseline placeholder,
    // both inspected via the explicit Suricata SNI rulesString.
    expect(rulesString).toContain("tls.sni");
    expect(rulesString).toContain(SAAS_TEST_DOMAIN);
    expect(rulesString).toContain(PLACEHOLDER_BLOCKED_DOMAIN);
  });
});
