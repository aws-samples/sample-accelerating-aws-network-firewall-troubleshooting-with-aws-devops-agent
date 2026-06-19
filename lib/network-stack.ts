/**
 * NetworkStack — the `Sample_VPC` and its routing fabric (Requirement 1).
 *
 * Builds a standard AWS Network Firewall "distributed" topology across two
 * Availability Zones (two AZs are required so Scenario 3 / Requirement 7 can
 * route a flow through a firewall endpoint that never observed the SYN):
 *
 *   - 1 Amazon VPC (Amazon Virtual Private Cloud), `10.0.0.0/16`
 *   - per AZ: a PUBLIC subnet (hosts a NAT gateway, default route -> IGW),
 *             a FIREWALL subnet (hosts the NF endpoint, default route -> NAT),
 *             a PROTECTED subnet (hosts the test workload, default route -> NF
 *             endpoint — added later by the firewall stack, see contract below)
 *   - 1 Internet Gateway
 *   - 2 NAT gateways (one per AZ)
 *   - an IGW edge (ingress) route table for symmetric return traffic
 *   - AWS Systems Manager (SSM) interface VPC endpoints (ssm / ssmmessages / ec2messages) in the
 *     protected subnets so SSM control traffic bypasses the firewall
 *
 * Baseline routing (per AZ, symmetric):
 *
 *   | Route table         | Destination          | Target                       |
 *   |---------------------|----------------------|------------------------------|
 *   | Protected subnet    | 0.0.0.0/0            | Firewall endpoint (same AZ)  |  <- added by firewall stack
 *   | Firewall subnet     | 0.0.0.0/0            | NAT gateway (same AZ)        |  <- L2 PRIVATE_WITH_EGRESS
 *   | Public subnet       | 0.0.0.0/0            | Internet gateway             |  <- L2 PUBLIC
 *   | IGW ingress (edge)  | Protected subnet CIDR| Firewall endpoint (same AZ)  |  <- added by firewall stack
 *
 * ────────────────────────────────────────────────────────────────────────────
 * CHICKEN-AND-EGG CONTRACT (read this before consuming the stack)
 * ────────────────────────────────────────────────────────────────────────────
 * The protected subnet's `0.0.0.0/0` route and the IGW edge route must target
 * the **Network Firewall VPC endpoint**, but that endpoint only exists after the
 * firewall stack (task 7) creates the `CfnFirewall`, and the firewall stack
 * depends on THIS stack (it needs the firewall subnet ids). To avoid a
 * cross-stack circular dependency this stack deliberately does NOT:
 *   - create the `CfnFirewall`, and
 *   - reference any firewall resource.
 *
 * Instead it leaves the protected subnets ISOLATED (no `0.0.0.0/0` route) and
 * exposes everything the firewall stack needs to add the routes **in the
 * firewall stack's own scope** (so the only cross-stack dependency direction is
 * firewall -> network). The firewall stack, once it has the endpoint ids, does:
 *
 *   for (const r of network.protectedSubnetRouting) {
 *     // egress: 0.0.0.0/0 -> firewall endpoint in r.firewallEndpointAz
 *     //   (== r.availabilityZone at baseline; the OTHER AZ when asymmetricRoute)
 *     new ec2.CfnRoute(this, `ProtectedEgress-${r.availabilityZone}`, {
 *       routeTableId: r.routeTableId,
 *       destinationCidrBlock: "0.0.0.0/0",
 *       vpcEndpointId: endpointIdForAz(r.firewallEndpointAz),
 *     });
 *     // ingress (symmetric return): r.cidr -> firewall endpoint in r.availabilityZone
 *     //   (always same-AZ; the asymmetry in Scenario 3 lives only on egress)
 *     new ec2.CfnRoute(this, `IngressEdge-${r.availabilityZone}`, {
 *       routeTableId: network.ingressEdgeRouteTableId,
 *       destinationCidrBlock: r.cidr,
 *       vpcEndpointId: endpointIdForAz(r.availabilityZone),
 *     });
 *   }
 *
 * (CfnFirewall exposes `attrEndpointIds` as a list of `"<az>:<vpce-id>"` strings;
 * the firewall stack splits those to resolve `endpointIdForAz`.)
 *
 * The stack synthesizes standalone (its test in task 6.2 calls
 * `Template.fromStack(this)` on it alone) because it references no other stack.
 */
import * as cdk from "aws-cdk-lib";
import { Tags } from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import { Construct } from "constructs";
import { ScenarioContext } from "../src/scenarioctl/state";

/** The project-wide tag value used for teardown sweeps (design Decision 3). */
export const PROJECT_TAG_KEY = "Project";
export const PROJECT_TAG_VALUE = "nf-devops-agent";

/** Default VPC CIDR for the `Sample_VPC`. */
const DEFAULT_VPC_CIDR = "10.0.0.0/16";
/** Two AZs are mandatory for Scenario 3 (asymmetric routing). */
const DEFAULT_MAX_AZS = 2;

/** Subnet group names — also used by downstream stacks via `selectSubnets`. */
export const PUBLIC_SUBNET_GROUP = "public";
export const FIREWALL_SUBNET_GROUP = "firewall";
export const PROTECTED_SUBNET_GROUP = "protected";
/**
 * Dedicated subnet tier for the status-page ALB. This tier is OUT OF BAND of the
 * firewall: its route table carries NO return route to the protected CIDRs, so
 * ALB-to-workload management traffic (the :8080 status-page health check) always
 * uses the VPC `local` route and never traverses a firewall endpoint. The NAT
 * gateways live in {@link PUBLIC_SUBNET_GROUP}, which DOES carry the firewall
 * return route (needed for Scenario 1 SNI inspection). Keeping the ALB in its
 * own tier means breaking any scenario — including Scenario 3, which drops all
 * firewall egress — can never take the status page itself offline. This mirrors
 * how SSM/Amazon CloudWatch traffic is kept out of band via interface endpoints.
 */
export const ALB_SUBNET_GROUP = "alb";

/**
 * Per-protected-subnet routing contract consumed by the firewall stack (task 7)
 * to wire the firewall-endpoint routes (see the CHICKEN-AND-EGG CONTRACT above).
 */
export interface ProtectedSubnetRouting {
  /** The protected (isolated) subnet hosting the test workload. */
  readonly subnet: ec2.ISubnet;
  /** The AZ this protected subnet lives in. */
  readonly availabilityZone: string;
  /** This subnet's IPv4 CIDR — destination for the IGW edge (ingress) route. */
  readonly cidr: string;
  /**
   * The protected subnet's route table id. The firewall stack adds the
   * `0.0.0.0/0` -> firewall endpoint route here.
   */
  readonly routeTableId: string;
  /**
   * The AZ whose firewall endpoint the protected subnet's EGRESS default route
   * must target. Equals {@link availabilityZone} at baseline (symmetric); the
   * OTHER AZ when `asymmetricRoute` is set (Scenario 3 / Requirement 7.1). The
   * INGRESS edge route always targets {@link availabilityZone} (symmetric
   * return), so the asymmetry lives only on the egress path.
   */
  readonly firewallEndpointAz: string;
}

/**
 * Per-return-route contract consumed by the firewall stack to wire the
 * NAT-gateway return path through a firewall endpoint.
 *
 * Outbound traffic flows workload -> firewall endpoint -> NAT -> IGW, but the
 * RETURN hop from the NAT gateway back to the workload would otherwise use the
 * public subnet's `local` route and BYPASS the firewall, leaving the stateful
 * engine seeing only one direction (logs `app_proto:unknown`, `tls.sni` rules
 * never match). To fix this, the PUBLIC subnet that hosts the NAT gateway
 * handling a workload's egress must send traffic destined for that workload's
 * PROTECTED CIDR back through a firewall endpoint.
 *
 * One entry is produced PER PROTECTED SUBNET (not per public subnet). For each
 * protected subnet, the return route is:
 *   - PLACED in the public subnet of the AZ where that subnet's egress actually
 *     exits (`firewallEndpointAz` — same AZ at baseline, the OTHER AZ under
 *     Scenario 3), because that is where the NAT gateway handling the flow's
 *     return traffic lives, and
 *   - TARGETED at the protected subnet's OWN-AZ firewall endpoint
 *     ({@link endpointAz} == the subnet's own AZ).
 *
 * At baseline these two AZs are identical, so egress and return both traverse
 * the same-AZ endpoint (symmetric — required for Scenario 1's TLS SNI
 * inspection). Under Scenario 3 the egress flips to the OTHER AZ's endpoint
 * while the return still targets the own-AZ endpoint, so egress and return
 * traverse DIFFERENT endpoints. The own-AZ endpoint never observed the flow's
 * SYN, so the `DROP` stream exception policy discards the mid-flow return
 * packets. That asymmetry is exactly Scenario 3's failure condition.
 */
export interface PublicSubnetReturnRouting {
  /**
   * The route table id of the PUBLIC subnet hosting the NAT gateway that
   * handles this protected subnet's egress (the public subnet in
   * `firewallEndpointAz`). The firewall stack adds the return route here.
   */
  readonly routeTableId: string;
  /** The protected subnet's IPv4 CIDR — destination for the return route. */
  readonly protectedCidr: string;
  /**
   * The AZ whose firewall endpoint the return route TARGETS — always the
   * protected subnet's OWN AZ. At baseline this equals the egress AZ (symmetric);
   * under Scenario 3 it differs from the egress AZ, so a flow's SYN exits via one
   * endpoint and its return arrives at a different endpoint that never saw the
   * SYN. The handshake never completes and egress is dropped.
   */
  readonly endpointAz: string;
}

/**
 * Props for {@link NetworkStack}.
 *
 * The scenario context is accepted as a prop (preferred, for testability — the
 * app entry resolves context once and passes it down) but the stack also falls
 * back to reading `asymmetricRoute` directly from CDK context so it behaves
 * correctly when synthesized standalone.
 */
export interface NetworkStackProps extends cdk.StackProps {
  /** Resolved scenario context (from `state.ts` `toContext`). Optional. */
  readonly scenarioContext?: ScenarioContext;
  /** Override the VPC CIDR. Defaults to `10.0.0.0/16`. */
  readonly vpcCidr?: string;
  /** Override the AZ count. Defaults to 2 (do not lower below 2). */
  readonly maxAzs?: number;
}

/**
 * The `Sample_VPC` network stack. Exposes the VPC, the three subnet tiers, the
 * NAT/IGW handles, the IGW edge route table id, and the per-protected-subnet
 * routing contract the firewall stack uses to wire firewall-endpoint routes.
 */
export class NetworkStack extends cdk.Stack {
  /** The Sample_VPC (`IVpc`) downstream stacks attach resources to. */
  public readonly vpc: ec2.Vpc;
  /** Firewall subnets (one per AZ). The firewall stack maps the NF endpoint into these. */
  public readonly firewallSubnets: ec2.ISubnet[];
  /** Protected subnets (one per AZ). The test workload runs in `protectedSubnets[0]`. */
  public readonly protectedSubnets: ec2.ISubnet[];
  /** Public subnets (one per AZ). Each hosts a NAT gateway. */
  public readonly publicSubnets: ec2.ISubnet[];
  /**
   * Dedicated ALB subnets (one per AZ), OUT OF BAND of the firewall. The
   * status-page ALB lives here so its management traffic to the workload never
   * traverses a firewall endpoint and the page stays up while a scenario breaks
   * firewall egress.
   */
  public readonly albSubnets: ec2.ISubnet[];
  /** True while Scenario 3 (Requirement 7) is active — egress routes flip cross-AZ. */
  public readonly asymmetricRoute: boolean;
  /**
   * Route table id for the IGW edge (ingress) association. The firewall stack
   * adds the `protected-CIDR -> firewall endpoint (same AZ)` routes here for
   * symmetric return traffic.
   */
  public readonly ingressEdgeRouteTableId: string;
  /** Per-protected-subnet routing contract for the firewall stack. */
  public readonly protectedSubnetRouting: ProtectedSubnetRouting[];
  /** Per-public-subnet return-routing contract for the firewall stack (symmetric NAT return). */
  public readonly publicSubnetReturnRouting: PublicSubnetReturnRouting[];
  /** The SSM interface endpoints (so traffic bypasses the firewall). */
  public readonly ssmEndpoints: ec2.InterfaceVpcEndpoint[];

  constructor(scope: Construct, id: string, props?: NetworkStackProps) {
    super(scope, id, props);

    // Resolve asymmetricRoute: prefer the resolved prop, fall back to context,
    // then default false. Tolerate a string "true"/"false" coming from context.
    const ctxAsymmetric = this.node.tryGetContext("asymmetricRoute");
    const rawAsymmetric = props?.scenarioContext?.asymmetricRoute ?? ctxAsymmetric ?? false;
    this.asymmetricRoute = rawAsymmetric === true || rawAsymmetric === "true";

    const maxAzs = props?.maxAzs ?? DEFAULT_MAX_AZS;

    // L2 VPC with three subnet tiers. The tier subnet TYPES give us most of the
    // baseline routing for free:
    //   PUBLIC               -> 0.0.0.0/0 to the IGW, and hosts the NAT gateways
    //   PRIVATE_WITH_EGRESS  -> 0.0.0.0/0 to the same-AZ NAT (the firewall tier)
    //   PRIVATE_ISOLATED     -> NO default route (the protected tier); the
    //                           firewall stack adds 0.0.0.0/0 -> NF endpoint.
    this.vpc = new ec2.Vpc(this, "SampleVpc", {
      ipAddresses: ec2.IpAddresses.cidr(props?.vpcCidr ?? DEFAULT_VPC_CIDR),
      maxAzs: maxAzs,
      natGateways: maxAzs, // one NAT gateway per AZ (lives in the public subnets)
      // NAT gateways must land in the PUBLIC tier (which carries the firewall
      // return route), NOT the out-of-band ALB tier.
      natGatewaySubnets: { subnetGroupName: PUBLIC_SUBNET_GROUP },
      subnetConfiguration: [
        { name: PUBLIC_SUBNET_GROUP, subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
        { name: FIREWALL_SUBNET_GROUP, subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS, cidrMask: 24 },
        { name: PROTECTED_SUBNET_GROUP, subnetType: ec2.SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
        // Dedicated ALB tier, appended LAST so CDK assigns it new CIDRs
        // (10.0.6.0/24, 10.0.7.0/24) without renumbering the existing tiers (no
        // VPC replacement). PUBLIC subnetType so it has its own 0.0.0.0/0 -> IGW
        // route and an internet-facing ALB can place nodes here, but its route
        // table carries NO firewall return route (out of band).
        { name: ALB_SUBNET_GROUP, subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
      ],
    });

    // Resolve the tiers (returned in AZ order).
    this.publicSubnets = this.vpc.selectSubnets({ subnetGroupName: PUBLIC_SUBNET_GROUP }).subnets;
    this.firewallSubnets = this.vpc.selectSubnets({ subnetGroupName: FIREWALL_SUBNET_GROUP }).subnets;
    this.protectedSubnets = this.vpc.selectSubnets({ subnetGroupName: PROTECTED_SUBNET_GROUP }).subnets;
    this.albSubnets = this.vpc.selectSubnets({ subnetGroupName: ALB_SUBNET_GROUP }).subnets;

    // AZ list as ordered by the firewall tier — defines where NF endpoints exist.
    const firewallAzs = this.firewallSubnets.map((s) => s.availabilityZone);

    // IGW edge (ingress) route table + association. Routes (protected CIDR ->
    // firewall endpoint same AZ) are added later by the firewall stack; the
    // table + edge association are created here because they only depend on the
    // IGW (created by the L2 VPC), not on the firewall.
    const edgeRouteTable = new ec2.CfnRouteTable(this, "IngressEdgeRouteTable", {
      vpcId: this.vpc.vpcId,
      tags: [{ key: "Name", value: `${id}/IngressEdgeRouteTable` }],
    });
    if (this.vpc.internetGatewayId) {
      new ec2.CfnGatewayRouteTableAssociation(this, "IngressEdgeAssociation", {
        gatewayId: this.vpc.internetGatewayId,
        routeTableId: edgeRouteTable.ref,
      });
    }
    this.ingressEdgeRouteTableId = edgeRouteTable.ref;

    // Build the per-protected-subnet routing contract (egress endpoint AZ flips
    // cross-AZ when asymmetricRoute is set; ingress stays same-AZ).
    this.protectedSubnetRouting = this.protectedSubnets.map((subnet, i) => {
      const sameAz = firewallAzs[i];
      const otherAz = firewallAzs[(i + 1) % firewallAzs.length];
      return {
        subnet,
        availabilityZone: subnet.availabilityZone,
        cidr: subnet.ipv4CidrBlock,
        routeTableId: subnet.routeTable.routeTableId,
        firewallEndpointAz: this.asymmetricRoute ? otherAz : sameAz,
      };
    });

    // Build the per-protected-subnet return-routing contract. For each PROTECTED
    // subnet we add a return route that sends traffic destined for that subnet's
    // CIDR back through a firewall endpoint, so the NAT-to-workload return hop
    // traverses the firewall and the stateful engine sees both directions.
    //
    // The route is PLACED in the public subnet of the egress AZ (where the NAT
    // gateway handling this flow lives — `firewallEndpointAz`, which flips
    // cross-AZ under Scenario 3) and TARGETS the protected subnet's OWN-AZ
    // firewall endpoint. At baseline these AZs match, so egress and return use
    // the same endpoint (symmetric — required for Scenario 1 SNI inspection).
    // Under Scenario 3 the egress endpoint (other AZ) and the return endpoint
    // (own AZ) differ, so the own-AZ endpoint never saw the SYN and the `DROP`
    // stream exception discards the return packets. That is Scenario 3's
    // asymmetric-flow failure.
    const publicSubnetByAz = new Map<string, ec2.ISubnet>();
    this.publicSubnets.forEach((s) => publicSubnetByAz.set(s.availabilityZone, s));
    this.publicSubnetReturnRouting = this.protectedSubnetRouting.map((r) => {
      const egressPublicSubnet = publicSubnetByAz.get(r.firewallEndpointAz);
      if (!egressPublicSubnet) {
        throw new Error(
          `No public subnet found in egress AZ "${r.firewallEndpointAz}" for return routing of ${r.cidr}`,
        );
      }
      return {
        routeTableId: egressPublicSubnet.routeTable.routeTableId,
        protectedCidr: r.cidr,
        endpointAz: r.availabilityZone,
      };
    });

    // SSM interface VPC endpoints in the protected subnets so SSM control
    // traffic (Session Manager / RunCommand probe) bypasses the firewall and
    // stays reachable even while egress through the firewall is deliberately
    // broken. The CloudWatch (`monitoring`) endpoint is included for the SAME
    // reason: the health-check daemon publishes its per-scenario custom metrics
    // via `cloudwatch:PutMetricData`, and that call MUST succeed even when the
    // active scenario drops all firewall egress (most importantly Scenario 3,
    // whose asymmetric routing breaks every flow through the firewall). Routing
    // metric traffic over an interface endpoint keeps the MONITORING path up
    // while the DATA path is broken, so the alarm still fires and the daemon
    // loop never wedges on a hung publish. `open: true` provisions an SG
    // allowing 443 from the VPC CIDR.
    const ssmServices: Array<{ id: string; service: ec2.InterfaceVpcEndpointAwsService }> = [
      { id: "Ssm", service: ec2.InterfaceVpcEndpointAwsService.SSM },
      { id: "SsmMessages", service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES },
      { id: "Ec2Messages", service: ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES },
      { id: "Monitoring", service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING },
    ];
    this.ssmEndpoints = ssmServices.map((e) =>
      this.vpc.addInterfaceEndpoint(`${e.id}Endpoint`, {
        service: e.service,
        subnets: { subnets: this.protectedSubnets },
        privateDnsEnabled: true,
        open: true,
      }),
    );

    // Tag every resource in the stack for the teardown sweep (Requirement 10).
    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);

    // ── Migration shim: retain the public-subnet AWS CloudFormation exports ──
    // The status-page ALB moved from the public subnets to the dedicated ALB
    // subnets. CloudFormation refuses to drop an export while another stack
    // still imports it, which deadlocks the cross-stack update (network wants to
    // remove the auto-generated public-subnet exports, but the not-yet-updated
    // status-page stack still imports them). Re-declaring those exports under
    // their EXACT original auto-generated names keeps them published during the
    // transition so both stacks can update. Harmless to keep; removable in a
    // later cleanup once no stack imports them.
    this.exportValue(this.publicSubnets[0].subnetId, {
      name: "NfNetworkStack:ExportsOutputRefSampleVpcpublicSubnet1Subnet95A2D897B46D678D",
    });
    this.exportValue(this.publicSubnets[1].subnetId, {
      name: "NfNetworkStack:ExportsOutputRefSampleVpcpublicSubnet2SubnetEB9F2FDCC577CFA0",
    });
  }
}
