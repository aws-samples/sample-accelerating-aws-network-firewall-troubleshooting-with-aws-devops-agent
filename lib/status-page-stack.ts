/**
 * StatusPageStack — an internet-facing Application Load Balancer that fronts the
 * workload's live status page.
 *
 * The workload EC2 instance runs a tiny HTTP server (see `lib/workload-stack.ts`
 * `buildHealthCheckUserData`) on {@link STATUS_PAGE_PORT} that renders one
 * green/red card per scenario from the health-check daemon's `status.json`,
 * behind a styled in-page login (signed session cookie). This stack puts a
 * public ALB in the network stack's PUBLIC subnets, forwards HTTP :80 to that
 * server, and fronts the ALB with an Amazon CloudFront distribution so the page
 * is served to the browser over HTTPS (the `*.cloudfront.net` URL).
 *
 * ────────────────────────────────────────────────────────────────────────────
 * SECURITY NOTE.
 * ────────────────────────────────────────────────────────────────────────────
 * The page is gated by a single shared login (session cookie) and exposes only
 * scenario names, a green/red state, and a webhook-config form (which writes to
 * AWS Secrets Manager but never shows the stored secret). CloudFront serves HTTPS,
 * but the CloudFront-to-ALB origin hop is plain HTTP and the credential is a
 * low-assurance shared one, so do not reuse a real password. For anything beyond
 * a short-lived sample, restrict `allowedCidr` to a specific IP or range (the
 * `statusPageAllowedCidr` context value) and put a custom domain + ACM
 * certificate on the origin. The page password is always generated in AWS
 * Secrets Manager at deploy.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * NO cross-stack dependency cycle.
 * ────────────────────────────────────────────────────────────────────────────
 * This stack consumes the VPC + public subnets (network stack) and the workload
 * instance + its security group (workload stack), so its only dependency edges
 * are status-page -> network and status-page -> workload. The ALB -> instance
 * ingress rule is created HERE as a standalone `AWS::EC2::SecurityGroupIngress`
 * (referencing the workload SG by id) rather than by calling `addIngressRule`
 * on the workload SG — calling it on the workload SG would create the rule in
 * the WORKLOAD stack and make it depend back on this stack's ALB SG, closing a
 * cycle. Creating the rule in this stack keeps the edges one-directional.
 */
import * as cdk from "aws-cdk-lib";
import { Tags } from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as elbv2_targets from "aws-cdk-lib/aws-elasticloadbalancingv2-targets";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import { Construct } from "constructs";

import { PROJECT_TAG_KEY, PROJECT_TAG_VALUE } from "./network-stack";
import { STATUS_PAGE_PORT } from "./workload-stack";

/**
 * Props for {@link StatusPageStack}. Takes the VPC + public subnets from the
 * network stack and the workload instance + its security group from the
 * workload stack.
 */
export interface StatusPageStackProps extends cdk.StackProps {
  /** The Sample_VPC the ALB attaches to (from the network stack). */
  readonly vpc: ec2.IVpc;
  /** The PUBLIC subnets (one per AZ) the internet-facing ALB places its nodes in. */
  readonly publicSubnets: ec2.ISubnet[];
  /** The workload EC2 instance the ALB targets (from the workload stack). */
  readonly workloadInstance: ec2.Instance;
  /** The workload's security group — this stack opens it to the ALB on {@link STATUS_PAGE_PORT}. */
  readonly workloadSecurityGroup: ec2.ISecurityGroup;
  /**
   * CIDR allowed to reach the public status page on :80. Defaults to
   * `0.0.0.0/0` (open to the internet — see the SECURITY NOTE). Set the
   * `statusPageAllowedCidr` context value to lock it to your own IP/range.
   */
  readonly allowedCidr?: string;
}

/**
 * The status-page ALB stack. Exposes the load balancer, its public DNS name,
 * and the ALB security group.
 */
export class StatusPageStack extends cdk.Stack {
  /** The internet-facing Application Load Balancer fronting the status page. */
  public readonly loadBalancer: elbv2.ApplicationLoadBalancer;
  /** The ALB's public DNS name (surfaced as a CfnOutput — the status page URL). */
  public readonly loadBalancerDnsName: string;
  /** The ALB's security group (the source the workload SG is opened to). */
  public readonly albSecurityGroup: ec2.SecurityGroup;
  /** CloudFront distribution fronting the ALB so the status page is served over HTTPS. */
  public readonly distribution: cloudfront.Distribution;
  /** The CloudFront domain name (the HTTPS status-page URL). */
  public readonly distributionDomainName: string;

  constructor(scope: Construct, id: string, props: StatusPageStackProps) {
    super(scope, id, props);

    const allowedCidr = props.allowedCidr ?? "0.0.0.0/0";

    // ALB security group: it forwards to the workload, so it needs all egress.
    this.albSecurityGroup = new ec2.SecurityGroup(this, "StatusPageAlbSg", {
      vpc: props.vpc,
      description: "Status-page ALB: HTTP :80 from CloudFront only, forwards to the workload",
      allowAllOutbound: true,
    });

    // Inbound :80 is restricted to Amazon CloudFront's origin-facing IP ranges
    // (the AWS-managed prefix list), NOT to 0.0.0.0/0. Browsers reach the page
    // over the HTTPS CloudFront URL, and CloudFront connects to the ALB from
    // these ranges, so this keeps the ALB off the open internet while leaving
    // the CloudFront path fully working. The prefix-list ID is region-specific;
    // the map below covers the sample's supported Regions, and an override is
    // available via the `cloudFrontPrefixListId` context value for any other
    // Region (find it with: aws ec2 describe-managed-prefix-lists --filters
    // Name=prefix-list-name,Values=com.amazonaws.global.cloudfront.origin-facing).
    const region = cdk.Stack.of(this).region;
    const CLOUDFRONT_ORIGIN_FACING_PL: Record<string, string> = {
      "us-east-1": "pl-3b927c52",
      "us-west-2": "pl-82a045eb",
    };
    const plOverride = this.node.tryGetContext("cloudFrontPrefixListId") as string | undefined;
    const cfPrefixListId = plOverride ?? CLOUDFRONT_ORIGIN_FACING_PL[region];
    if (cfPrefixListId) {
      this.albSecurityGroup.addIngressRule(
        ec2.Peer.prefixList(cfPrefixListId),
        ec2.Port.tcp(80),
        "HTTP from Amazon CloudFront origin-facing ranges (managed prefix list)",
      );
    } else {
      // Unknown Region and no override: fall back to the operator CIDR so the
      // deploy still works, and warn loudly to set the prefix list for lockdown.
      cdk.Annotations.of(this).addWarning(
        `No CloudFront origin-facing prefix list known for Region ${region}. ` +
          "The ALB will allow the configured allowedCidr instead. Set the " +
          "'cloudFrontPrefixListId' context value to lock the ALB to CloudFront.",
      );
      this.albSecurityGroup.addIngressRule(
        ec2.Peer.ipv4(allowedCidr),
        ec2.Port.tcp(80),
        "HTTP to the status page (no CloudFront prefix list for this Region)",
      );
    }
    // When a prefix list IS applied, an explicitly narrowed allowedCidr is added
    // as an ADDITIONAL rule for direct ALB testing. Locking the ALB to your own
    // IP alone would break CloudFront (the ALB sees CloudFront's IPs, not yours).
    if (cfPrefixListId && allowedCidr !== "0.0.0.0/0") {
      this.albSecurityGroup.addIngressRule(
        ec2.Peer.ipv4(allowedCidr),
        ec2.Port.tcp(80),
        "Additional operator-allowed CIDR (direct ALB access for testing)",
      );
    }

    // The internet-facing ALB, one node per public subnet (two AZs).
    this.loadBalancer = new elbv2.ApplicationLoadBalancer(this, "StatusPageAlb", {
      vpc: props.vpc,
      internetFacing: true,
      vpcSubnets: { subnets: props.publicSubnets },
      securityGroup: this.albSecurityGroup,
    });

    // Open the workload SG to the ALB SG on the status-page port. Created in
    // THIS stack (see the header) so the dependency edge stays status-page ->
    // workload and no cycle forms.
    new ec2.CfnSecurityGroupIngress(this, "WorkloadFromAlbIngress", {
      groupId: props.workloadSecurityGroup.securityGroupId,
      sourceSecurityGroupId: this.albSecurityGroup.securityGroupId,
      ipProtocol: "tcp",
      fromPort: STATUS_PAGE_PORT,
      toPort: STATUS_PAGE_PORT,
      description: "Allow the status-page ALB to reach the workload status server",
    });

    // HTTP :80 listener forwarding to the instance on the status-page port. We
    // manage the ALB SG ourselves, so `open: false` keeps CDK from adding a
    // second 0.0.0.0/0 rule.
    const listener = this.loadBalancer.addListener("HttpListener", {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      open: false,
    });

    // Instance target on the status-page port, health-checked on /healthz.
    listener.addTargets("WorkloadTarget", {
      port: STATUS_PAGE_PORT,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targets: [new elbv2_targets.InstanceTarget(props.workloadInstance, STATUS_PAGE_PORT)],
      healthCheck: {
        path: "/healthz",
        port: String(STATUS_PAGE_PORT),
        healthyHttpCodes: "200",
      },
    });

    this.loadBalancerDnsName = this.loadBalancer.loadBalancerDnsName;

    // ── CloudFront in front of the ALB so the page is served over HTTPS ──
    // This sample's ALB has no TLS certificate (no domain to validate one against),
    // and modern browsers force https:// on a bare hostname, which would fail
    // against an HTTP-only ALB. CloudFront gives a working HTTPS *.cloudfront.net
    // URL with its default certificate and no domain to manage. The origin hop
    // (CloudFront -> ALB) is HTTP, which is acceptable for this sample; lock it
    // down with a custom domain + ACM cert for anything beyond a short sample.
    //
    // The page is dynamic and cookie-authenticated, so caching is disabled.
    // Rather than forwarding every viewer header (ALL_VIEWER), forward only what
    // the origin actually needs: all cookies (the session cookie) and a minimal
    // set of headers. This narrows what reaches the origin without breaking auth
    // or the login/webhook-config POSTs.
    const originRequestPolicy = new cloudfront.OriginRequestPolicy(this, "StatusPageOriginPolicy", {
      comment: "Status page: forward session cookie and minimal headers only",
      cookieBehavior: cloudfront.OriginRequestCookieBehavior.all(),
      headerBehavior: cloudfront.OriginRequestHeaderBehavior.allowList(
        "Host",
        "Origin",
        "Referer",
      ),
      queryStringBehavior: cloudfront.OriginRequestQueryStringBehavior.none(),
    });
    this.distribution = new cloudfront.Distribution(this, "StatusPageCdn", {
      comment: "AWS Network Firewall status page (HTTPS in front of the HTTP ALB)",
      defaultBehavior: {
        origin: new origins.LoadBalancerV2Origin(this.loadBalancer, {
          protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
          httpPort: 80,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy,
      },
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
    });
    this.distributionDomainName = this.distribution.distributionDomainName;

    // Tag every resource in the stack for the teardown sweep (Requirement 10).
    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);
  }
}
