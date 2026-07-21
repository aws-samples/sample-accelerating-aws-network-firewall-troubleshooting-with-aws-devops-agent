# Security notes

This repository is a **sample** that deploys a short-lived AWS Network Firewall
environment to demonstrate incident response with AWS DevOps Agent. It is built
to be stood up, exercised, and torn down the same day. Several components are
intentionally demo-grade and should be hardened before any pattern here is
adapted for a persistent or production deployment.

## Reporting a security issue

Do not open a public GitHub issue for security problems. Follow the
[AWS vulnerability reporting](https://aws.amazon.com/security/vulnerability-reporting/)
process instead.

## Things to set before deploying

- **Lock down the status page.** The status page is reachable on the internet by
  default (`statusPageAllowedCidr` defaults to `0.0.0.0/0` in `cdk.json`). Set it
  to a specific IP or range before deploying, for example
  `npx cdk deploy --all -c statusPageAllowedCidr=203.0.113.10/32`.
- **Page password is always generated.** The status-page password is always
  randomly generated (20 characters) into AWS Secrets Manager
  (`nf-devops-agent-statuspage-login`) at deploy and printed once by
  `scripts/deploy.sh`. There is no plaintext-password override, so the password
  never appears in the synthesized AWS CloudFormation template. To rotate it,
  update the secret in AWS Secrets Manager directly.
- **Scope the DevOps Agent trust principal.** If `devopsAgentPrincipal` is not
  set, the agent role trusts the account root. Set it to the AWS DevOps Agent
  Space principal so only that principal can assume the read-only role.

## Demo-grade by design (harden before production)

- **Status-page web server.** The page is a small single-file Python server
  (`buildStatusServer()` in `lib/workload-stack.ts`). It uses a single shared
  username/password, an HMAC session cookie (`HttpOnly; SameSite=Lax; Secure`),
  best-effort per-IP login rate limiting, and a CSRF token on the webhook
  configuration form. These are reasonable for a short-lived sample but are not
  a full production auth model. The login password is read from AWS Secrets
  Manager at runtime and held only in memory; it is never written to disk. If the
  password cannot be read, the server refuses to start rather than falling back
  to a default credential (the systemd unit then retries until the secret is
  readable). **Intentional for the demo:** the auth is a small custom
  implementation rather than a managed service. For production, replace it with
  **Amazon Cognito** (hosted UI, session management, MFA) or **AWS IAM Identity
  Center** for internal users — the page is a throwaway, single-instance status
  view stood up and torn down the same day, so the custom login is deliberate.
- **Agent role trust placeholder.** When `devopsAgentPrincipal` /
  `devOpsAgentPrincipalArn` is not set, the read-only agent role trusts the
  account root **constrained by an `sts:ExternalId` condition**
  (`nf-devops-agent-placeholder-trust`), so the placeholder cannot be assumed by
  an arbitrary in-account principal without the external id. This is a synth/
  deploy convenience only; set the real Agent Space principal for production,
  which replaces the placeholder trust entirely.
- **Probe shared-secret.** The `X-Probe-Secret` header the probes send to the
  test endpoint is randomly generated into AWS Secrets Manager at deploy
  (`nf-devops-agent-probe-secret`) and read at runtime by both the endpoint
  server and the health-check daemon — never hardcoded. It is defence in depth
  on top of the NAT-EIP-scoped security group (the primary control).
- **AWS Network Firewall protection flags are disabled.** `deleteProtection`,
  `firewallPolicyChangeProtection`, and `subnetChangeProtection` are set to
  `false` in `lib/firewall-stack.ts`. This is **intentional for the demo**: the
  same-day `scripts/destroy.sh` teardown (the cost control) and the scripted
  scenario activate/revert (which edit the policy and routes) would all be
  blocked by these guards. For any non-ephemeral deployment, set all three to
  `true` and disable them deliberately only when you intend to tear down.
- **TLS terminates at Amazon CloudFront.** Traffic from Amazon CloudFront to the
  Application Load Balancer travels over the VPC-internal network on HTTP. Use
  the Amazon CloudFront `https://...cloudfront.net` URL, not the direct ALB URL.
- **Webhook secret placeholder.** `lib/webhook-stack.ts` seeds the webhook
  secret with non-secret `REPLACE_ME` placeholders via `unsafePlainText`. This
  is safe only because the values are placeholders; the real URL and signing
  secret are written at runtime through the status page (which calls
  `PutSecretValue`). As a compensating control, the webhook bridge AWS Lambda
  function validates the secret is not the `REPLACE_ME` placeholder before use
  and skips delivery if it is, so a deploy that has not yet been configured never
  sends with placeholder values. **Never pass a real secret to `unsafePlainText`**
  — it would be written in clear text into the synthesized AWS CloudFormation
  template. Use `PutSecretValue` (or a generated secret) for any real value.
- **Encryption.** The log bucket uses Amazon S3-managed encryption (SSE-S3). For
  production, consider a customer-managed AWS KMS key for an auditable key trail
  (this requires granting the AWS Network Firewall log-delivery service and any
  readers `kms:GenerateDataKey` / `kms:Decrypt` on the key).
- **Deploy convenience.** `scripts/deploy.sh` prints the generated page password
  to the terminal and defaults to `--require-approval never`. In production, do
  not log secrets and set `REQUIRE_APPROVAL` to keep CDK's IAM/security-group
  change review enabled.

## Acknowledged IAM exceptions (`Resource: "*"`)

Two policy statements use `Resource: "*"`. Both are **resource wildcards, not
action wildcards**, and both are required because the underlying AWS APIs are
not resource-scopable. They are the minimal viable scope:

- **`cloudwatch:PutMetricData`** (workload instance role, `lib/workload-stack.ts`).
  This action has no resource ARN and cannot be resource-scoped per the AWS API.
  Access is constrained to the `NfAgent/Workload` metric namespace via the
  `cloudwatch:namespace` condition key.
- **AWS Network Firewall `List*`** (agent role, `src/scenarioctl/policy.ts`).
  AWS Network Firewall `List*` actions are not resource-scopable per the AWS API,
  so `Resource` must be `"*"`. These are read-only list operations; the matching
  `Describe*` actions are scoped to the specific firewall, policy, and rule-group
  ARNs.

## Known dependency advisories

Dependency vulnerabilities are tracked with GitHub Dependabot and, where
possible, remediated through the `overrides` block in `package.json` (which pins
transitive dependencies to patched versions). At the time of writing, the
following advisory remains open and is **accepted** as a low-risk, build-time-only
item rather than remediated in this repository:

- **`brace-expansion` ReDoS ([GHSA-3jxr-9vmj-r5cp](https://github.com/advisories/GHSA-3jxr-9vmj-r5cp), high).**
  A copy of `brace-expansion` `5.0.6` (patched in `5.0.7`) is a **bundled
  dependency inside `aws-cdk-lib`** (aws-cdk-lib ships its dependency tree
  pre-packed in its own package tarball). npm `overrides` cannot rewrite a
  package's bundled dependencies, so this copy cannot be pinned from this
  project's `package.json`, and the latest `aws-cdk-lib` release still bundles
  `5.0.6`. The `overrides` here already pin every *non-bundled* copy of
  `brace-expansion` (and `js-yaml`) to patched versions.
  - **Why the exposure is negligible:** the vulnerability is a
    regular-expression denial of service triggered only by maliciously crafted
    brace/glob input. Within `aws-cdk-lib` this code runs on the `cdk synth` /
    `cdk deploy` path (path and pattern matching), i.e. at **build time on a
    trusted developer or CI machine, over your own CDK source** — there is no
    attacker-controlled input and nothing in the *deployed* sample runtime
    exercises it.
  - **Resolution path:** it clears automatically once `aws-cdk-lib` publishes a
    release that bundles `brace-expansion` `5.0.7` or later; bump `aws-cdk-lib`
    at that point and the alert closes with no code change here.

## Self-deployed test endpoint for scenario probes

The scenarios demonstrate a real firewall drop, so the probe targets must be
reachable endpoints that are healthy at baseline and only break when a scenario
is activated. Rather than depend on external/real domains, the app deploys its
own test endpoint (`NfTestEndpointStack`): a second, isolated VPC with two
internet-facing Network Load Balancers (an "app" endpoint on 80/443/9142 and a
separate "control" endpoint on 443) and a single SSM-managed target instance
running a small stdlib server (HTTPS with a self-signed cert, raw TCP on 9142,
HTTP `/healthz`). All probe targets are the **deploy-generated NLB DNS names**, so
no real domain is hardcoded anywhere.

Security properties of the test endpoint:

- **Ingress is scoped to the deployment's egress IPs.** Network Load Balancers
  preserve the client source IP, and all workload egress leaves the main VPC
  through its two NAT gateway Elastic IPs. The target instance's security group
  allows 80/443/9142 **only from those two NAT EIPs (/32)** — never `0.0.0.0/0`.
  So although the NLBs are internet-facing (required for the traffic to egress
  the firewall, reach the internet, and return), nothing on the internet other
  than this deployment's egress can get a response.
- **No public instance.** The target instance has no public IP and is SSM-managed,
  matching the main workload's posture; only the NLBs face the internet.
- **Defence in depth.** The HTTPS probes send a shared-secret header
  (`X-Probe-Secret`) the server requires on non-health paths, so even an actor
  inside the test VPC cannot trivially use the endpoint. The self-signed
  certificate is acceptable because the probes only measure connect-success vs a
  firewall-drop timeout (`curl -k`); the firewall inspects the TLS SNI regardless
  of certificate validity.

The example domains that appear as fallback defaults in the code (`app.example.com`,
`control.example.com`, `db.example.com:9142`) are RFC-2606 example names used only
when the stack is built standalone (e.g. unit tests); a real deploy always uses the
generated NLB DNS names.

## What is solid

- The AWS DevOps Agent IAM role is least-privilege and allowlist-only: read-only
  AWS Network Firewall `Describe*`/`List*` and Amazon CloudWatch Logs read, with
  no action wildcards (the only `*` is the resource on list operations that
  require it, documented above). The policy builder is property-tested.
- The webhook bridge AWS Lambda function validates and HMAC-signs payloads and
  reads its secret from AWS Secrets Manager at invocation time.
- No credentials, account IDs, or live resource identifiers are committed to the
  repository.
