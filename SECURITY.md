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
  readable).
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

## Use of real AWS endpoints in scenario probes

The scenarios demonstrate a real firewall drop, so the probe targets must be
**reachable, resolvable endpoints** that are healthy at baseline and only break
when a scenario is activated. The following are intentional references to real
AWS service endpoints used as functional test targets, not example placeholders:

- **`docs.aws.amazon.com`** (Scenario 1 domain deny list) and **`aws.amazon.com`**
  (Scenario 3 asymmetric routing) — reachable HTTPS endpoints the workload probes
  and the firewall then blocks.
- **`cassandra.<region>.amazonaws.com:9142`** (Scenario 2) — the regional Amazon
  Keyspaces (for Apache Cassandra) TLS endpoint, used as the stateless port-9142
  test class.
- **`sts.amazonaws.com`** (status-page control probe) — an AWS endpoint that no
  scenario rule targets, used to distinguish a subnet-wide egress outage from an
  isolated rule failure.

These are not customer or third-party domains and are used only as live test
targets within the deploying account's own egress path.

## What is solid

- The AWS DevOps Agent IAM role is least-privilege and allowlist-only: read-only
  AWS Network Firewall `Describe*`/`List*` and Amazon CloudWatch Logs read, with
  no action wildcards (the only `*` is the resource on list operations that
  require it, documented above). The policy builder is property-tested.
- The webhook bridge AWS Lambda function validates and HMAC-signs payloads and
  reads its secret from AWS Secrets Manager at invocation time.
- No credentials, account IDs, or live resource identifiers are committed to the
  repository.
