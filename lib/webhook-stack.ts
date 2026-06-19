/**
 * WebhookStack — the bridge that wires the Amazon CloudWatch alarms to AWS
 * DevOps Agent (the "How the alarm pipeline works" path).
 *
 * The alarm pipeline is: a CloudWatch alarm transitions to ALARM → publishes to
 * the Amazon Simple Notification Service (Amazon SNS) topic → SNS invokes this
 * stack's AWS Lambda function → the Lambda reads the webhook
 * URL + signing secret from AWS Secrets Manager, builds an incident payload, signs
 * it with HMAC SHA-256, and POSTs it to the DevOps Agent webhook → the agent
 * validates the signature and starts an investigation.
 *
 * Why SNS sits between CloudWatch and Lambda (per the reference design): it
 * retries delivery if the Lambda is throttled, it can fan out to additional
 * subscribers (email, chat, ticketing) without touching the alarms, and it
 * supports cross-account publishing so multiple accounts can feed one pipeline.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Requires the AlarmsStack.
 * ────────────────────────────────────────────────────────────────────────────
 * This stack subscribes its Lambda to the alarms stack's SNS topic (passed as a
 * prop). The operator fills in the real webhook URL + secret AFTER creating the
 * DevOps Agent Space and its webhook, by updating the Secrets Manager secret
 * this stack provisions (it ships with a placeholder so the deploy never blocks
 * on an out-of-band value). Until then the Lambda skips delivery cleanly.
 */
import * as cdk from "aws-cdk-lib";
import { Duration, Tags } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as sns from "aws-cdk-lib/aws-sns";
import * as sns_subscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as path from "path";
import { Construct } from "constructs";

import { PROJECT_TAG_KEY, PROJECT_TAG_VALUE } from "./network-stack";

/** Fixed name for the webhook-credentials secret the operator updates post-deploy. */
export const WEBHOOK_SECRET_NAME = "nf-devops-agent-webhook-credentials";

/**
 * Props for {@link WebhookStack}. Takes the alarms SNS topic (from
 * `alarms.topic`) so the bridge Lambda subscribes to the same topic the alarms
 * publish to.
 */
export interface WebhookStackProps extends cdk.StackProps {
  /** The alarms SNS topic (from `alarms.topic`) the Lambda subscribes to. */
  readonly alarmTopic: sns.ITopic;
}

/**
 * The DevOps Agent webhook bridge stack. Exposes the Lambda, the Secrets Manager
 * secret, and the secret name/ARN so `bin/app.ts` can surface them as outputs
 * (the operator updates the secret with the real webhook URL + signing secret).
 */
export class WebhookStack extends cdk.Stack {
  /** The bridge Lambda subscribed to the alarms SNS topic. */
  public readonly webhookFunction: lambda.Function;
  /** The Secrets Manager secret holding `{ webhookUrl, webhookSecret }`. */
  public readonly webhookSecret: secretsmanager.Secret;
  /** The secret name (for operator instructions + outputs). */
  public readonly webhookSecretName: string;

  constructor(scope: Construct, id: string, props: WebhookStackProps) {
    super(scope, id, props);

    // ── Secrets Manager: webhook URL + signing secret, seeded with placeholders ──
    // The operator overwrites these after creating the DevOps Agent webhook
    // (Agent Space → webhook → download CSV → paste the URL + secret here).
    this.webhookSecret = new secretsmanager.Secret(this, "WebhookCredentials", {
      secretName: WEBHOOK_SECRET_NAME,
      description:
        "AWS DevOps Agent webhook URL + HMAC signing secret. Update after creating the Agent Space webhook.",
      // A fixed placeholder JSON (not a generated password) so the Lambda can
      // detect "not yet configured" and skip delivery rather than erroring.
      //
      // SAMPLE ONLY: `unsafePlainText` writes this literal value into the
      // synthesized AWS CloudFormation template. That is acceptable here ONLY
      // because the values are non-secret placeholders (`REPLACE_ME`) that the
      // operator overwrites with the real webhook URL and signing secret through
      // the status page (which calls PutSecretValue at runtime). NEVER pass a
      // real secret to `unsafePlainText` — it would land in the template (stored
      // in Amazon S3 and visible in the console). For generated secrets, use
      // `generateSecretString` instead.
      secretStringValue: cdk.SecretValue.unsafePlainText(
        JSON.stringify({ webhookUrl: "REPLACE_ME", webhookSecret: "REPLACE_ME" }),
      ),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    this.webhookSecretName = WEBHOOK_SECRET_NAME;

    // ── Bridge Lambda: SNS → read secret → HMAC-sign → POST to the agent webhook ──
    this.webhookFunction = new lambda.Function(this, "WebhookFunction", {
      functionName: "nf-devops-agent-webhook",
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "..", "src", "webhook")),
      timeout: Duration.seconds(15),
      memorySize: 128,
      description:
        "Bridges CloudWatch alarm notifications to the AWS DevOps Agent webhook (HMAC-signed POST).",
      environment: {
        WEBHOOK_SECRET_ID: this.webhookSecret.secretArn,
      },
    });

    // Least privilege: the Lambda only needs to READ the one webhook secret.
    this.webhookSecret.grantRead(this.webhookFunction);

    // ── Subscribe the Lambda to the alarms SNS topic ──
    props.alarmTopic.addSubscription(
      new sns_subscriptions.LambdaSubscription(this.webhookFunction),
    );

    // Tag every resource in the stack for the teardown sweep (Requirement 10).
    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);
  }
}
