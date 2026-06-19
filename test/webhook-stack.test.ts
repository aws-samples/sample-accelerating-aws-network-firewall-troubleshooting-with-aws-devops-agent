/**
 * CDK assertion tests for `lib/webhook-stack.ts`.
 *
 * Feature: nf-devops-agent-incident-response
 *
 * The `WebhookStack` is the bridge between the CloudWatch alarms' SNS topic and
 * the AWS DevOps Agent webhook. It needs an `alarmTopic` (an `sns.ITopic`) to
 * subscribe its bridge Lambda to. To keep the test self-contained and avoid the
 * moving parts of the full alarms pipeline, we create a tiny throwaway "host"
 * stack with a single `sns.Topic` and hand that topic to the webhook stack
 * (Option A).
 *
 * Cross-stack note (verified against the synthesized `NfWebhookStack` template):
 * because the topic lives in a DIFFERENT stack, CDK places both the
 * `AWS::SNS::Subscription` and the `AWS::Lambda::Permission` (the
 * `sns.amazonaws.com`→Lambda invoke grant) into the SUBSCRIBER's stack — i.e.
 * the webhook stack — and references the topic via `Fn::ImportValue`. The
 * assertions below therefore expect both to appear in the webhook template.
 *
 * Validates the webhook bridge wiring: one Lambda (nodejs20.x / index.handler),
 * one Secrets Manager secret (fixed name), the secret ARN injected into the
 * Lambda's environment, the SNS→Lambda subscription + invoke permission, and an
 * IAM policy granting the Lambda read access to the secret.
 */

import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import * as sns from "aws-cdk-lib/aws-sns";
import { WebhookStack } from "../lib/webhook-stack";

/** A pinned environment so synthesis is deterministic. */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

/** The fixed secret name the webhook stack provisions (operator updates post-deploy). */
const WEBHOOK_SECRET_NAME = "nf-devops-agent-webhook-credentials";

/**
 * Build the WebhookStack (with a throwaway host stack supplying the alarm
 * topic) and return its synthesized template.
 */
function templateForWebhook(): Template {
  const app = new cdk.App();
  // Throwaway host stack just to own an SNS topic in the same app (Option A).
  const host = new cdk.Stack(app, "Host", { env: ENV });
  const topic = new sns.Topic(host, "T");
  const webhookStack = new WebhookStack(app, "TestWebhook", {
    env: ENV,
    alarmTopic: topic,
  });
  return Template.fromStack(webhookStack);
}

describe("WebhookStack CDK assertions", () => {
  let template: Template;

  beforeAll(() => {
    template = templateForWebhook();
  });

  it("synthesizes exactly one bridge Lambda (nodejs20.x / index.handler)", () => {
    template.resourceCountIs("AWS::Lambda::Function", 1);
    template.hasResourceProperties(
      "AWS::Lambda::Function",
      Match.objectLike({
        Runtime: "nodejs20.x",
        Handler: "index.handler",
      }),
    );
  });

  it("provisions exactly one Secrets Manager secret with the fixed webhook-credentials name", () => {
    template.resourceCountIs("AWS::SecretsManager::Secret", 1);
    template.hasResourceProperties(
      "AWS::SecretsManager::Secret",
      Match.objectLike({
        Name: WEBHOOK_SECRET_NAME,
      }),
    );
  });

  it("injects the webhook secret ARN into the Lambda's WEBHOOK_SECRET_ID environment variable", () => {
    // Token-aware: the value is a `{ Ref: <secret> }`, so match anyValue.
    template.hasResourceProperties(
      "AWS::Lambda::Function",
      Match.objectLike({
        Environment: Match.objectLike({
          Variables: Match.objectLike({
            WEBHOOK_SECRET_ID: Match.anyValue(),
          }),
        }),
      }),
    );
  });

  it("subscribes the bridge Lambda to the alarms SNS topic (lambda protocol)", () => {
    // The subscription lands in the webhook (subscriber) stack because the topic
    // is in a different stack — confirmed against the synthesized template.
    template.resourceCountIs("AWS::SNS::Subscription", 1);
    template.hasResourceProperties(
      "AWS::SNS::Subscription",
      Match.objectLike({
        Protocol: "lambda",
      }),
    );
  });

  it("grants SNS permission to invoke the bridge Lambda (Lambda::Permission in the webhook stack)", () => {
    // The cross-stack invoke permission is created in the subscriber's (webhook)
    // stack, principal `sns.amazonaws.com`.
    template.resourceCountIs("AWS::Lambda::Permission", 1);
    template.hasResourceProperties(
      "AWS::Lambda::Permission",
      Match.objectLike({
        Action: "lambda:InvokeFunction",
        Principal: "sns.amazonaws.com",
      }),
    );
  });

  it("grants the Lambda's execution role read access to the webhook secret (secretsmanager:GetSecretValue)", () => {
    // Token-aware: the policy's Resource is a `{ Ref: <secret> }`, so we can't
    // match the ARN literally. Instead find every IAM policy and stringify its
    // document, asserting at least one allows `secretsmanager:GetSecretValue`.
    const policies = template.findResources("AWS::IAM::Policy");
    const grantingPolicies = Object.values(policies).filter((policy) =>
      JSON.stringify(policy.Properties?.PolicyDocument ?? {}).includes(
        "secretsmanager:GetSecretValue",
      ),
    );
    expect(grantingPolicies.length).toBeGreaterThanOrEqual(1);
  });
});
