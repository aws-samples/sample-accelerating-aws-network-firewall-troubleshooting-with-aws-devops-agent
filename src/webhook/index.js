"use strict";

/**
 * AWS DevOps Agent webhook bridge AWS Lambda function (deployed asset).
 *
 * Subscribed to the alarms Amazon Simple Notification Service (Amazon SNS)
 * topic. For each Amazon CloudWatch alarm notification it:
 *   1. reads the webhook URL + signing secret from AWS Secrets Manager,
 *   2. builds an incident payload from the alarm message,
 *   3. signs the JSON body with HMAC SHA-256,
 *   4. POSTs it to the AWS DevOps Agent webhook with the signature header.
 *
 * The agent validates the signature and starts an investigation. This is the
 * SNS -> Lambda -> Secrets Manager -> signed POST bridge described in the blog's
 * "How the alarm pipeline works" section.
 *
 * Plain CommonJS (no build step) so it deploys as a `lambda.Code.fromAsset`
 * directly. Only Node built-ins are required at module load; the AWS SDK v3
 * Secrets Manager client (present in the Lambda runtime) is required lazily
 * inside the handler so the pure helpers below can be unit-tested without the
 * SDK installed locally.
 */

const https = require("node:https");
const crypto = require("node:crypto");
const { URL } = require("node:url");

/** Secrets Manager id/ARN holding `{ webhookUrl, webhookSecret }` (set by the stack). */
const SECRET_ID = process.env.WEBHOOK_SECRET_ID;
/** Placeholder value the secret ships with; a real webhook URL replaces it. */
const PLACEHOLDER = "REPLACE_ME";

/**
 * Build the incident payload POSTed to the DevOps Agent webhook from a parsed
 * CloudWatch alarm message. Pure and deterministic given its inputs (except for
 * the generated `incidentId`/`timestamp`, which the caller may override for
 * tests).
 *
 * The shape follows the DevOps Agent generic-webhook Version 1 schema:
 * `{ eventType, incidentId, action, priority, title, description, timestamp,
 * service, data }`. The full original alarm is attached under `data` so the
 * agent can read everything CloudWatch sent.
 *
 * @param {object} alarm parsed CloudWatch alarm message (the SNS `Message` JSON).
 * @param {object} [opts] optional overrides: `{ region, incidentId, timestamp }`.
 * @returns {object} the incident payload in the agent's expected schema.
 */
function buildIncidentPayload(alarm, opts) {
  const a = alarm && typeof alarm === "object" ? alarm : {};
  const o = opts && typeof opts === "object" ? opts : {};
  const region = a.Region || o.region || "";
  const alarmName = a.AlarmName || "unknown-alarm";
  const timestamp = o.timestamp || a.StateChangeTime || new Date().toISOString();
  // A unique id per event so the agent does not deduplicate distinct incidents.
  const incidentId = o.incidentId || `${alarmName}-${Date.parse(timestamp) || Date.now()}`;
  const description =
    a.NewStateReason ||
    a.AlarmDescription ||
    `CloudWatch alarm ${alarmName} entered ${a.NewStateValue || "ALARM"}` +
      (region ? ` in ${region}` : "");
  return {
    eventType: "incident",
    incidentId,
    action: "created",
    priority: "HIGH",
    title: `CloudWatch Alarm: ${alarmName}`,
    description,
    timestamp,
    service: "nf-devops-agent",
    data: {
      metadata: { region, source: "nf-devops-agent" },
      alarm: a,
    },
  };
}

/**
 * Sign a request for the DevOps Agent generic webhook (Version 1 HMAC). The
 * agent computes HMAC-SHA-256 over `"<timestamp>:<body>"` with the shared
 * secret and compares the base64 digest, so we must sign the exact same string
 * and base64-encode the result.
 *
 * @param {string} timestamp the ISO-8601 timestamp sent in `x-amzn-event-timestamp`.
 * @param {string} body the exact JSON string that will be POSTed.
 * @param {string} secret the shared signing secret from Secrets Manager.
 * @returns {string} base64 HMAC-SHA-256 digest of `"<timestamp>:<body>"`.
 */
function signPayload(timestamp, body, secret) {
  return crypto
    .createHmac("sha256", String(secret))
    .update(`${timestamp}:${body}`, "utf8")
    .digest("base64");
}

/** POST a signed body to the webhook URL; resolves with `{ statusCode, body }`. */
function postToWebhook(webhookUrl, body, signature, timestamp) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(webhookUrl);
    } catch (err) {
      reject(new Error(`Invalid webhook URL: ${err.message}`));
      return;
    }
    const options = {
      method: "POST",
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
        "x-amzn-event-signature": signature,
        "x-amzn-event-timestamp": timestamp,
      },
    };
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => resolve({ statusCode: res.statusCode || 0, body: data }));
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/** Read and parse the `{ webhookUrl, webhookSecret }` secret from Secrets Manager. */
async function readWebhookCredentials() {
  // Lazy require so unit tests of the pure helpers don't need the SDK installed.
  const { SecretsManagerClient, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");
  const client = new SecretsManagerClient({});
  const out = await client.send(new GetSecretValueCommand({ SecretId: SECRET_ID }));
  const raw = out.SecretString || "{}";
  const creds = JSON.parse(raw);
  return { webhookUrl: creds.webhookUrl, webhookSecret: creds.webhookSecret };
}

/**
 * SNS handler. Reads the webhook credentials once, then for each alarm record
 * builds, signs, and POSTs the incident payload. Skips delivery (without error)
 * when the secret still holds the placeholder, so a deploy before the operator
 * configures the Agent Space webhook does not throw.
 */
exports.handler = async (event) => {
  const records = (event && event.Records) || [];
  const { webhookUrl, webhookSecret } = await readWebhookCredentials();

  if (!webhookUrl || webhookUrl === PLACEHOLDER) {
    console.log(
      "Webhook URL not configured (still the placeholder); skipping. " +
        "Update the nf-devops-agent-webhook-credentials secret to enable delivery.",
    );
    return { statusCode: 200, body: JSON.stringify({ message: "webhook not configured; skipped" }) };
  }

  const results = [];
  for (const record of records) {
    const message = record && record.Sns && record.Sns.Message;
    let alarm = {};
    try {
      alarm = JSON.parse(message);
    } catch {
      alarm = { AlarmName: "unparseable-alarm", NewStateReason: String(message) };
    }
    const payload = buildIncidentPayload(alarm, { region: process.env.AWS_REGION });
    const body = JSON.stringify(payload);
    // Version 1 HMAC: sign "<timestamp>:<body>" and send both headers.
    const timestamp = new Date().toISOString();
    const signature = signPayload(timestamp, body, webhookSecret);
    const res = await postToWebhook(webhookUrl, body, signature, timestamp);
    console.log(
      `Posted incident for ${payload.title}; webhook status ${res.statusCode}` +
        (res.statusCode >= 400 ? ` body: ${res.body}` : ""),
    );
    results.push({ incidentId: payload.incidentId, webhookStatus: res.statusCode });
  }

  return { statusCode: 200, body: JSON.stringify({ message: "DevOps Agent investigation triggered", results }) };
};

// Exported for unit testing (test/webhook.test.ts).
exports.buildIncidentPayload = buildIncidentPayload;
exports.signPayload = signPayload;
