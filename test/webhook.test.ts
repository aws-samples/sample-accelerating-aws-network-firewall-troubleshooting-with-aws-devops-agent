/**
 * Unit tests for the pure helpers exported by the DevOps Agent webhook bridge
 * Lambda (`src/webhook/index.js`): `buildIncidentPayload` and `signPayload`.
 *
 * Feature: nf-devops-agent-incident-response
 *
 * Only the side-effect-free exported helpers are exercised here. The SNS
 * `handler` is intentionally NOT invoked: it lazily requires the AWS SDK
 * Secrets Manager client and performs outbound HTTPS POSTs, neither of which
 * belong in a unit test of the pure logic.
 *
 * These assertions track the DevOps Agent generic-webhook Version 1 HMAC
 * contract (see the user guide "Invoking DevOps Agent through Webhook"):
 *   - the payload follows the agent's incident schema
 *     (`eventType`/`incidentId`/`action`/`priority`/`title`/...), and
 *   - the signature is the base64 HMAC-SHA-256 of `"<timestamp>:<body>"`.
 *
 * The module is plain CommonJS, so it is pulled in with `require` (guarded by
 * an eslint-disable). `createHmac` is imported from the Node `crypto` module to
 * independently recompute the expected signature.
 */

import { createHmac } from "crypto";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { buildIncidentPayload, signPayload } = require("../src/webhook/index.js");

describe("webhook pure helpers", () => {
  describe("buildIncidentPayload", () => {
    it("maps a full CloudWatch alarm message into the agent incident schema", () => {
      const alarm = {
        AlarmName: "Alarm-1",
        AlarmDescription: "desc",
        NewStateValue: "ALARM",
        NewStateReason: "reason",
        Region: "us-east-1",
        StateChangeTime: "2024-01-02T03:04:05Z",
      };

      const payload = buildIncidentPayload(alarm, { region: "us-west-2" });

      // Version 1 incident schema fields.
      expect(payload.eventType).toBe("incident");
      expect(payload.action).toBe("created");
      expect(payload.priority).toBe("HIGH");
      expect(payload.title).toBe("CloudWatch Alarm: Alarm-1");
      expect(payload.description).toBe("reason");
      expect(payload.timestamp).toBe("2024-01-02T03:04:05Z");
      expect(payload.service).toBe("nf-devops-agent");
      // The alarm's own Region wins over the fallback, and the raw alarm is attached.
      expect(payload.data.metadata.region).toBe("us-east-1");
      expect(payload.data.alarm).toEqual(alarm);
      // incidentId is present and ties to the alarm name.
      expect(typeof payload.incidentId).toBe("string");
      expect(payload.incidentId).toContain("Alarm-1");
    });

    it("applies defaults for an empty alarm and uses the fallback region", () => {
      const payload = buildIncidentPayload({}, { region: "us-west-2" });

      expect(payload.eventType).toBe("incident");
      expect(payload.title).toBe("CloudWatch Alarm: unknown-alarm");
      expect(payload.priority).toBe("HIGH");
      expect(payload.service).toBe("nf-devops-agent");
      expect(payload.data.metadata.region).toBe("us-west-2");
      // timestamp falls back to a generated ISO string.
      expect(typeof payload.timestamp).toBe("string");
      expect(payload.timestamp.length).toBeGreaterThan(0);
    });

    it("is deterministic when incidentId and timestamp are supplied", () => {
      const alarm = {
        AlarmName: "Alarm-1",
        NewStateReason: "reason",
        Region: "us-east-1",
        StateChangeTime: "2024-01-02T03:04:05Z",
      };
      const opts = { region: "us-east-1", incidentId: "fixed-id", timestamp: "2024-01-02T03:04:05Z" };

      const first = buildIncidentPayload(alarm, opts);
      const second = buildIncidentPayload(alarm, opts);

      expect(first).toEqual(second);
      expect(first.incidentId).toBe("fixed-id");
    });
  });

  describe("signPayload", () => {
    it("produces the base64 HMAC-SHA-256 of '<timestamp>:<body>'", () => {
      const timestamp = "2024-01-02T03:04:05.000Z";
      const body = '{"a":1}';
      const secret = "s3cret";

      const signature = signPayload(timestamp, body, secret);
      const expected = createHmac("sha256", secret)
        .update(`${timestamp}:${body}`, "utf8")
        .digest("base64");

      expect(signature).toBe(expected);
      // base64 of a 256-bit digest is 44 chars ending in '='.
      expect(signature).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    });

    it("is deterministic and varies with the secret and the timestamp", () => {
      const ts = "2024-01-02T03:04:05.000Z";
      const body = '{"a":1}';

      expect(signPayload(ts, body, "s3cret")).toBe(signPayload(ts, body, "s3cret"));
      expect(signPayload(ts, body, "s3cret")).not.toBe(signPayload(ts, body, "different"));
      // Changing the timestamp changes the signature (replay protection).
      expect(signPayload(ts, body, "s3cret")).not.toBe(
        signPayload("2024-01-02T03:04:06.000Z", body, "s3cret"),
      );
    });
  });
});
