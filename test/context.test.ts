/**
 * Unit tests for CDK context rendering (`src/scenarioctl/context.ts`).
 *
 * Feature: nf-devops-agent-incident-response
 *
 * These are plain example-based unit tests (the property-based invariants for
 * the underlying state machine live in `test/state.properties.test.ts`). They
 * assert the rendered context object the CDK stacks read back contains the
 * expected keys/values for `baseline()` and for each scenario's `desired(n)`,
 * that `serializeContext` emits valid JSON, and
 * that `writeContextFile` writes to (and returns) the requested path.
 *
 * _Requirements: 9.1, 9.2_
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  renderContext,
  serializeContext,
  writeContextFile,
} from "../src/scenarioctl/context";
import { baseline, desired } from "../src/scenarioctl/state";

describe("context.ts unit tests", () => {
  describe("renderContext(baseline())", () => {
    it("renders the expected baseline keys/values", () => {
      const ctx = renderContext(baseline());
      expect(ctx).toEqual({
        activeScenario: "none",
        allowPriority: 100,
        dropPriority: 200,
        streamExceptionPolicy: "CONTINUE",
        asymmetricRoute: false,
        domainDenyActive: false,
        logDestination: "cloudwatch",
      });
    });
  });

  describe("renderContext(desired(n)) per scenario", () => {
    it("Scenario 1 flips only domainDenyActive", () => {
      const ctx = renderContext(desired("1"));
      expect(ctx.activeScenario).toBe("1");
      expect(ctx.domainDenyActive).toBe(true);
      // Other scenario-owned fields stay at baseline.
      expect(ctx.allowPriority).toBe(100);
      expect(ctx.dropPriority).toBe(200);
      expect(ctx.streamExceptionPolicy).toBe("CONTINUE");
      expect(ctx.asymmetricRoute).toBe(false);
    });

    it("Scenario 2 inverts allowPriority/dropPriority", () => {
      const ctx = renderContext(desired("2"));
      expect(ctx.activeScenario).toBe("2");
      expect(ctx.allowPriority).toBe(200);
      expect(ctx.dropPriority).toBe(100);
      // allow now evaluated after drop.
      expect(ctx.allowPriority).toBeGreaterThan(ctx.dropPriority);
      // Other scenario-owned fields stay at baseline.
      expect(ctx.domainDenyActive).toBe(false);
      expect(ctx.streamExceptionPolicy).toBe("CONTINUE");
      expect(ctx.asymmetricRoute).toBe(false);
    });

    it("Scenario 3 sets asymmetricRoute=true and leaves streamExceptionPolicy at baseline (routing-only)", () => {
      const ctx = renderContext(desired("3"));
      expect(ctx.activeScenario).toBe("3");
      expect(ctx.asymmetricRoute).toBe(true);
      // Scenario 3 is routing-only: it makes NO firewall-policy change.
      expect(ctx.streamExceptionPolicy).toBe("CONTINUE");
      // Other scenario-owned fields stay at baseline.
      expect(ctx.allowPriority).toBe(100);
      expect(ctx.dropPriority).toBe(200);
      expect(ctx.domainDenyActive).toBe(false);
    });
  });

  describe("serializeContext", () => {
    it("returns valid JSON that parses back to the rendered context", () => {
      for (const scenario of ["none", "1", "2", "3"] as const) {
        const state = desired(scenario);
        const json = serializeContext(state);
        // Valid JSON: parsing it must not throw.
        const parsed = JSON.parse(json);
        expect(parsed).toEqual(renderContext(state));
      }
    });

    it("ends with a trailing newline", () => {
      expect(serializeContext(baseline()).endsWith("\n")).toBe(true);
    });
  });

  describe("writeContextFile", () => {
    it("writes the serialized context to the requested path and returns it", () => {
      const tmpPath = path.join(
        os.tmpdir(),
        `nf-context-test-${process.pid}-${Date.now()}.json`,
      );
      try {
        const returned = writeContextFile(desired("2"), tmpPath);
        // Returns the absolute path that was written.
        expect(returned).toBe(path.resolve(tmpPath));
        // The on-disk content matches serializeContext exactly.
        const onDisk = fs.readFileSync(returned, { encoding: "utf8" });
        expect(onDisk).toBe(serializeContext(desired("2")));
        // And it parses back to the rendered context.
        expect(JSON.parse(onDisk)).toEqual(renderContext(desired("2")));
      } finally {
        if (fs.existsSync(tmpPath)) {
          fs.unlinkSync(tmpPath);
        }
      }
    });
  });
});
