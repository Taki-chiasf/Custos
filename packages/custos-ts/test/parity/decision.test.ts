// Parity test: `Decision` enum + Janus verdict mapping — IR_CONTRACT .

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  asDecision,
  isAllow,
  toCustosDecision,
  DECISION_VALUES,
} from "../../src/decision.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures: Array<
  | { decision: string; expected_value: string; is_allow: boolean }
  | { janus_verdict: string; custos: string }
> = JSON.parse(
  readFileSync(join(__dirname, "fixtures", "decision.json"), "utf8")
);

describe("parity / decision", () => {
  for (const fx of fixtures) {
    if ("decision" in fx) {
      it(`Decision.${fx.decision} wire round-trips + isAllow=${fx.is_allow}`, () => {
        const d = asDecision(fx.decision);
        expect(d).toBe(fx.expected_value);
        expect(isAllow(d)).toBe(fx.is_allow);
      });
    } else {
      it(`toCustosDecision(${JSON.stringify(fx.janus_verdict)}) -> ${fx.custos}`, () => {
        expect(toCustosDecision(fx.janus_verdict)).toBe(fx.custos);
      });
    }
  }

  it("seven members exact string values", () => {
    expect([...DECISION_VALUES].sort()).toEqual(
      ["allow", "allow_and_persist", "allow_once", "defer", "deny", "prompt", "quarantine"].sort()
    );
  });

  it("an unknown Decision throws", () => {
    expect(() => asDecision("bogus")).toThrow();
  });

  it("an unknown Janus verdict throws", () => {
    expect(() => toCustosDecision("bogus")).toThrow();
  });
});