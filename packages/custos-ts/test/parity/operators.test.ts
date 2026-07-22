// Parity test: ABAC operators — IR_CONTRACT .

// Reads the Python-generated fixtures (`operators.json`) and asserts the
// TS operator implementations return the same boolean for every row.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { applyOperator, OPERATOR_FUNCS } from "../../src/policy/operators.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures: Array<{
  label: string;
  op: string;
  a: unknown;
  b: unknown;
  expected: boolean;
  got: boolean | null;
}> = JSON.parse(
  readFileSync(join(__dirname, "fixtures", "operators.json"), "utf8")
);

describe("parity / operators", () => {
  for (const fx of fixtures) {
    it(`${fx.op} ${fx.label} -> ${fx.expected}`, () => {
      expect(applyOperator(fx.op, fx.a, fx.b)).toBe(fx.expected);
    });
  }

  it("OPERATOR_FUNCS has all 11 keys pinned by IR_CONTRACT", () => {
    expect(Object.keys(OPERATOR_FUNCS).sort()).toEqual(
      [
        "==",
        "!=",
        ">",
        "<",
        ">=",
        "<=",
        "in",
        "not_in",
        "contains",
        "not_contains",
        "matches",
      ].sort()
    );
  });

  it("unknown operator throws", () => {
    expect(() => applyOperator("garbage", 1, 2)).toThrow();
  });

  it("matches is start-anchored, not fullmatch", () => {
    // re.match(b, a) — anchored at start only. The contract pins this.
    // `re.match("^abc$", "abc")` DOES match (fullmatch author-supplied).
    expect(applyOperator("matches", "abc", "ab")).toBe(true);
    expect(applyOperator("matches", "abc", "^abc$")).toBe(true);
    expect(applyOperator("matches", "abcd", "abc")).toBe(true);
    expect(applyOperator("matches", "abcd", "^abc$")).toBe(false);
    expect(applyOperator("matches", "abc", "bc")).toBe(false);
  });

  it("matches on a non-string returns false (well-defined)", () => {
    expect(applyOperator("matches", 123, ".*")).toBe(false);
  });

  it("matches on an invalid regex returns false (safe)", () => {
    expect(applyOperator("matches", "abc", "[invalid")).toBe(false);
  });

  it("cross-type ordered comparison returns false", () => {
    expect(applyOperator(">", 1, "a")).toBe(false);
    expect(applyOperator("<", "a", 1)).toBe(false);
  });

  it("string-in-string membership", () => {
    // Python `in` supports string-in-string (substring); JS `in` does not.
    // The TS port MUST special-case this. Both "x" and "z" are in "xyz".
    expect(applyOperator("in", "x", "xyz")).toBe(true);
    expect(applyOperator("in", "z", "xyz")).toBe(true);
    expect(applyOperator("in", "w", "xyz")).toBe(false);
  });
});