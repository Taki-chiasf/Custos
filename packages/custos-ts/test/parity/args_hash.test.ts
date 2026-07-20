// Parity test: `_args_hash` canonicalization — IR_CONTRACT .

// Reads the Python-generated fixtures (`args_hash.json`) and asserts the
// TS canonicalizer produces byte-identical canonical JSON + identical
// SHA-256 for every row. Any divergence is a contract violation and
// blocks the  cut.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { canonicalize, asciiJSON, argsHash } from "../../src/canonicalize.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures: Array<{
  label: string;
  input: unknown;
  canonical_json: string;
  sha256: string;
  error?: string;
}> = JSON.parse(
  readFileSync(join(__dirname, "fixtures", "args_hash.json"), "utf8")
);

describe("parity / args_hash", () => {
  for (const fx of fixtures) {
    it(`canonicalize ${fx.label}`, () => {
      if (fx.error) {
        // Python raised; the TS port must also throw for this input.
        expect(() => canonicalize(fx.input)).toThrow();
        return;
      }
      const tsCanonical = asciiJSON(canonicalize(fx.input));
      expect(tsCanonical).toBe(fx.canonical_json);
    });

    it(`argsHash ${fx.label}`, () => {
      if (fx.error) {
        expect(() => argsHash(fx.input)).toThrow();
        return;
      }
      expect(argsHash(fx.input)).toBe(fx.sha256);
    });
  }

  it("dict key order is canonical (a == b)", () => {
    const a = argsHash({ a: 1, b: 2 });
    const b = argsHash({ b: 2, a: 1 });
    expect(a).toBe(b);
  });

  it("list order is preserved (a != b)", () => {
    const a = argsHash([1, 2, 3]);
    const b = argsHash([3, 2, 1]);
    expect(a).not.toBe(b);
  });
});