// Parity test: `fnmatchCase` glob — IR_CONTRACT .

// Reads the Python-generated fixtures (`glob.json`) and asserts the TS
// re-implementation of Python `fnmatch.fnmatchcase` matches every row.
// NOT JS `minimatch` — the port ships Python `fnmatch` semantics verbatim.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { fnmatchCase } from "../../src/fnmatch.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures: Array<{
  name: string;
  glob: string;
  expected: boolean;
}> = JSON.parse(
  readFileSync(join(__dirname, "fixtures", "glob.json"), "utf8")
);

describe("parity / fnmatchCase", () => {
  for (const fx of fixtures) {
    it(`fnmatchCase(${JSON.stringify(fx.name)}, ${JSON.stringify(fx.glob)}) -> ${fx.expected}`, () => {
      expect(fnmatchCase(fx.name, fx.glob)).toBe(fx.expected);
    });
  }
});