// `_args_hash` canonicalization — IR_CONTRACT.md  (/ H13).

// Mirrors `custos.fatigue._canonicalize` + `_args_hash`. The canonical
// form is byte-stable across runs and across Python / TS implementations:

//   dict  -> object with keys sorted lexicographically by UTF-8 byte
//            order, values recursively canonicalized.
//   list  -> array with order PRESERVED (positional semantics).
//   set   -> array with elements sorted (numbers numerically, strings
//            lexicographically; mixed-type sets are NOT supported —
//            matching Python `sorted(...)` which raises TypeError on
//            incomparable elements).
//   bool / int / float / str / null -> themselves; no coercion.
//   any other type -> the Python `repr` string of the object.
//            Out-of-contract for the TS port for non-JSON scalars; the
//            parity fixture set  pins the canonical string per
//            type and the TS port matches the fixtures.

// Hashing:
//   sha256(asciiJSON(canonicalize(args)))

// `asciiJSON` matches Python `json.dumps(canonical, sort_keys=True)`
// defaults: separators `", "` and `": "`, ASCII-escaping of non-ASCII
// characters as lowercase `\uXXXX` (with surrogate pairs for non-BMP),
// no trailing newline, UTF-8 encoded.

// Known cross-language gap: Python `json.dumps(1.0)` -> `"1.0"` but
// `JSON.stringify(1)` -> `"1"` and JS does NOT distinguish integer-valued
// floats from ints at the Number level. For JSON-sourced args (the only
// kind a host can pass through the wire) `1.0` and `1` parse identically
// to JS `1`, and the canonical form accepts JS-native semantics. The
// parity fixture set avoids integer-valued float values; a host that
// constructs args programmatically with `1.0` (Python) gets a different
// hash than a host constructing the same args in TS — documented as a
// known edge case, fixable by a future canonical-form contract bump.

import { createHash } from "node:crypto";

type Canonical =
  | null
  | boolean
  | number
  | string
  | Canonical[]
  | { [key: string]: Canonical };

type ArgsInput = unknown;

// Whether a value is a "plain" JSON scalar the canonicalizer can pass
// through. bool/int/float/str/null.
function isJsonScalar(v: unknown): v is null | boolean | number | string {
  return (
    v === null ||
    typeof v === "boolean" ||
    typeof v === "number" ||
    typeof v === "string"
  );
}

// A JS Set is the only set-like we accept; the host is expected to pass
// arrays for ordered collections. Sets of mixed incomparable types are
// rejected (matches Python's `sorted({1, "a"})` TypeError).
function tryCanonicalSet(v: Set<unknown>): Canonical[] {
  const elements: Canonical[] = [];
  for (const el of v) {
    if (el instanceof Set || (el !== null && typeof el === "object" && !Array.isArray(el))) {
      // Set elements must themselves be hashable in Python; objects are
      // unhashable. Reject to mirror Python `TypeError: unhashable type`.
      throw new TypeError("set elements must be JSON scalars");
    }
    if (!isJsonScalar(el)) {
      throw new TypeError("set elements must be JSON scalars");
    }
    elements.push(el);
  }
  try {
    elements.sort((a, b) => {
      if (typeof a === "number" && typeof b === "number") return a - b;
      if (typeof a === "string" && typeof b === "string") return utf8ByteCompare(a, b);
      if (typeof a === "boolean" && typeof b === "boolean") return a === b ? 0 : a ? 1 : -1;
      if (a === null && b === null) return 0;
      // Mixed-type sort — Python raises TypeError. We throw to mirror.
      throw new TypeError("mixed-type set sort");
    });
  } catch (err) {
    if (err instanceof TypeError && err.message === "mixed-type set sort") throw err;
    throw err;
  }
  return elements;
}

export function canonicalize(value: ArgsInput): Canonical {
  if (isJsonScalar(value)) return value;
  if (value instanceof Set) return tryCanonicalSet(value);
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const entries = Object.entries(obj).sort(([a], [b]) => utf8ByteCompare(a, b));
    const out: { [key: string]: Canonical } = {};
    for (const [k, v] of entries) out[k] = canonicalize(v);
    return out;
  }
  // Non-JSON scalar (function, symbol, undefined, bigint, etc.). Mirror
  // Python `repr(obj)`. Out-of-contract for args; pinned in fixtures.
  return reprNonJson(value);
}

function reprNonJson(v: unknown): string {
  if (typeof v === "bigint") return `${v}n`;
  if (typeof v === "symbol") return v.toString();
  if (typeof v === "function") return `function ${v.name || "<anonymous>"}`;
  if (v === undefined) return "undefined";
  // Fallback matches Python `repr(obj)` shape loosely: <ClassName object at 0x...>
  // The parity fixture set pins specific cases; this branch is not
  // exercised for JSON-sourced args.
  return `<${(v as object)?.constructor?.name ?? "Object"} object>`;
}

// Python `json.dumps(v, sort_keys=True)` byte-equivalent serializer.
//   - separators: ", " and ": "
//   - ensure_ascii=True: non-ASCII -> \uXXXX (surrogate pair for non-BMP)
//   - no trailing newline
//   - keys sorted (canonicalize already sorted; this re-sorts idempotently)
export function asciiJSON(canonical: Canonical): string {
  return serializeCanonical(canonical);
}

function serializeCanonical(v: Canonical): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return serializeNumber(v);
  if (typeof v === "string") return serializeString(v);
  if (Array.isArray(v)) {
    return "[" + v.map(serializeCanonical).join(", ") + "]";
  }
  // Object — sort keys by UTF-8 byte order (idempotent w/ canonicalize).
  const entries = Object.entries(v).sort(([a], [b]) => utf8ByteCompare(a, b));
  return (
    "{" +
    entries.map(([k, val]) => serializeString(k) + ": " + serializeCanonical(val)).join(", ") +
    "}"
  );
}

function serializeNumber(n: number): string {
  if (Number.isNaN(n) || !Number.isFinite(n)) {
    // Python `json.dumps` raises ValueError on NaN/Infinity by default.
    // The contract  forbids these; throw to mirror.
    throw new RangeError(`non-finite number in canonical form: ${n}`);
  }
  if (Number.isInteger(n)) return String(n);
  // Float with fractional part — JS `Number.toString` uses shortest
  // round-trip per ES2015+, matching Python `repr(float)` for the
  // fixtures' float values.
  return n.toString();
}

// Python `json.dumps` string escaping:
//   - `"` and `\\` escaped
//   - control chars \b \f \n \r \t
//   - other control chars (< 0x20) -> \uXXXX
//   - non-ASCII (>= 0x7F) -> \uXXXX (lowercase hex; surrogate pair for
//     non-BMP codepoints, e.g. U+1F600 -> \ud83d\ude00)
//   - NOT escaped: `/`, `\u2028`, `\u2029` (Python default; JS does
//     escape the latter two — we follow Python).
function serializeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else if (code >= 0x7f) {
      if (code > 0xffff) {
        // Non-BMP: emit surrogate pair (Python json default behavior).
        const high = 0xd800 + ((code - 0x10000) >> 10);
        const low = 0xdc00 + ((code - 0x10000) & 0x3ff);
        out += "\\u" + high.toString(16).padStart(4, "0");
        out += "\\u" + low.toString(16).padStart(4, "0");
      } else {
        out += "\\u" + code.toString(16).padStart(4, "0");
      }
    } else {
      out += ch;
    }
  }
  out += '"';
  return out;
}

// UTF-8 byte-order comparison. JS default string sort is by UTF-16 code
// unit, which differs from Python's `sorted` (which sorts by Unicode
// codepoint). For BMP strings the two agree; for non-BMP they diverge
// (Python treats the codepoint as a single unit, JS as a surrogate
// pair). To match Python we compare by codepoint.
export function utf8ByteCompare(a: string, b: string): number {
  // Python sorts strings by Unicode codepoint. Iterate by codepoint.
  const ai = a[Symbol.iterator]();
  const bi = b[Symbol.iterator]();
  for (;;) {
    const ar = ai.next();
    const br = bi.next();
    if (ar.done && br.done) return 0;
    if (ar.done) return -1;
    if (br.done) return 1;
    const ac = ar.value.codePointAt(0)!;
    const bc = br.value.codePointAt(0)!;
    if (ac !== bc) return ac - bc;
  }
}

export function argsHash(args: ArgsInput): string {
  const canonical = canonicalize(args);
  const json = asciiJSON(canonical);
  return createHash("sha256").update(json, "utf8").digest("hex");
}