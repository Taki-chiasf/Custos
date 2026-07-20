// ABAC operator primitives — IR_CONTRACT.md  (dual-engine lock).

// Eleven operators; the string keys are identical to
// `custos.policy.operators.OPERATOR_FUNCS` and the harness `JanusOperator`
// enum. Semantics MUST match the Python implementations exactly,
// including the null / type-error -> `false` catch-and-return contract
// . The parity fixture set pins the JS-foreign cases:
//   - `string`-in-`string` (Python supports it; JS `in` does not)
//   - `>` across `number`|`string` (Python raises; JS would coerce)

// `matches` is start-anchored  via `new RegExp("^" + b)` (caller
// supplies the trailing `$` if they want fullmatch).

export type OperatorKey =
  | "=="
  | "!="
  | ">"
  | "<"
  | ">="
  | "<="
  | "in"
  | "not_in"
  | "contains"
  | "not_contains"
  | "matches";

export const OPERATOR_KEYS: readonly OperatorKey[] = [
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
];

export type OperatorFn = (a: unknown, b: unknown) => boolean;

// Equality / inequality — Python `==` semantics: `bool` is a subclass
// of `int` so `True == 1` is `True` and `False == 0` is `True`. JS `===`
// does NOT do this (strict type check); JS `==` does but has footguns
// (`"" == 0`, `null == undefined`). We special-case bool↔number coercion
// to match Python without pulling in the JS loose-equality hazards.
function pyEquals(a: unknown, b: unknown): boolean {
  if (typeof a === "boolean" && typeof b === "number") return Number(a) === b;
  if (typeof a === "number" && typeof b === "boolean") return a === Number(b);
  return a === b;
}

export const eq: OperatorFn = (a, b) => pyEquals(a, b);
export const ne: OperatorFn = (a, b) => !pyEquals(a, b);

// Ordered comparisons. Cross-type returns `false` (Python raises
// TypeError -> caught and returned as `false` by `_ArgPred.evaluate`).
function orderedCmp(a: unknown, b: unknown, op: "<" | "<=" | ">" | ">="): boolean {
  if (typeof a === "number" && typeof b === "number") {
    if (op === "<") return a < b;
    if (op === "<=") return a <= b;
    if (op === ">") return a > b;
    return a >= b;
  }
  if (typeof a === "string" && typeof b === "string") {
    if (op === "<") return a < b;
    if (op === "<=") return a <= b;
    if (op === ">") return a > b;
    return a >= b;
  }
  if (typeof a === "boolean" && typeof b === "boolean") {
    const an = a ? 1 : 0;
    const bn = b ? 1 : 0;
    if (op === "<") return an < bn;
    if (op === "<=") return an <= bn;
    if (op === ">") return an > bn;
    return an >= bn;
  }
  // Cross-type: Python raises TypeError -> caught by `_ArgPred.evaluate` -> `false`.
  return false;
}

export const gt: OperatorFn = (a, b) => orderedCmp(a, b, ">");
export const lt: OperatorFn = (a, b) => orderedCmp(a, b, "<");
export const ge: OperatorFn = (a, b) => orderedCmp(a, b, ">=");
export const le: OperatorFn = (a, b) => orderedCmp(a, b, "<=");

// Membership. Python `a in b`:
//   - string in string: substring check (JS `in` does NOT support this).
//   - scalar in array: includes.
//   - scalar in object: key check.
//   - scalar in set: set has.
//   - null/non-iterable b: Python raises TypeError -> `false`.
function inOp(a: unknown, b: unknown): boolean {
  if (b === null || b === undefined) return false;
  if (typeof a === "string" && typeof b === "string") return b.includes(a);
  if (typeof b === "string") return false; // a not a string but b is — Python raises
  if (Array.isArray(b)) return b.includes(a);
  if (b instanceof Set) return b.has(a);
  if (typeof b === "object") return (a as string | number | symbol) in (b as Record<string, unknown>);
  return false;
}

export const inside: OperatorFn = (a, b) => inOp(a, b);
export const notInside: OperatorFn = (a, b) => !inOp(a, b);

// `contains` is `in` with args reversed: `a contains b` = `b in a`.
export const contains: OperatorFn = (a, b) => inOp(b, a);
export const notContains: OperatorFn = (a, b) => !inOp(b, a);

// `matches` — start-anchored regex . Non-string `a` returns `false`.
export const matches: OperatorFn = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string") return false;
  try {
    // `re.match(b, a)` is start-anchored, NOT fullmatch. Caller authors
    // a trailing `$` if they need full-string match. We anchor at the
    // start only.
    const re = b.startsWith("^") ? new RegExp(b) : new RegExp("^" + b);
    return re.test(a);
  } catch {
    // Invalid regex — Python `re.match` raises `re.error`; mirror as
    // `false` (caught by `_ArgPred.evaluate`).
    return false;
  }
};

export const OPERATOR_FUNCS: Record<OperatorKey, OperatorFn> = {
  "==": eq,
  "!=": ne,
  ">": gt,
  "<": lt,
  ">=": ge,
  "<=": le,
  in: inside,
  not_in: notInside,
  contains,
  not_contains: notContains,
  matches,
};

export function applyOperator(op: string, a: unknown, b: unknown): boolean {
  const fn = OPERATOR_FUNCS[op as OperatorKey];
  if (fn === undefined) {
    throw new Error(`unknown arg operator: ${JSON.stringify(op)}`);
  }
  try {
    return fn(a, b);
  } catch {
    // Mirror Python `_ArgPred.evaluate` catching (TypeError, ValueError).
    return false;
  }
}