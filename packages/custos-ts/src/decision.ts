// Custos Decision enum — IR_CONTRACT.md  .

// Six members; the string values are the canonical wire form and MUST
// match the Python `custos.schema.Decision` enum byte-for-byte.
// `isAllow` is the single derived property to expose. The Janus → Custos
// verdict mapping (table) is locked here too.

export const DECISION_VALUES = [
  "allow",
  "allow_once",
  "allow_and_persist",
  "deny",
  "prompt",
  "defer",
] as const;

export type Decision = (typeof DECISION_VALUES)[number];

export const isAllow = (d: Decision): boolean =>
  d === "allow" || d === "allow_once" || d === "allow_and_persist";

// Intermediate policy engine outcome . ASSIST is the only one that
// advances to step 3 (the named assistant).
export const POLICY_OUTCOME_VALUES = ["allow", "deny", "prompt", "assist"] as const;
export type PolicyOutcome = (typeof POLICY_OUTCOME_VALUES)[number];

// Janus → Custos verdict mapping (mirrors
// `custos.policy.operators.to_custos_decision`).
const JANUS_TO_CUSTOS: Record<string, Decision> = {
  approve_once: "allow_once",
  create_policy: "allow_and_persist",
  reject: "deny",
};

export function toCustosDecision(janusVerdict: string): Decision {
  const mapped = JANUS_TO_CUSTOS[janusVerdict];
  if (mapped === undefined) {
    throw new Error(`unknown Janus verdict: ${JSON.stringify(janusVerdict)}`);
  }
  return mapped;
}

export function asDecision(s: string): Decision {
  if (!DECISION_VALUES.includes(s as Decision)) {
    throw new Error(`unknown Decision: ${JSON.stringify(s)}`);
  }
  return s as Decision;
}