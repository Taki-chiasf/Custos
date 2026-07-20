# Custos Cross-Language IR Contract

**Status:** v1.0 — locked at   (2026-07-20). Closes  Q12.
**Scope:** the deterministic subset of Custos that MUST behave identically
across the Python `custos` package and the TypeScript `@custos/core`
package , including the  sidecar gRPC schema that carries
LLM-backed assistant verdicts back to a TS agent.

This document is the **single source of truth** for cross-language
behavior. Any change to the items pinned below is a **contract-version
bump** and requires:

1. A coordinated update to both the Python and TS SDKs in the same release.
2. Bumping `AuditEvent.schema_version` (forwards) at both ends.
3. Updating the TS↔Python parity test fixtures
   (`packages/custos-ts/test/parity/fixtures/*.json`) so a parity
   regression cannot ship.

The Python implementation is the reference; the TS implementation MUST
match it. Where a language has no built-in equivalent (e.g. `fnmatch`
glob), the TS port ships a deterministic re-implementation and the
parity test asserts byte-equal hashes across the fixture set.

The contract is mechanical — no behavior is left to language-default
coercion semantics. Anything not pinned below is **out of contract** and
MUST NOT be relied on by a cross-language caller.

---

## 1. The `Decision` enum

Six members, exact string values. Member order is the canonical
ordering; `is_allow` is the only derived property to expose.

| Member | String value | Semantics  |
|---|---|---|
| `ALLOW` | `"allow"` | Standing allow (persisted policy rule). |
| `ALLOW_ONCE` | `"allow_once"` | One-time allow, no persistence. |
| `ALLOW_AND_PERSIST` | `"allow_and_persist"` | One-time allow + persist a new ABAC rule (Janus `create_policy`). |
| `DENY` | `"deny"` | Final deny; an assistant can never relax this (floor). |
| `PROMPT` | `"prompt"` | Hand to the responder for user input. |
| `DEFER` | `"defer"` | Defer the call (fatigue / ask-me-later). |

```ts
type Decision =
  | "allow"
  | "allow_once"
  | "allow_and_persist"
  | "deny"
  | "prompt"
  | "defer";
const isAllow = (d: Decision): boolean =>
  d === "allow" || d === "allow_once" || d === "allow_and_persist";
```

The Janus verdict mapping  is locked in
`custos.policy.operators.to_custos_decision`:

| Janus verdict | Custos `Decision` |
|---|---|
| `approve_once` | `allow_once` |
| `create_policy` | `allow_and_persist` |
| `reject` | `deny` |

`prompt` / `defer` are Custos-only extensions; they have no Janus source
label and MUST NOT appear in the verdict mapping.

## 2. `PolicyOutcome` (intermediate, step 2 of the pipeline)

The deterministic policy engine returns one of four values; the rest of
the pipeline maps them to a final `Decision`.

| Member | String value | Pipeline step |
|---|---|---|
| `ALLOW` | `"allow"` | Step 2 — short-circuits to `Decision.ALLOW`. |
| `DENY` | `"deny"` | Step 2 — short-circuits to `Decision.DENY`. Floor; NOT relaxable by an assistant . |
| `PROMPT` | `"prompt"` | Step 2 — skips assistant, hands to responder. |
| `ASSIST` | `"assist"` | Step 2 — invoke the named assistant . |

## 3. ABAC operator set (dual-engine lock)

Eleven operators; the string keys are identical in
`custos.policy.operators.OPERATOR_FUNCS` and in the eval-harness
`JanusOperator` enum. The TS SDK MUST use the same string keys and the
same semantics.

| Key | Python impl | Semantics |
|---|---|---|
| `==` | `bool(a == b)` | Equality. |
| `!=` | `bool(a != b)` | Inequality. |
| `>` | `bool(a > b)` | Greater-than. |
| `<` | `bool(a < b)` | Less-than. |
| `>=` | `bool(a >= b)` | Greater-or-equal. |
| `<=` | `bool(a <= b)` | Less-or-equal. |
| `in` | `a in b` | Membership: `a` is a member of container `b`. |
| `not_in` | `a not in b` | Non-membership. |
| `contains` | `b in a` | `a` contains `b` (args reversed from `in`). |
| `not_contains` | `b not in a` | `a` does NOT contain `b`. |
| `matches` | `bool(re.match(b, a))` if `a` is `str` else `False` | Regex match. **See  for anchoring.** |

### Null / type-error handling (the cross-language hazard)

When a Python operator raises `TypeError` or `ValueError` for a given
`(arg_value, predicate_value)` pair, the production match engine
catches the exception and the predicate evaluates to **`False`**
(see `custos.policy.match._ArgPred.evaluate`). The TS port MUST do the
same: a type-mismatched comparison resolves to `false`, never to an
exception, never to `undefined`.

Specifically:

| Operator | `arg_value` | `predicate_value` | Result | Note |
|---|---|---|---|---|
| `in` | `false` (or any) | `undefined` / `null` | `false` | `a in b` raises `TypeError` when `b` is `None`. |
| `contains` | `undefined` / `null` | any | `false` | `b in a` raises `TypeError` when `a` is `None`. |
| `>` / `<` / `>=` / `<=` | `3` | `"foo"` | `false` | Cross-type comparison raises `TypeError` in Python 3; JS would coerce. **TS MUST guard explicitly** (no `>` across `number|string` — return `false`). |
| `matches` | `123` (non-string) | any pattern | `false` | Well-defined in the operator itself; do NOT pass a non-string to the regex engine. |
| `in` | `"x"` | `"xyz"` | `true` | Strings are iterable in Python (`"x" in "xyz"` is `true`); **TS MUST special-case `string`-in-`string`** because JS `in` does NOT support it. |

**The contract:** the Python behavior is canonical; each TS operator MUST
produce the same `boolean` result for the same `(arg_value, predicate_value)`
pair across the parity fixture set .

## 4. Regex anchoring (the cross-language hazard)

Two distinct regex surfaces exist; they MUST NOT be conflated:

| Surface | Python function | Anchoring |
|---|---|---|
| Arg predicate `matches` operator | `re.match(b, a)` | **Start-anchored only** (`re.match` anchors at the start of string; the END is NOT anchored). Equivalent to `"^" + b` against `a`. |
| Tool name glob `match.tool` | `fnmatch.fnmatchcase(inv.tool, self.tool_glob)` | **Not regex** — `fnmatch` glob with `*` / `?` / `[seq]`; case-sensitive. See . |

The `matches` operator is intentionally **prefix-anchored, not
fully-anchored** — this is observable behavior in
`custos.policy.operators.matches`. The TS port MUST use the JS regex:

```ts
const matches = (a: unknown, b: string): boolean =>
  typeof a === "string"
    ? new RegExp(b.startsWith("^") ? b : "^" + b).test(a)
    : false;
```

(Callers who need full-string match author their pattern with a trailing
`$`; the contract pins the start-anchor as the default so an author
intuition of "the start matches" matches the existing v1.0rc1 semantics.)

JSON-schema `patternProperties` redaction
(`custos.schema._simple_pattern_match`) uses `re.search` — unanchored.
This is a REDACTION surface, not a POLICY match surface; it is pinned in
 and MUST NOT be confused with the `matches` operator above.

## 5. Tool-name glob (`fnmatch` semantics)

The `match.tool` match criterion is evaluated via
`fnmatch.fnmatchcase(name, glob)` — case-sensitive Python `fnmatch`.

Glob translation table (`fnmatch.translate`):

| Glob char | Matches |
|---|---|
| `*` | Zero or more characters (any). |
| `?` | Exactly one character (any). |
| `[seq]` | Any character in `seq` (ranges supported `[a-z]`, negation `[!seq]`). |
| `\` | Escapes the next glob char. |
| everything else | Literal character. |

The TS port MUST re-implement `fnmatchcase` deterministically (the
parity fixture set includes `["fs.read", "fs.read_file", "fs.r*",
"*.read", "fs.[rs]*", "fs.\\*"]` covering the wildcard, character-class,
and escape forms). JS `minimatch` is NOT acceptable — it defaults to
case-insensitive on Windows and expands `**` differently; the port MUST
ship the Python `fnmatch` semantics verbatim.

## 6. `_args_hash` canonicalization (/ H13)

Deterministic SHA-256 of the canonicalized args, used as the dedup
cache key  and the A10 learned-policy store key. The canonical
form is shared between Python (`custos.fatigue._canonicalize` +
`hashlib.sha256(json.dumps(...))`) and the TS port.

### Canonicalization rules

| Input type | Canonical form |
|---|---|
| `dict` / mapping | Object with **keys sorted lexicographically by UTF-8 byte order**, each value recursively canonicalized. |
| `list` / `tuple` | Array with **order preserved** (positional semantics); each element recursively canonicalized. |
| `set` | Array with **elements sorted**: numbers numerically, strings lexicographically by UTF-8 byte order, mixed types by `repr`-equivalent string order. Sets of unhashable elements are not supported (Python `set` semantics). |
| `bool` / `int` / `float` / `str` / `None` | Themselves; no coercion. |
| any other type | The Python `repr` string of the object. **TS equivalent:** `Object.prototype.toString.call(value)` is NOT the same; the parity fixture set  pins the canonical string per type, and the TS port MUST match those fixtures exactly. Pinned shortlist (the only non-JSON-serializable types that appear in test fixtures): `datetime` → the Python `repr`, captured as a fixture; complex objects from third-party SDKs are out-of-contract and MUST NOT be passed as args. |

### Hashing

```python
canonical = _canonicalize(args)
return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode).hexdigest
```

- JSON serialization uses `json.dumps(..., sort_keys=True)` so the
  canonical form is byte-stable across runs. The TS port uses
  `JSON.stringify(canonical)` with a stable key-sorting walker
  (the JS `JSON.stringify` does NOT sort keys by default — the port
  MUST sort keys in the canonicalization walker before stringify, then
  string-encode as UTF-8).
- The hash input is **UTF-8 encoded JSON**. No BOM, no native line
  endings, no trailing newline.
- No separators customization is pinned (Python `json.dumps` default
  `", "` / `": "` separators are the canonical form); the TS port
  MUST produce a byte-identical string. The parity test asserts
  byte-equality of the hash input string, not just hash equality.

### Parity fixture set  — the same set of args dicts run through
both the Python and the TS canonicalizer; each fixture has a pinned
canonical-JSON string and a pinned SHA-256. Any divergence fails both
suite rows.

## 7. `expires_at` / monotonic clock

The dedup/suppression cache uses a **monotonic clock** (`time.monotonic`
in Python). Monotonic time is **NOT** portable across languages or
even across processes — `time.monotonic` is meaningful only within
one process. The contract therefore pins the **shape** of the cache
entry, not the wall-clock value:

```python
@dataclass
class _CacheEntry:
    decision: Decision
    expires_at: float  # monotonic deadline; opaque outside the process
```

The TS port uses `performance.now` (browser / Node) and stores the
deadline as `number` (the JS `performance.now` returns ms; the
contract stores it as **seconds** with fractional precision to match
the Python `time.monotonic` unit — the TS port MUST convert
`performance.now / 1000` before storing).

Cross-language interaction: the cache NEVER crosses a process boundary
(single-process state —  HA deferred to v1.1). The `expires_at`
field is NOT part of the sidecar gRPC schema : a sidecar caller
receives a resolved `Decision`, not a cache entry, and re-evaluates
locally with its own cache.

`deadline_unix_ms` on `PromptRequest`  is a wall-clock deadline
because it is observable by the responder across the process boundary
— monotonic time would be useless for an out-of-band Slack responder.
This is the ONLY wall-clock field in the contract; the contract pins
it as **Unix milliseconds** (signed 64-bit; the TS port uses `bigint`
for fidelity, not JS `number`, to avoid floating-point drift past
~8.6e15 ms).

## 8. Wire shapes (JSON)

### 8.1 `ToolDescriptor`

```json
{
  "name": "fs.read",
  "risk_tier": 2,
  "reversible": false,
  "side_effects": ["read"]
}
```

- `risk_tier`: integer 1..5 (inclusive); out-of-range raises
  `ValueError` / MUST throw in TS at construction time.
- `side_effects`: array of `SideEffect` string values, **sorted
  lexicographically**. TS MUST sort the same way.

### 8.2 `SubjectContext`

```json
{
  "user_id": "alice",
  "goal_id": "task-42",
  "task_id": null,
  "delegation_chain": ["alice", "bob", "carol"],
  "session_ttl": 3600,
  "extra": { "user_id": "alice" }
}
```

- `delegation_chain`: ordered array, **shallowest-first**.
  `delegation_depth = delegation_chain.length`.
- `extra`: free-form, but **audit serialization filters to
  `AUDIT_SUBJECT_FIELDS`** (`{"user_id", "goal_id", "task_id"}`). The
  wire shape above reflects the FILTERED form emitted by
  `SubjectContext.to_dict`; an unfiltered `extra` never crosses the
  audit boundary (deep redaction).
- `null` is `null` (JSON `null`), not the string `"null"`. The TS port
  MUST round-trip `null` rather than `undefined` because `undefined`
  is dropped by `JSON.stringify`.

### 8.3 `Invocation`

```json
{
  "tool": "fs.read",
  "args": { "path": "/etc/hosts" },
  "request_id": "req_abc",
  "descriptor": { "name": "fs.read", "risk_tier": 2, ... }
}
```

(Note: `args` here are the UNREDACTED invocation args; the sidecar
schema  carries a separate `args_redacted` field on the
`PromptRequest`-equivalent message. The redacted form is produced
client-side before any cross-boundary send — see .)

### 8.4 `AuditEvent`

```json
{
  "ts_unix_ms": 1721476800000,
  "invocation": { "tool": "...", "args": {...}, "request_id": "...", "descriptor": null },
  "decision": "allow_once",
  "policy_match": "base:fs.read-only",
  "assistant": "risk-assessment",
  "risk_score": 0.21,
  "reasoning": "low-risk read within goal scope",
  "responder": null,
  "latency_ms": 31,
  "subject": { "user_id": "alice", "goal_id": null, "task_id": null,
               "delegation_chain": [], "session_ttl": null,
               "extra": {} },
  "approver": null,
  "quorum_state": null
}
```

- `ts_unix_ms`: Unix milliseconds (signed 64-bit, same caveat as
  `deadline_unix_ms`).
- `invocation.args`: the REDACTED args — `AuditEvent.invocation` is
  built from `Invocation.with_redacted_args` by the gateway.
- `risk_score`: float 0.0..1.0.
- `latency_ms`: integer.
- `quorum_state`: `"met"` / `"failed"` / `null`. Only set on
  prompt-resolved decisions under a `quorum` rule; `null` everywhere
  else.   .
- `schema_version`: **forward field** — the v1.0rc1 Python impl does
  NOT emit it;  (audit tamper-evidence) introduces it
  with the value `"1.0"`. The TS port ships `schema_version: "1.0"`
  from day one and the Python side adds the same field at . Until
   the field is OPTIONAL and consumers MUST tolerate its absence.

### 8.5 `PromptRequest` / `PromptResponse`

`PromptRequest` (gateway → responder):

```json
{
  "tool": "email.send",
  "args_redacted": { "to": "[REDACTED]", "subject": "hi" },
  "risk": 0.62,
  "reasoning": "recipient outside trusted set",
  "options": ["allow", "deny", "allow_once"],
  "request_id": "req_abc",
  "deadline_unix_ms": 1721476830000,
  "quorum": 2,
  "approver_roles": ["finance", "security"],
  "approver_allowlist": ["alice", "bob"]
}
```

`PromptResponse` (responder → gateway):

```json
{
  "choice": "allow_once",
  "ttl": 600,
  "signature": null,
  "nonce": null,
  "approver": "alice"
}
```

- `signature` / `nonce`: webhook-only; emitted by `WebhookResponder` per
  . They are out-of-contract for CLI / noop / Slack / web (always
  `null` on the wire). The TS port serializes absent signature as
  `null` (not `undefined`).
- `approver`: responder-attested identity (H12 /).

## 9. Sidecar gRPC schema (deliverable; pinned here)

The  sidecar exposes `Gateway.decide` over gRPC. The schema is
pinned in this contract so the TS `@custos/core` SDK can codegen
against it at  — the sidecar ships at  but the IR is locked
here.

### 9.1 Service

```proto
syntax = "proto3";
package custos.v1;

// Custos gateway sidecar service. The  floor is enforced at the
// sidecar; the caller (TS or another Python process) re-applies the
//  floor LOCALLY on the returned verdict — assistant output is
// untrusted across the boundary.
service CustosGateway {
  rpc Decide(DecideRequest) returns (DecideResponse);
}

// The request carries the FULL, UNREDACTED invocation plus the caller
// attestation. The sidecar redacts before audit; it does NOT echo
// unredacted args back.
message DecideRequest {
  Invocation invocation = 1;
  // mTLS is the transport auth; this is the caller identity attested
  // by the mTLS cert, cross-checked against the OIDC bearer below.
  string caller_id = 2;
  // OIDC bearer (or local signed-token); empty when the caller is the
  // mTLS principal only.
  string bearer = 3;
  // Per-call request_id / nonce; replayed nonce -> DENY .
  string request_id = 4;
  // Per-tenant rate-limit key (single-tenant guard rail for v1.0 per
  // decision D19). Empty for the global default tenant.
  string tenant_id = 5;
}

message Invocation {
  string tool = 1;
  // Unredacted args; the sidecar redacts before building an AuditEvent.
  google.protobuf.Struct args = 2;
  SubjectContext context = 3;
  ToolDescriptor descriptor = 4;
  string request_id = 5;
}

message SubjectContext {
  string user_id = 1;
  string goal_id = 2;
  string task_id = 3;
  repeated string delegation_chain = 4;
  int32 session_ttl = 5;
  google.protobuf.Struct extra = 6;
}

message ToolDescriptor {
  string name = 1;
  int32 risk_tier = 2;
  bool reversible = 3;
  repeated string side_effects = 4;
  google.protobuf.Struct schema = 5;
}

message DecideResponse {
  Decision decision = 1;
  // Audit event the caller SHOULD persist locally (the sidecar also
  // persists its own copy). The  floor is enforced at BOTH ends.
  AuditEvent audit_event = 2;
  // Server-side latency for SLO observability (excludes network).
  int32 server_latency_ms = 3;
  // Sidecar-assigned expiry of the verdict the caller SHOULD honour
  // when caching the decision locally (monotonic to the caller's
  // process, NOT the sidecar's —).
  int64 verdict_cache_ms = 4;
  // Verdict chain verifiable by the caller: the sidecar's HMAC over
  // (decision, request_id, ts_unix_ms, risk_score) —  replay guard
  // at the boundary. Empty when the caller is the sidecar's own mTLS
  // principal AND the operator disabled verdict signing.
  bytes verdict_signature = 5;
}

enum Decision {
  DECISION_UNSPECIFIED = 0;
  ALLOW = 1;
  ALLOW_ONCE = 2;
  ALLOW_AND_PERSIST = 3;
  DENY = 4;
  PROMPT = 5;
  DEFER = 6;
}

message AuditEvent {
  int64 ts_unix_ms = 1;
  Invocation invocation = 2;
  Decision decision = 3;
  string policy_match = 4;
  string assistant = 5;
  double risk_score = 6;
  string reasoning = 7;
  string responder = 8;
  int32 latency_ms = 9;
  SubjectContext subject = 10;
  string approver = 11;
  string quorum_state = 12;
  // Forward : tamper-evidence schema version. The
  // sidecar emits "1.0" from day one; the in-process Python impl adds
  // it at . Optional in the wire shape — empty == "unversioned".
  string schema_version = 13;
}
```

### 9.2 Wire-shape cross-overs

- `google.protobuf.Struct` carries arbitrary JSON. The sidecar MUST
  round-trip UTF-8 strings, integers, doubles, booleans, `null` — and
  MUST reject (DENY + audit alert) any field value that does not fit
  that JSON-shaped envelope. The Python `_args_hash` canonical form
   is what the sidecar hashes server-side; the caller NEVER sees
  the canonical form (it sees only the verdict + audit event).
- `Decision` proto enum starts at 1 (`DECISION_UNSPECIFIED = 0` is
  required by proto3); a 0 client-side is a hard error → safe `DENY`
  at the local floor . The string values in
  `AuditEvent.decision` (JSON) stay the  lowercase strings; the
  proto enum is a separate encoding for the gRPC channel and is NOT
  used in the JSONL audit sinks.
- `verdict_signature` (replay guard) is HMAC-SHA256 over
  `decision.name|request_id|ts_unix_ms|risk_score` (pipe-delimited,
  ASCII); the caller verifies it with the operator-published
  sidecar HMAC key (`SECURITY_PGP.pub`-adjacent deployment artifact
  at v1.0, owner action). A failed signature verification MUST
  downgrade the verdict to `DENY` locally per  (assistant output
  is untrusted across the boundary, and so is sidecar output).

### 9.3  floor is LOCAL

A TS caller routes `assist:risk-assessment` to the sidecar (per D17 —
the LLM-backed assistants live server-side). The sidecar returns a
verdict. The TS `Gateway.decide` re-runs the policy engine on the
same invocation LOCALLY; if the local policy says `DENY`, the
sidecar's `ALLOW*` is dropped and the final decision is `DENY`. This
mirrors the in-process invariant : policy is the floor, an
assistant cannot relax it — including an assistant reached over the
network. The parity test (`packages/custos-ts/test/parity/`)
includes a fixture row for this case.

## 10. Parity fixture set (v1.0)

The  TS port ships `packages/custos-ts/test/parity/fixtures/`
containing JSON fixture rows the Python reference also consumes. Each
row exercises one pinned item; the parity test runs the same row
through both walkers and asserts byte-equal output. The set is
versioned with the contract (bump on any change):

- `args_hash/` — 30+ rows covering `_args_hash` canonicalization
  across dicts (key-order permutations), tuples vs. lists, sets
  (number, string, mixed), nested composites, `None` / `bool` /
  `int` / `float`, string UTF-8 keys, the pinned non-JSON-scalar
  `repr` cases.
- `operators/` — ≥11 rows × 5 null/type edge cases each (165+ rows)
  covering every ABAC operator including the JS-foreign cases from
   (`string`-in-`string`, `>` across `number|string`).
- `regex/` — rows covering start-anchored `matches`, `patternProperties`
  unanchored redaction, and the divergence trap (a `matches` pattern
  with a trailing `$` vs. without — both must produce the same
  decision in Python and TS).
- `glob/` — rows covering `fnmatch` wildcards, character classes,
  negation, and the `\\*` escape.
- `decision/` — rows covering the 6 `Decision` values round-tripped
  through JSON.
- `wire/` — rows covering full `AuditEvent` / `ToolDescriptor` /
  `SubjectContext` / `Invocation` / `PromptRequest` / `PromptResponse`
  JSON round-trips (the `schema_version` forward-field case is pinned).
- `sidecar/` — rows for the  floor-is-local case: a sidecar
  `ALLOW*` dropped when the local policy says `DENY`.

A row failing the parity test blocks the  cut (and therefore the
v1.0 GA at). Adding a row is a contract-non-breaking enhancement
(allowed in a patch release once the contract is locked); renaming /
removing / changing the semantics of a row is a contract-version bump
(§disclaimer at top).

## 11. Forbidden cross-language behaviors

These are explicitly NOT in contract and a caller / port MUST NOT rely
on them:

- **Floating-point precision**: the JSON wire shape uses native
  `double` / Python `float` for `risk_score` and `latency_ms` is
  integer; the contract pins the JSON encoding (no NaN / Infinity —
  `json.dumps` rejects them anyway). A port MUST produce canonical
  JSON, not native struct serialization.
- **Timezone-aware timestamps**: only `ts_unix_ms` and
  `deadline_unix_ms` are portable. Anything else (`expires_at`
  monotonic, internal batch-window timers) is process-local and does
  not cross the boundary.
- **Datetime objects** as arg values: out of contract. Pass ISO-8601
  strings; the parity fixture set pins the canonical `repr` for the
  one test fixture only so the canonical-form diverter does NOT
  silently misbehave for a real call.
- **Enums other than `Decision`**: `PolicyOutcome` is in-process only
  (never crosses the sidecar, never in JSONL audit).
- **Native object identity**: the contract pins JSON shapes, not
  pointers. A `ToolDescriptor` with the same five fields is equal
  across the boundary even if the Python dataclass and the TS class
  are different language objects.
- **Exception types**: the contract pins the VERDICT (`false` /
  `DENY`) on type errors, NOT the exception object. A port MUST NOT
  throw an exception across the boundary; it MUST downgrade to a
  verdict.

## 12. Contract version

This is `IR_CONTRACT.md` v1.0. The version is
`AuditEvent.schema_version == "1.0"` (onwards; absent before).
A bump updates both SDKs + this document + the parity fixture set in
the same release; the `[Unreleased]` section of `CHANGELOG.md`
records the bump rationale. Until the v1.0 GA cut , this
document is allowed to receive non-breaking clarifications; after
, any change is a contract bump.

---

**Provenance.** This contract is the mechanical pinning of the v1.0rc1
Python implementation in `Custos/src/custos/` (cut, 2026-07-20).
The reference files are: `custos/schema.py` ;
`custos/policy/operators.py` and `custos/policy/match.py` ;
`custos/fatigue/__init__.py` . The sidecar gRPC schema  is
new in  — it does NOT have a v1.0rc1 implementation reference; it
is the spec the  sidecar ships against and the  TS port codegens
against. The  floor-is-local rule  is restated from  and
is the authoritative invariant under which both surfaces operate.