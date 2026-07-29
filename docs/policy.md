# Policy schema

A Custos policy is a declarative ruleset evaluated top-down, first-match-wins
. Match criteria are AND-ed; an absent criterion matches everything.
The full YAML reference lives in [`docs/policy.example.yaml`](policy.example.yaml)
and the validator in [`custos/policy/schema.py`](https://github.com/Taki-chiasf/Custos/blob/main/src/custos/policy/schema.py).

## Top-level shape

```yaml
version: 1                       # int; must be 1
default: deny                    # 'deny' | 'allow' (default-deny recommended)
overlays:                        # ordered; scope filters concatenate in file order
  - id:-base
    scope: { user_id: "alice", goal_id: "g1", env: "prod" }   # optional
    rules:
      - match: { ... }
        action: <action>
        options: [...]             # for prompt
        batching: { window_ms: ..., max_per_minute: ... }
        quorum: 2
        approver_roles: [finance, security]
        approver_allowlist: [alice, bob]
```

`scope` is optional; absent scope = applies to all contexts. Each overlay
appends its rules; the matching rule across all overlays wins (`first-match`
over the concatenated list).

## Match criteria

| Field | Match shape |
|---|---|
| `tool` | `fnmatch` glob (`fs.read*` matches `fs.read_file`). |
| `risk_tier` | `int` (exact) or `[min, max]` (inclusive). |
| `side_effects` | list; rule matches if the tool's side-effects set intersects it (any-of). Values: `read`, `write`, `network`, `payment`, `destructive`, `pii`. |
| `args.<name>` | bare scalar = `==`; a single-operator dict applies one of `==, !=, >, <, >=, <=, in, not_in, contains, not_contains, matches` (selector `re.match` — start-anchored, IR_CONTRACT). |
| `goal_id` | exact match against `SubjectContext.goal_id`. |
| `delegation_depth` | exact match against `SubjectContext.delegation_depth` (use A11 for a gradient). |
| `any: true` | wildcard — match every call. Use for default rules + fatigue layer triggers. |

All AND together. `null`-bearing arg predicates return `false` (the IR
contract's null/type-error catch-and-return boundary; see IR_CONTRACT).
This is what makes the engine deterministic given (invocation, context,
policy_version) — .

## Actions

`allow`, `deny`, `prompt`, `assist:<name>`, `inspect:<name>`, `allow_and_audit`, `deny_and_alert`.

- `deny` short-circuits the pipeline (the floor invariant); an assistant is NEVER
  invoked on a policy `deny`.
- `assist:<name>` routes to a registered permission assistant by name .
  An unresolved name fail-closes to a safe `deny` + audit.
- `inspect:<name>` routes to a registered context inspector by name (A12).
  Requires a `ContextSnapshot` from the agent framework adapter. SAFE ->
  proceed to assistant; SUSPICIOUS -> prompt; INJECTION -> quarantine.
  An unresolved name fail-closes to a safe `deny` + audit.
- `allow_and_audit` short-circuits with an audit emit; no responder and no
  assistant consulted.

## Compose

Policies compose by stacking overlays. Base + per-user + per-env overlays
form a single concatenated rule list . Scope-on-overlay filters which
context the overlay applies to; e.g. `scope: { user_id: "alice" }` means the
overlay's rules only fire when the subject context's `user_id` is `alice`.

## Hot-reload

`Policy.reload` is mtime-based and atomic-swap. A malformed file leaves
the in-memory policy intact. `Gateway.reload_policy` also calls
`FatigueLayer.clear` so a stale cached allow cannot shadow a freshly
tightened policy.

The persisted-rule overlay (rules inserted via `allow_and_persist`) is
re-applied on top of file rules after a reload — in-session learning
survives a reload (addendum + H6).

## Quorum / approver hints

`quorum`, `approver_roles`, `approver_allowlist` are **rule-level responder
hints** — they ride alongside `match`/`action`/`batching`, NOT inside the
`MatchSpec`. The gateway extracts them via `_resolve_quorum` and forwards
to `PromptRequest`. The dedicated `MultiApproverResponder` consumes them.

Security: separation of duties — one role counts once toward the quorum. See
the [payment quorum cookbook recipe](cookbook/payment-quorum.md).

## Validation

`custos/policy/schema.py:validate_policy_file` + `validate_rule` validate
the file shape before `Policy.from_yaml` / `from_dict` build the engine.
A validation failure raises `PolicyValidationError(ValueError)`.

## Deterministic floor /

For `(invocation, context, policy_version)` the policy evaluation is
deterministic, pure, and reproducible. Assistants may be non-deterministic
by design (the only allowed source); an assistant `allow` never relaxes a
policy `deny` (the floor invariant).