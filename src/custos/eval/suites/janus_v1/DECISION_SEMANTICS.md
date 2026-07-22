# Decision Semantics Mapping (lock)

This document locks how the Janus reference's decision vocabulary maps onto
Custos's `Decision` enum so the rest of  (and the eventual fold into
`src/custos/`) is unambiguous. It is the resolution of   bullet 3
("Resolve the decision-semantics mapping ").

## 1. Label mapping

| Janus label (from `handle_permission_denial` return dict) | Custos `Decision`  | Notes |
|---|---|---|
| `approve_once` | `allow_once` | One-time approval; not persisted to the policy set. |
| `create_policy` | `allow_and_persist` | One-time approval **and** a new ABAC rule is written so future identical calls short-circuit at policy evaluation (Janus's primary in-session fatigue mechanism). The rule dict travels in `AssistantOutput.persist_rule` for the gateway to compile + persist. |
| `reject` | `deny` | Call denied. In Custos this is final against the assistant. |
| _(none)_ | `prompt` | Custos extension: hand to a responder for human input. Janus simulates this via `user_confirmation` returning `reject`/`approve_once`, not via a distinct label. |
| _(none)_ | `defer` | Custos extension ("ask me later"). No Janus equivalent. |
| _(none)_ | `allow` | Custos standing allow. Janus has no standing-allow label distinct from `approve_once`; persistence is always via `create_policy`. |

The authoritative Custos enum lives at `src/custos/schema.py:Decision`. The
 re-implementations under `custos_phase0/` keep the **Janus** labels
internally (`approve_once` / `create_policy` / `reject`) so the parity numbers
are directly comparable to `Janus/metrics/submission_metrics.csv`; the mapping
above is applied at the boundary when the verified algorithms fold into
`src/custos/` after .

## 2. Interface gap: async (Janus) vs sync (Custos)

Janus assistants are `async` because the agent runtime (Google ADK + LiteLLM) is
async and the prompt hooks (`_ask`/`_confirm`) can be backed by an async
synthetic responder. The Janus abstract method (read at
`Janus/src/permissions/assistants/base.py:91-101`) is:

```
async def handle_permission_denial(subject, tool_name, action, args, failed_policies) -> Dict[str, Any]
```

Custos's `Assistant` Protocol (`src/custos/assistants/base.py`) is **synchronous**:

```
def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput
```

Decision (locked): **the Custos production `Assistant` Protocol stays sync**
(that is the  contract; we do not let Janus's async runtime shape the
production API).  re-implementations under `custos_phase0/` are async to
match the harness reality (synthetic-responder hooks + future LLM client are
async). When the verified algorithms fold into `src/custos/` post-Phase-0, the
async→sync boundary is handled by the gateway: the gateway runs the assistant
event-loop (or uses `asyncio.run` for the in-process embedding case), and the
production `Assistant.decide` is sync from the caller's perspective. This is
the same shape LangChain/OpenAI Agents use for their tool adapters.

## 3. The deny-floor departure (vs Janus semantics)

This is the single most important semantic gap between Custos and Janus, and it
is **deliberate**:

- **Janus** (`Janus/src/permissions/policy_engine.py:PolicySet.evaluate`,
  lines 200-233) is **default-allow-leaning**: if any applicable `PERMIT` rule
  matches, it permits; otherwise (including when only `DENY`-effect rules
  match) it denies by default. There is **no precedence for `DENY`-effect
  policies** — a `DENY` rule is effectively shadowed by any permitting rule.
  The "deny" comes from the empty-set default-deny, not from explicit deny
  rules. An assistant returning `approve_once` cannot be relaxed further, but
  there is no rule-level "floor" that an assistant cannot relax.

- **Custos**  enforces a **deny-floor / permit-ceiling**
  invariant: a policy `deny` is final; an assistant may only **escalate**
  strictness, never relax a denial. Assistant output is untrusted input.

For  parity this matters because M7 requires ±5% reproduction of the
**published Janus numbers**, which were produced under Janus's no-deny-floor
semantics. If Custos enforces its stricter  invariant during parity runs,
the numbers will not match on any scenario where a `DENY`-effect rule would
otherwise be shadowed.

Decision (locked): ** re-implementations reproduce Janus's exact
no-deny-floor semantics** (`custos_phase0/policy/engine.py:PolicySet.evaluate`
mirrors Janus lines 200-233). The Custos  invariant is a **production-only**
hardening that is *not* exercised for parity. The parity report
(`docs/PARITY_REPORT.md`) explicitly documents this departure: parity is
claimed against Janus semantics; production Custos is strictly safer than the
parity configuration. This is the same posture the  "License
incompatibility" mitigation implies ("re-implement rather than fork") — we
re-implement the *observable behavior* for parity, then harden for production.

## 4. `create_policy` persistence semantics

Janus `create_policy` (from `Janus/src/permissions/permission_manager.py:339-342`)
calls `self.create_policy(**new_policy)` which builds a `Policy`, adds it to the
in-memory `PolicySet`, and (`PermissionManager._save_policies`) writes to disk
**only if `--policy-file` was passed**. The harness's default matrix invocation
omits `--policy-file`, so created rules live in-process only and are lost when
the process exits. Each cell therefore starts from an empty policy set.

Custos  reproduces this exactly: `custos_phase0/run_harness.py` passes
no `--policy-file` by default; each cell run starts with an empty `PolicySet`;
in-session `create_policy` rules are kept in memory only.

## 5. Risk-tolerance expansion rule

To match the published 1440-row baseline, `--risk-tolerances 0.2,0.7` must
expand to a per-assistant effective tolerance as follows (re-implemented in
`custos_phase0/run_harness.py:resolve_risk_tolerance`):

| Assistant | Effective tolerance |
|---|---|
| `auto_approve` | `1.0` (always approves regardless of input) |
| `user_confirmation` | `0.0` (always defers to user — tolerance irrelevant) |
| `constitution` | unused (ignored) |
| `policy_suggestion` | unused (ignored) |
| `risk_assessment` | the CLI value, verbatim |
| `risk_assessment_autonomous` | the CLI value, verbatim |

For the 4 non-risk assistants only `args.risk_tolerances[0]` is used (so the
second tolerance value contributes zero extra cells); for the 2 risk assistants
both values expand. This is what makes `6 × 3 × 4 × 3 × 2 × 5 = 2160` collapse
to the observed `1440` rows in `submission_metrics.csv`.

## 6. Pointers

- Janus assistant base contract: `Janus/src/permissions/assistants/base.py:91-101`.
- Janus policy evaluation: `Janus/src/permissions/policy_engine.py:200-233`.
- Janus `create_policy` dispatch: `Janus/src/permissions/permission_manager.py:336-342`.
- Custos `Decision` enum: `src/custos/schema.py:Decision`.
- Custos deny-floor invariant:  .
-  reproducer engine: `phase0/src/custos_phase0/policy/engine.py`.