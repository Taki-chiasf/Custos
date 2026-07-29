# Context Inspectors (A12)

A12 — `ipi-defender` — is Custos's selective IPI (Indirect Prompt Injection)
defence. Unlike permission assistants (A1–A11), which operate on a single tool
invocation, a context inspector runs with access to the agent's full
conversation context (messages, input sources, system prompt).

## How it works

```
    Tool call
       |
   ┌────▼─────┐
   │ 1.Policy │  Policy says "inspect:ipi-defender"
   └────┬─────┘
        │
   ┌────▼─────┐
   │ 2.A12    │  Context inspector analyses full conversation
   │  (new)   │  SAFE / SUSPICIOUS / INJECTION
   └────┬─────┘
        │
  ┌─────┼─────────────┐
  │     │             │
  SAFE  SUSPICIOUS    INJECTION
  │     │             │
  ▼     ▼             ▼
 Asst  PROMPT        QUARANTINE
  │     (human)      (block + memory wipe)
  ▼
Responder
```

### Fast path (<50ms)

Runs on every invocation. Uses:
- **Pattern matching** against known injection markers: `<INSTRUCTION>`, `[SYSTEM]`,
  `[EXECUTE]`, `[URGENT]`, jailbreak phrases (DAN, "ignore prior instructions"),
  exfiltration patterns (send email contents, delete sent email)
- **Homoglyph detection** for Unicode substitution attacks
- **Base64 payload detection** for smuggled content
- **N-gram similarity** against a reference bank of known injection patterns

The fast path is pure Python with zero dependencies — it works in the runtime
dep-set without additional packages.

### Deep path (LLM-backed, async)

Opt-in leave-one-out causal attribution. When enabled:

1. For each SUSPICIOUS source identified by the fast path, a lightweight judge
   LLM re-evaluates the agent's decision with that source removed
2. If removing the source changes the agent's action from malicious to benign,
   the source is attributed as the injection vector
3. Results are applied on the **next turn** via CoT masking

Enable deep attribution:
```python
from custos.inspectors import IPIDefender

inspector = IPIDefender(
    deep_attribution_enabled=True,
    judge_llm=my_llm_callable,  # async def judge(prompt: str) -> str
    max_attribution_sources=3,
)
```

### CoT masking

When injection sources are found, the inspector walks the conversation history
and masks messages whose content has high n-gram similarity to the attributed
source. Masked messages are replaced with `[REDACTED - potential injection
influence]` in the returned `masked_snapshot`.

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `similarity_threshold` | 0.25 | Jaccard threshold for reference bank similarity |
| `suspicious_threshold` | 0.4 | Score above which verdict is SUSPICIOUS |
| `injection_threshold` | 0.7 | Score above which verdict is INJECTION |
| `deep_attribution_enabled` | False | Enable LLM-backed leave-one-out attribution |
| `max_attribution_sources` | 5 | Max candidate sources for deep attribution |
| `judge_llm` | None | Async callable for deep attribution re-evaluation |
| `mask_threshold` | 0.3 | Jaccard threshold for CoT masking |

## Wiring

### Global inspector (blanket coverage)
```python
from custos import Gateway, Policy
from custos.inspectors import IPIDefender

gw = Gateway(
    policy=Policy.from_yaml("policy.yaml"),
    assistant=my_assistant,
    responder=my_responder,
    inspector=IPIDefender(),
)
```

### Policy-routed (per-tool)
```yaml
# policy.yaml
rules:
  - match: {tool: "email.*"}
    action: "inspect:ipi-defender"
  - match: {tool: "fs.*"}
    action: "assist"
```

The `inspect:<name>` action routes to a named inspector registered with the
gateway. The bare `inspect` action routes to the default (first registered)
inspector.

### SDK context provider

The inspector needs a `ContextSnapshot` — your SDK adapter provides it:
```python
from custos.sdk import wrap_callables, ContextProvider, MemoryWipe

class MyContextProvider:
    def get_snapshot(self):
        return ContextSnapshot(
            ts_unix_ms=...,
            messages=...,
            sources=[InputSource(...)],
            system_prompt=...,
        )

gated_tools = wrap_callables(
    gateway, my_tools,
    context_provider=MyContextProvider(),
)
```

### Memory wipe on QUARANTINE

When the inspector returns INJECTION, the gateway emits `Decision.QUARANTINE`.
Your adapter's `MemoryWipe` implementation sanitises the agent context:
```python
class MyMemoryWipe:
    def sanitize(self, context, sources, strategy):
        # Clear/rollback/sanitize the agent's conversation
        return cleaned_context
```

## Decision pipeline flow

| Verdict | Decision | Effect |
|---------|----------|--------|
| SAFE | Proceed to assistant | Normal flow: assistant evaluates the call |
| SUSPICIOUS | PROMPT | Route to human review via responder |
| INJECTION | QUARANTINE | Block call + trigger SDK memory wipe + audit |

The inspector floor: an inspector can only escalate strictness
(SAFE -> SUSPICIOUS -> INJECTION -> QUARANTINE), never relax.
Matches the existing assistant floor invariant.
