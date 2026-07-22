# Recipe: network-egress prompt

Anything that crosses the network — HTTP GET, `requests.post`, a curl shell
call, an SMTP email send — prompts the user. Read-only local work stays in
`allow_and_audit`; the network hop is the boundary that asks. This is the
shape of "ask for email sends, auto-allow read-only file ops" from .

## Policy

```yaml
version: 1
default: deny

overlays:
  - id: base
    rules:
      - match: { tool: "fs.read*", side_effects: [read] }
        action: allow_and_audit
      - match: { side_effects: [network] }
        action: prompt
      - match: { side_effects: [payment] }
        action: prompt
        options: [allow_once, deny]          # never a standing allow for money
      - match: { tool: "shell.*", args: { cmd: { matches: "^\\s*(curl|wget|ssh)\\b" } } }
        action: prompt                       # the shell tries to egress via curl
```

- `side_effects: [network]` is "any-of": a tool declaring
  `{network, write}` still matches the network rule (the side-effect set
  intersects).
- The shell rule uses an anchored `re.match` regex (operator `matches` for
  args predicates is start-anchored — see IR_CONTRACT). MS-DOS-style
  `\s*` lets the agent put a space before the command, which catches the
  common adversarial shape.
- The order matters: a `shell.cp` to localhost hits the `fs.read*` / general
  `shell.*` deny default only if no rule above matches. A shell call that
  starts with `curl ...` matches BOTH the order-of-rules matters: the
  network-rule catches it on the `args.cmd` predicate path before the generic
  `shell.*` rule would have.

## Wiring

```python
from custos import Gateway, Policy
from custos.assistants import RulePolicy
from custos.audit import FileAuditSink
from custos.responders import CLIResponder
from custos.fatigue import InMemoryFatigueLayer
from custos.sdk import set_default_context, wrap_callables
from custos.schema import SubjectContext

policy = Policy.from_yaml("policy.yaml")
gw = Gateway(policy=policy,
    assistant=RulePolicy,
    responder=CLIResponder(timeout=30),
    audit_sink=FileAuditSink("audit.jsonl"),
    fatigue=InMemoryFatigueLayer,          # dedup + suppression + rate limit)
set_default_context(SubjectContext(user_id="alice", goal_id="net-egress"))
```

`InMemoryFatigueLayer`  gives you:
- `dedup_ttl_s` cache: identical `(user, tool, args_hash)` re-resolves to the
  prior decision. A retry-spam agent doesn't re-prompt you.
- `allow for 10 min` (CLIResponder `A`) caches an allow.
- per-minute prompt rate limit (`max_prompts_per_minute`); overflow -> safe
  DENY + audit alert . Transient; does NOT poison the dedup cache
  (CacheableDecision invariant).

## What this guards against

- Data exfiltration via `http.post` with a payload the agent assembled — the
  prompt surfaces the **redacted** args before the call leaves the process.
- An agent wrapping exfiltration in `subprocess.check_output(["curl", url])`
  — the shell `matches:` rule catches the leading `curl`.

## What this does NOT guard against

- An agent that opens a TCP socket directly via `socket.create_connection`
  in a tool that **declares** `side_effects: [read]`. Custos governs on the
  descriptor; mitigate by pinning tool descriptors from a trusted registry.
  The threat model (forward-looking threats) notes this as the
  out-of-descriptor-lies gap.

## How to test this recipe in CI

```bash
custos eval --suite adversarial           # prompt-injection cells expect DENY
custos audit replay audit.jsonl --policy policy.tighter.yaml  # what-if analysis
```