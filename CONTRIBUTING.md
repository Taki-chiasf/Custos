# Contributing to Custos

Custos is a drop-in permission middleware for AI agents. See `README.md`
for the project overview and `CHANGELOG.md` for recent changes. We welcome
contributions that improve quality, fix bugs, or add well-scoped features.

The project is Apache-2.0. **Do not vendor third-party code without
a license audit** — all contributions must carry compatible licensing
and be implemented behind clean interfaces.

## Getting started

1. Clone the repo.
2. Create a virtualenv: `python -m venv .venv && . .venv/bin/activate`.
3. Install the dev extra: `pip install -e '.[dev]'` (and any optional
   extras you intend to exercise, e.g. `pip install -e '.[yaml,llm,langchain]'`).
4. Verify:
   ```bash
   pytest -q                       # 492 passed, 1 known-fail on 3.13
   ruff check src tests            # clean
   mypy --strict src/custos        # clean across 75 source files
   ```
5. Run the end-to-end demo: `python examples/demo.py`.
6. Run the keyless adversarial suite:
   `custos eval --suite adversarial`.

Install pre-commit hooks:
```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

## Code style

- **Python ≥3.10** .
- `ruff` format + lint (config in `pyproject.toml`; selected rule sets
  `E, F, I, UP, B, SIM, C4`); `mypy --strict` over `src/custos`.
- **No emojis** in code, docs, or commit messages.
- **No comments unless asked** during a task; production code stays lean.
- Do not add new top-level files unless required; prefer editing.

### The import-shadowing filename rule (locked)

Several Custos integration adapter targets share a name with a Python
stdlib module or upstream SDK package. To avoid shadowing when a host
project does `from custos.integrations import <vendor>` (a tempting
re-export shape), the adapter filename MUST use a trailing underscore:

| Adapter module | Reason |
|---|---|
| `custos.integrations.anthropic_` | `anthropic` is the upstream SDK package name |
| `custos.integrations.mcp_` | `mcp` is the upstream SDK package name |
| `custos.integrations.openai_agents` | `agents` is the SDK package name but the conventional filename doesn't shadow a re-export path — no underscore needed |

A module named `anthropic.py` would, for any host that does
`from custos.integrations import anthropic`, shadow the upstream package
for the rest of the import graph. The adapter's `__dict__` therefore MUST
NOT host the bare vendor name; the trailing-underscore filename makes the
shadowing collision impossible.

This rule is locked for the v1.x line; deviations require a risk-mitigation
amendment.

### Runtime dependency discipline

The Custos **runtime** has zero hard deps beyond a JSON-schema validator
(`jsonschema>=4.21`). Framework adapters MUST import vendor SDKs strictly
**inside the adapter function bodies**, never at module top — `import custos`
with no extras installed never imports `anthropic` / `mcp` / `agents` /
`langchain` / etc. Each adapter carries a regression test of the shape
`test_import_custos_does_not_import_<vendor>` that drops the vendor package
from `sys.modules`, re-imports the adapter, and verifies it did not enter
`sys.modules`. New adapters MUST land an equivalent test.

The eval harness inherits Janus's parity-reproduction stack
(`google-adk`, `litellm`, `mcp[cli]`) and lives under the `[eval]` extra —
dev/test-only, never in the runtime dependency set.

### Security invariants

- **Policy is the floor.** An assistant can ONLY escalate strictness, never
  relax a `deny`. Treat assistant output as untrusted.
- Persisted rules from `allow_and_persist` MUST be structurally narrower
  than the rule they escalate from (H3 narrowness); broad globs /
  `any:true` / `allow` actions are rejected at insert time.
- Prompt payloads are signed; webhook responses are HMAC + nonce +
  timestamp verified. Redaction is recursive.
- Determinism first : policy evaluation is pure and deterministic.
  Assistants may be non-deterministic — that's the only allowed source.

## Tests

- The suite is the contract. Every FR fix / hardening landing MUST come
  with a test that would fail without the fix.
- Tests live under `tests/` organized by subsystem; adapter tests are
  `pytest.importorskip`-guarded so the suite stays green in a runtime-only
  install (no optional extras installed).
- The async suite uses a `_async_test` decorator (`asyncio.run`, no
  `pytest-asyncio` dep) — do not add `pytest-asyncio` to the dev extra.

## Commit policy

- Use clear conventional-commit prefixes (`feat(phaseN):`, `fix(phaseN):`,
  `chore:`, `docs:`). Include the phase number when relevant.
- The project rule: **do not commit unless explicitly asked.** The owner
  cuts phase commits; contributors open PRs.
- Release tags (`git tag v0.x.0`, `v1.0.0rc1`, `v1.0.0`) are owner actions.

## Scope

Map your change to a milestone target; do not silently shift scope. When
a scope deviation is warranted (e.g. an adapter scope narrowing),
flag it explicitly with a progress-log entry rather than amending the
feature list in silence.

Before declaring a non-trivial change done, run the full verification suite
(`pytest`, `ruff`, `mypy`) and, if the change touches the eval harness,
`custos eval --suite adversarial` or `--smoke`.