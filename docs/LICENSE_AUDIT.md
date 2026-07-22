# Custos license audit (v1.0)

Normative license-audit artifact for the v1.0 cut . Covers the Python runtime, the optional extras, the TypeScript
packages, the vendored test fixtures, and the Janus reference upstream.

The audit lives at `docs/LICENSE_AUDIT.md` so it is part of the docs
site (referenced from `docs/index.md`). First audit was
(`Custos/phase0/docs/PARITY_REPORT.md`); this  re-run covers the
new TS-vendored code and confirms the  findings still hold.

## 1. Custos core (the shipped runtime)

| Component | Path | License | Notes |
|---|---|---|---|
| Python runtime | `src/custos/` | Apache-2.0 | Authoritative LICENSE at repo root. |
| TypeScript SDK `@taqiy/custos-core` | `packages/custos-ts/` | Apache-2.0 | Per-package `LICENSE` file. `"license": "Apache-2.0"` in `package.json`. Zero runtime deps (-equivalent). |
| gRPC sidecar client `@taqiy/custos-grpc` | `packages/custos-grpc/` | Apache-2.0 | Per-package `LICENSE` file. `"license": "Apache-2.0"` in `package.json`. |
| gRPC schema | `src/custos/sidecar/custos_v1.proto`, `packages/custos-grpc/proto/custos_v1.proto` | Apache-2.0 | Authored by us. `package custos.v1`. IR_CONTRACT  is the canonical spec; both copies of the `.proto` are kept byte-equal intentionally. |

## 2. Optional extras (Python)

All optional extras  carry their own upstream licenses;
each is gated behind `pip install custos-middleware[<extra>]` so a runtime-only
install never pulls them.

| Extra | Upstream license | `_`-filename rule? |
|---|---|---|
| `[yaml]` (PyYAML) | MIT | n/a (no adapter) |
| `[llm]` (litellm) | MIT | n/a (adapter in `integrations/litellm_.py`, but `litellm` does not collide with a stdlib name — no `_` rule needed) |
| `[langchain]` (langchain-core) | MIT | n/a (adapter `langchain.py`; no stdlib collision) |
| `[mcp]` (mcp v1.x) | MIT | yes — adapter `mcp_.py` (shadows upstream `mcp`) |
| `[openai-agents]` (openai-agents 0.x) | MIT | no — adapter `openai_agents.py` (upstream pkg is `agents`, no collision) |
| `[anthropic]` (anthropic 0.x) | MIT | yes — adapter `anthropic_.py` (shadows upstream `anthropic`) |
| `[sidecar]` (grpcio + protobuf) | Apache-2.0 (grpcio), BSD-3-Clause (protobuf) | n/a (no SDK adapter) |
| `[autogen]` (autogen-agentchat 0.4) | MIT | yes — adapter `autogen_.py` (shadows upstream `autogen`) |
| `[google-adk]` (google-adk 1.x) | Apache-2.0 | yes — adapter `google_adk_.py` (shadows upstream `google.adk` namespace) |
| `[llamaindex]` (llama-index-core 0.12) | MIT | yes — adapter `llamaindex_.py` (shadows upstream `llama_index`) |
| `[telemetry]` (opentelemetry-sdk + prometheus-client) | Apache-2.0 (OTel), Apache-2.0 (prometheus-client) | n/a (no adapter; sinks live in `custos.telemetry`) |
| `[eval]` (google-adk + litellm + mcp[cli] + PyYAML + rich + python-dotenv + requests) | mixed MIT/Apache-2.0 | n/a (eval harness, dev/test-only) |
| `[docs]` (mkdocs-material) | MIT | n/a (docs-only) |

All upstream licenses are Apache-2.0-compatible (the project license).
`protobuf` is BSD-3-Clause, also Apache-2.0-compatible.

## 3. Optional extras (TypeScript)

| Package | Upstream license | PepDep shape |
|---|---|---|
| `@taqiy/custos-grpc` `@grpc/grpc-js` (peer) | Apache-2.0 | peer dep — operator pins the tested-minimum; the `@taqiy/custos-grpc` tarball does NOT bundle the dep |
| `@taqiy/custos-grpc` `@grpc/proto-loader` (peer) | Apache-2.0 | peer dep — same |

`node_modules/` is gitignored and excluded from the `"files"` block in
each `package.json` so the published npm tarball ships ONLY our source
(`dist/`), the proto schema, the per-package `LICENSE`, and the README.

## 4. Vendored test fixtures

The TypeScript `packages/custos-ts/test/parity/fixtures/*.json` files are
**Python-generated** test data (canonical-form fixtures the Python
reference emitted — used to assert byte-equal output from the TS port).
Generated test data does not carry upstream licenses; Custos authors and
owns the fixtures. Provenance is documented inline in
`packages/custos-ts/test/parity/*.test.ts` ("Reads the Python-generated
fixtures ...").

The `packages/custos-ts/IR_CONTRACT.md` is a verbatim copy of the repo
root `IR_CONTRACT.md` — authored by us, Apache-2.0 (covered by the
LICENSE at the repo root AND the per-package LICENSE in
`packages/custos-ts/LICENSE`).

## 5. Re-implementations (clean-room; no vendored upstream code)

| File | Upstream concept | What was re-implemented |
|---|---|---|
| `packages/custos-ts/src/fnmatch.ts` | CPython `fnmatch.translate` | The translation algorithm is documented inline as the reference (CPython 3.10+ `fnmatch.translate`); the *implementation* is a clean-room TS port. NOT vendored CPython source. |
| `src/custos/eval/harness/` (A1–A6, scenarios, tool_call_evaluator, synthetic_responder) | Janus (`Janus/src/...`) | Clean-room re-implementations of the *documented behavior* of the Janus assistants and harness. Janus has no LICENSE → treated as all-rights-reserved; Custos re-implements behind clean interfaces and never vendors Janus source. |
| `Custos/phase0/` |  throwaway tree | Apache-2.0 (covered by the root LICENSE); provenance of any scenario-fixture data documented in `phase0/fixtures/README.md`. |

## 6. Janus upstream (reference, never vendored)

`Janus/` (the reference implementation at arXiv:2607.01510) is a design
reference ONLY.   "License incompatibility with Janus code" risk
row carries the standing mitigation.

| Resource | Status |
|---|---|
| `Janus/LICENSE` | Not present (no LICENSE file). |
| `Janus/pyproject.toml` | No `license` field. |
| `Janus/README.md` | No license declaration. |

Conclusion unchanged from : Janus is treated as
**all-rights-reserved**. Custos does not vendor, copy, or redistribute
Janus source code. Scenario JSON fixtures are derivative data used as
test inputs with provenance documented in
`Custos/phase0/fixtures/README.md` (and re-pinned under
`Custos/src/custos/eval/suites/janus_v1/fixtures/` for the v1.0 eval
suite).

## 7. Generated protobuf stubs

`src/custos/sidecar/proto/custos_v1_pb2.py` and
`custos_v1_pb2_grpc.py` are generated by `python -m grpc_tools.protoc`
from `custos_v1.proto` (ours, Apache-2.0). The generated stubs inherit
the proto's license. The single top-level `import custos_v1_pb2` in the
generated `_pb2_grpc.py` was rewritten to a fully-qualified
`from custos.sidecar.proto import custos_v1_pb2 as ...` import so the
modules load under the package namespace — the rewrite is a mechanical
import-path adjustment, not a content modification of the protobuf
output. mypy is configured to exclude `src/custos/sidecar/proto/` (the
generated dynamic symbols are runtime-introspected, not statically
type-checkable).

## 8. Audit summary for v1.0

- **Custos is Apache-2.0** end-to-end (Python runtime + TS packages +
  proto schema + docs + generated stubs).
- **No Janus source vendored.** Janus remains a design reference only;
  the A1–A6 assistants + the harness are clean-room re-implementations.
- **No third-party code vendored** into the published tarballs. The TS
  `@taqiy/custos-grpc` peer-deps `@grpc/grpc-js` and `@grpc/proto-loader` are
  the operator's install responsibility (the tested-minimum is pinned
  in the package.json `peerDependencies`); the npm tarball excludes
  `node_modules/`.
- **fnmatch.ts is a clean-room port** of the CPython `fnmatch.translate`
  algorithm — not vendored source. The algorithm is documented inline as
  the reference.
- **Optional extras carry Apache-2.0-compatible upstream licenses**
  (MIT, Apache-2.0, BSD-3-Clause); all are gated behind extras so the
  zero-dep runtime posture  is unchanged.

## 9. Audit cadence

This audit is re-run at every release cut per the  release-hygiene
discipline. The next audit is  (final hardening + review +
SBOM emission). The CycloneDX SBOM at  will cover the runtime +
the `[llm]`/`[eval]`/`[sidecar]`/`[telemetry]` extras.