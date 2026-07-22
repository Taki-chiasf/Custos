## Summary

<!-- One or two sentences: what does this change do, and why. -->

## Change type

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (semver-major or policy-schema bump)
- [ ] Docs / chore / release-hygiene
- [ ] Adapter integration (vendor imports strictly inside
      function bodies; regression test included)
- [ ] Security invariant relevant (sign-off required — see below)

## Security invariant check

If this change touches any security invariant, tick the relevant box and
explain in the PR body why the invariant is preserved or amended:

- [ ] Policy is the floor (assistant cannot relax a `deny`)
- [ ] Persisted-rule narrowness — narrower than the source rule
- [ ] Replay (webhook / sidecar nonce + timestamp)
- [ ] Secret leakage / redaction (recursive)
- [ ] LLM-assistant exfiltration gating (`exfiltrates_args`, air-gapped)
- [ ] Responder exception safety (pipeline boundary `try/finally` + safe `DENY`)
- [ ] Approver authority (identity + allowlist + quorum)
- [ ] Not applicable

## Verification

- [ ] `pytest -q` passes
- [ ] `ruff check src tests` clean
- [ ] `mypy --strict src/custos` clean
- [ ] If eval-harness change: `custos eval --suite adversarial` (or `--smoke`) green
- [ ] New / changed behavior has a test that would fail without the change

```
<!-- paste the tail of `pytest` / `ruff` / `mypy` output -->
```
