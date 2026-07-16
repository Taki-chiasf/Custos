# janus-v1 fixtures (data, not code)

These files are **data fixtures** copied verbatim from the Janus reference
snapshot at `Janus/` for parity reproduction only. They are not code and are
not vendored:

- `scenarios/definitions/` — scenario JSON (3 scenarios x 4 subscenarios +
  `default.json` shared seed data). Source: `Janus/scenarios/definitions/`.
- `constitutions/default.md` — constitution document consumed by the
  `constitution` assistant. Source: `Janus/config/constitutions/default.md`.

## Provenance and license caveat

Janus is shipped "as-is" with **no license** (confirmed in the
progress log in the ; re-confirmed at audit: no top-level `LICENSE`, no
`license` field in `Janus/pyproject.toml`, no license headers in any `.py`
file). Treat it as all-rights-reserved by default.

Custos is Apache-2.0 . To stay on the legal safe side:

- The **scenario JSON** and **constitution markdown** are data describing
  specific test scenarios. Their reproduction as test fixtures for parity
  measurement is the intended academic use of the Janus companion release and
  is the only reason they are copied here.
- No Janus **code** is vendored anywhere in this tree. All `.py` files under
  `eval/harness/` are clean-room re-implementations from the architecture doc
  + paper + reading the reference (see `eval/suites/janus_v1/DECISION_SEMANTICS.md`).
- Before publishing Custos publicly , re-evaluate: at minimum,
  attribute the scenario data to the Janus paper (arXiv:2607.01510); at
  most, regenerate scenario data fresh so no Janus-derived content ships in
  the release.

If the upstream Janus repository publishes a license after this audit, revisit
this README and the corresponding  risk row.