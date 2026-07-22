# Custos docs

The Custos documentation site, built with MkDocs Material. This directory
contains the user-facing docs published alongside each release.

## Build

```bash
pip install "custos-middleware[docs]"     # mkdocs-material
mkdocs serve                   # http://127.0.0.1:8000
mkdocs build                   # emits site/
```

`docs/` is docs-only — no runtime dependency of the Custos Python or TS
package. The `custos[docs]` extra is developer-side only.

## Layout

- `index.md` — landing page.
- `quickstart.md` — 5-line integration.
- `tutorial.md` — 20-to-30-minute onboarding walk.
- `policy.md` — policy schema reference.
- `cookbook/index.md` + 5 recipes — read-allow, network-egress-prompt,
  payment-quorum, learned-policy opt-out, air-gapped-profile.
- `assistants.md` / `responders.md` / `audit.md` / `eval.md` — component
  reference.
- `telemetry.md` — the  opt-in surface.
- `adapters.md` / `sidecar.md` — integration surfaces.
- `THREAT_MODEL.md` — normative; every mapped to a STRIDE
  threat + mitigation.

Cross-doc links to `../IR_CONTRACT.md`, `../CHANGELOG.md`,
`../CONTRIBUTING.md`, `../SECURITY.md` resolve in the built site (mkdocs
follows the `nav:` block in `mkdocs.yml`).