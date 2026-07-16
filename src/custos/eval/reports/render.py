"""HTML + JSON report renderer for the eval harness .

Stdlib-only (: the report writer must not pull a templating dep into the
runtime). Renders a single ``index.html`` and ``report.json`` per ``custos
eval`` run.

Input shapes:
  - a :class:`eval.metrics.MetricReport` (the  aggregate) +
  - optional per-cell result lists (adversarial ``CellResult``s or janus CSV
    rows serialised to dicts).

The HTML uses inline ``<style>`` (no CSS framework) and inline ``<script>``
is forbidden (no JS attack surface in an eval report). Jinja-style ``{var}``
tokens are rendered by plain str replacement so the template stays auditable.
"""

from __future__ import annotations

import html
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from custos.eval.metrics import MetricReport

__all__ = ["render_report", "write_html", "write_json"]

_CSS = """
body{font:14px/1.45 -apple-system,system-ui,sans-serif;color:#1c1f23;background:#fff;margin:2rem auto;max-width:920px;padding:0 1rem}
h1{font-size:1.5rem;border-bottom:2px solid #2c5aa0;padding-bottom:.3rem}
h2{font-size:1.1rem;margin-top:1.6rem;color:#2c5aa0}
table{border-collapse:collapse;margin:1rem 0;width:100%}
th,td{border:1px solid #d0d3d8;padding:.35rem .6rem;text-align:left;vertical-align:top}
th{background:#f3f5f8;font-weight:600}
.pass{color:#1a7e3a;font-weight:600}.fail{color:#c0341c;font-weight:600}
code{background:#f3f5f8;padding:.05rem .25rem;border-radius:3px}
.kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.6rem;margin:.8rem 0}
.kpi div{border:1px solid #d0d3d8;padding:.5rem .75rem;border-radius:6px}
.kpi b{display:block;font-size:1.4rem;line-height:1.2}
.kpi small{color:#555}
"""


def render_report(
    report: MetricReport,
    *,
    cells: Sequence[Mapping[str, Any]] | None = None,
    title: str = "Custos eval report",
) -> str:
    """Return a self-contained HTML document for ``report`` + ``cells``."""
    cells = list(cells or [])
    kpi_html = _render_kpis(report)
    cells_html = _render_cells(cells) if cells else "<p><em>No per-cell rows reported.</em></p>"
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        f"<title>{html.escape(title)}</title>"
        f"<style>{_CSS}</style></head><body>"
        f"<h1>{html.escape(title)}</h1>"
        f"<p><code>{html.escape(report.suite)}</code> suite "
        f"&middot; {report.total_cells} cells</p>"
        f"<section><h2>Metrics (FR-9.27)</h2>{kpi_html}</section>"
        f"<section><h2>Per-cell results</h2>{cells_html}</section>"
        "</body></html>"
    )


def write_html(
    path: str | Path,
    report: MetricReport,
    *,
    cells: Sequence[Mapping[str, Any]] | None = None,
    title: str = "Custos eval report",
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(report, cells=cells, title=title), encoding="utf-8")
    return path


def write_json(path: str | Path, payload: Mapping[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2), encoding="utf-8")
    return path


def _render_kpis(report: MetricReport) -> str:
    pairs = [
        ("False-allow rate", f"{report.false_allow_rate:.1%}", "M8 gate (lower is better)"),
        ("Precision of denials", f"{report.precision_of_denials:.1%}", "vs ground-truth-risk"),
        ("Recall of denials", f"{report.recall_of_denials:.1%}", "vs ground-truth-risk"),
        ("Prompts / session", f"{report.prompts_per_session:.2f}", "fatigue proxy"),
        ("Cognitive-load proxy", f"{report.cognitive_load_proxy:.2f}", "FR-9.27"),
        ("True denials", str(report.true_denials), "should-deny correctly denied"),
        ("False allows", str(report.false_allows), "should-deny actually allowed"),
        ("Missed denials", str(report.missed_denials), "prompt/defer instead of deny"),
    ]
    items = "".join(
        f"<div><b>{html.escape(label)}</b>{html.escape(value)}<small>{html.escape(hint)}</small></div>"
        for label, value, hint in pairs
    )
    return f'<div class="kpi">{items}</div>'


def _render_cells(cells: Sequence[Mapping[str, Any]]) -> str:
    if not cells:
        return ""
    header_keys = list(cells[0].keys())
    head = "".join(_th(html.escape(str(k))) for k in header_keys)
    body_rows: list[str] = []
    for c in cells:
        cells_row = "".join(_td(html.escape(str(c.get(k, "")))) for k in header_keys)
        body_rows.append(f"<tr>{cells_row}</tr>")
    return (
        "<table><thead><tr>"
        + head
        + "</tr></thead><tbody>"
        + "".join(body_rows)
        + "</tbody></table>"
    )


def _th(content: str) -> str:
    return f"<th>{content}</th>"


def _td(content: str) -> str:
    return f"<td>{content}</td>"


# --------------------------------------------------------------------------- #
# Convenience: emit both files for a suite run.
# --------------------------------------------------------------------------- #


def emit_suite_artifacts(
    out_dir: str | Path,
    *,
    metrics: MetricReport,
    cells: Sequence[Mapping[str, Any]] | None = None,
    title: str = "Custos eval report",
    extra_json: Mapping[str, Any] | None = None,
) -> tuple[Path, Path]:
    """Write ``report.html`` + ``report.json`` for one suite run ."""
    out_dir = Path(out_dir)
    html_path = write_html(out_dir / "report.html", metrics, cells=cells, title=title)
    payload: dict[str, Any] = {"metrics": metrics.to_dict()}
    if cells:
        payload["cells"] = [dict(c) for c in cells]
    if extra_json:
        payload.update(dict(extra_json))
    json_path = write_json(out_dir / "report.json", payload)
    return html_path, json_path
