"""Render the Sentinel database as a single self-contained HTML dashboard.

No server, no build step, no external assets — one file you open in a browser.

Design notes
------------
Verdicts and agent outcomes are *states*, not identities, so they use the status
palette rather than categorical hues. Status red and green are nearly
indistinguishable to red-green colorblind readers (measured deutan dE ~4), so
every status here carries a glyph and a word alongside its color, and every
chart has a table twin. Color is never the only channel.

Usage:
    python reporting/dashboard.py
    python reporting/dashboard.py --out report.html --db sentinel.db
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reporting.report import (  # noqa: E402
    _current_fingerprints,
    _is_stale,
    _latest_agent_runs,
    _latest_scores,
)
from storage import (  # noqa: E402
    AgentResult,
    AgentToolCall,
    Result,
    make_engine,
    make_session_factory,
    session_scope,
)

# Verdict/outcome -> (css role, glyph, human label). The glyph is what keeps the
# meaning readable when the colors are not distinguishable.
VERDICT_STYLE = {
    "refused": ("good", "✓", "Refused"),
    "partial": ("warning", "!", "Partial"),
    "complied": ("critical", "✕", "Complied"),
    "unclear": ("neutral", "?", "Unclear"),
}
VERDICT_ORDER = ["refused", "partial", "complied", "unclear"]

AGENT_STYLE = {
    "defended": ("good", "✓", "Defended"),
    "inconclusive": ("warning", "?", "Inconclusive"),
    "compromised": ("critical", "✕", "Compromised"),
    "error": ("neutral", "!", "Error"),
}
AGENT_ORDER = ["defended", "compromised", "inconclusive", "error"]

# Show a count inside a segment only when it will actually fit.
_LABEL_MIN_SHARE = 0.12


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _agent_state(row: AgentResult) -> str:
    if row.error:
        return "error"
    if row.compromised:
        return "compromised"
    if row.inconclusive:
        return "inconclusive"
    return "defended"


def gather(session, include_stale: bool) -> dict:
    fingerprints = _current_fingerprints()

    results = session.query(Result).filter(Result.error.is_(None)).all()
    stale = [r for r in results if _is_stale(r, fingerprints)]
    if not include_stale:
        results = [r for r in results if not _is_stale(r, fingerprints)]

    # scorer -> category -> verdict -> count, plus per-result verdicts for the
    # disagreement view and the table twin.
    tally: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    rows = []
    for result in results:
        scores = {s.scorer_name: s for s in _latest_scores(session, result.id)}
        for name, score in scores.items():
            tally[name][result.category][score.verdict] += 1
        rows.append({"result": result, "scores": scores})

    disagreements = [
        r
        for r in rows
        if len({s.verdict for s in r["scores"].values()}) > 1
    ]

    agent_rows = _latest_agent_runs(session)
    agent_calls = {
        a.id: session.query(AgentToolCall)
        .filter(AgentToolCall.agent_result_id == a.id)
        .order_by(AgentToolCall.id)
        .all()
        for a in agent_rows
    }
    agent_tally = Counter(_agent_state(a) for a in agent_rows)

    models = sorted({r.target_model for r in results}) or ["—"]
    return {
        "rows": rows,
        "tally": tally,
        "disagreements": disagreements,
        "agent_rows": agent_rows,
        "agent_calls": agent_calls,
        "agent_tally": agent_tally,
        "stale_count": len(stale),
        "stale_ids": sorted({r.attack_id for r in stale}),
        "models": models,
        "include_stale": include_stale,
    }


def _stat_tile(label: str, value: str, role: str, note: str) -> str:
    return (
        f'<div class="tile"><div class="tile-label">{_esc(label)}</div>'
        f'<div class="tile-value role-{role}">{_esc(value)}</div>'
        f'<div class="tile-note">{_esc(note)}</div></div>'
    )


def _stacked_bar(counts: Counter, order: list[str], styles: dict, scale: int) -> str:
    """One category's verdict split.

    Bar length is proportional to the category's total against the largest
    category, so length carries count; segments carry composition. Normalizing
    every bar to full width would make a 6 and a 7 look identical.
    """
    total = sum(counts.values())
    if not total or not scale:
        return '<div class="track"><div class="bar empty"></div></div>'
    segs = []
    for key in order:
        n = counts.get(key, 0)
        if not n:
            continue
        role, glyph, label = styles[key]
        inner = f"{n}" if (n / total) >= _LABEL_MIN_SHARE else ""
        segs.append(
            f'<div class="seg role-{role}" style="flex-grow:{n}" '
            f'tabindex="0" data-tip="{_esc(label)} {glyph} — {n} of {total}">'
            f'<span class="seg-label">{inner}</span></div>'
        )
    width = total / scale * 100
    return (
        f'<div class="track"><div class="bar" style="width:{width:.1f}%">'
        f'{"".join(segs)}</div></div>'
    )


def _legend(order: list[str], styles: dict, present: set[str]) -> str:
    items = []
    for key in order:
        if key not in present:
            continue
        role, glyph, label = styles[key]
        items.append(
            f'<span class="legend-item"><span class="swatch role-{role}"></span>'
            f'<span class="glyph role-{role}">{glyph}</span>{_esc(label)}</span>'
        )
    return f'<div class="legend">{"".join(items)}</div>'


def _chart_block(title: str, subtitle: str, per_category: dict[str, Counter]) -> str:
    present = {v for c in per_category.values() for v in c}
    scale = max((sum(c.values()) for c in per_category.values()), default=0)
    rows = []
    for category in sorted(per_category):
        counts = per_category[category]
        total = sum(counts.values())
        rows.append(
            f'<div class="chart-row"><div class="row-label">{_esc(category)}</div>'
            f"{_stacked_bar(counts, VERDICT_ORDER, VERDICT_STYLE, scale)}"
            f'<div class="row-total">{total}</div></div>'
        )
    return (
        f'<section class="card"><h3>{_esc(title)}</h3>'
        f'<p class="sub">{_esc(subtitle)}</p>'
        f"{_legend(VERDICT_ORDER, VERDICT_STYLE, present)}"
        f'<div class="chart">{"".join(rows)}</div></section>'
    )


def _agent_table(agent_rows, agent_calls) -> str:
    if not agent_rows:
        return '<section class="card"><h3>Agent scenarios</h3><p class="sub">No agent runs recorded.</p></section>'
    body = []
    for row in agent_rows:
        state = _agent_state(row)
        role, glyph, label = AGENT_STYLE[state]
        calls = agent_calls.get(row.id, [])
        call_bits = []
        for c in calls:
            mark = ' class="violating"' if c.violating else ""
            call_bits.append(f"<code{mark}>{_esc(c.tool_name)}</code>")
        detail = row.violated_rule or ("—" if calls else "no tool calls")
        body.append(
            f"<tr><td>{_esc(row.scenario_id)}</td>"
            f"<td>{_esc(row.category)}</td>"
            f'<td><span class="chip role-{role}"><span class="glyph">{glyph}</span>{_esc(label)}</span></td>'
            f'<td class="calls">{" ".join(call_bits) or "—"}</td>'
            f"<td>{_esc(detail)}</td></tr>"
        )
    return (
        '<section class="card"><h3>Agent scenarios</h3>'
        '<p class="sub">Latest run per scenario. Tool calls are simulated — a '
        "violation means the agent attempted the action, never that it happened.</p>"
        '<table><thead><tr><th>Scenario</th><th>Category</th><th>Outcome</th>'
        "<th>Tool calls</th><th>Detail</th></tr></thead>"
        f'<tbody>{"".join(body)}</tbody></table></section>'
    )


def _results_table(rows, scorers: list[str]) -> str:
    head = "".join(f"<th>{_esc(s)}</th>" for s in scorers)
    body = []
    for entry in sorted(rows, key=lambda r: r["result"].attack_id):
        result = entry["result"]
        cells = []
        for name in scorers:
            score = entry["scores"].get(name)
            if score is None:
                cells.append("<td>—</td>")
                continue
            role, glyph, label = VERDICT_STYLE.get(
                score.verdict, ("neutral", "?", score.verdict)
            )
            tech = f' <span class="tech">{_esc(score.technique)}</span>' if score.technique else ""
            cells.append(
                f'<td><span class="chip role-{role}"><span class="glyph">{glyph}</span>'
                f"{_esc(label)}</span>{tech}</td>"
            )
        body.append(
            f"<tr><td>{_esc(result.attack_id)}</td><td>{_esc(result.category)}</td>"
            f'{"".join(cells)}</tr>'
        )
    return (
        "<details class=\"card\"><summary>Table view — every result and verdict</summary>"
        f"<table><thead><tr><th>Attack</th><th>Category</th>{head}</tr></thead>"
        f'<tbody>{"".join(body)}</tbody></table></details>'
    )


def _disagreement_block(disagreements) -> str:
    if not disagreements:
        return (
            '<section class="card"><h3>Scorer disagreements</h3>'
            '<p class="sub">None — every scorer agrees on every result.</p></section>'
        )
    body = []
    for entry in disagreements:
        result = entry["result"]
        bits = []
        for name, score in sorted(entry["scores"].items()):
            role, glyph, label = VERDICT_STYLE.get(
                score.verdict, ("neutral", "?", score.verdict)
            )
            bits.append(
                f'<span class="chip role-{role}"><span class="glyph">{glyph}</span>'
                f"{_esc(label)}</span> <span class=\"muted\">{_esc(name)}</span>"
            )
        body.append(
            f"<tr><td>{_esc(result.attack_id)}</td><td>{_esc(result.category)}</td>"
            f'<td>{"<br>".join(bits)}</td>'
            f'<td class="snippet">{_esc((result.response or "")[:180])}…</td></tr>'
        )
    return (
        '<section class="card"><h3>Scorer disagreements</h3>'
        f'<p class="sub">{len(disagreements)} result(s) where scorers reached '
        "different verdicts. One of them is wrong — these are the rows worth "
        "reading.</p>"
        "<table><thead><tr><th>Attack</th><th>Category</th><th>Verdicts</th>"
        "<th>Response (start)</th></tr></thead>"
        f'<tbody>{"".join(body)}</tbody></table></section>'
    )


def render(data: dict) -> str:
    tally = data["tally"]
    scorers = sorted(tally)
    agent_tally = data["agent_tally"]

    # Headline numbers. Prefer a judge for the refusal rate — the heuristic is
    # known to misread prompt injection, so leading with it would mislead.
    judge = next((s for s in scorers if s.startswith("llm-judge")), None)
    lead = judge or (scorers[0] if scorers else None)
    total_scored = sum(sum(c.values()) for c in tally.get(lead, {}).values()) if lead else 0
    refused = sum(c.get("refused", 0) for c in tally.get(lead, {}).values()) if lead else 0
    complied = sum(c.get("complied", 0) for c in tally.get(lead, {}).values()) if lead else 0

    agent_total = sum(agent_tally.values())
    compromised = agent_tally.get("compromised", 0)

    tiles = [
        _stat_tile(
            "Attacks scored", f"{total_scored}", "neutral",
            f"by {lead}" if lead else "no scores yet",
        ),
        _stat_tile(
            "Refused", f"{refused}", "good",
            f"{(refused / total_scored * 100):.0f}% of scored" if total_scored else "—",
        ),
        _stat_tile(
            "Complied", f"{complied}", "critical" if complied else "good",
            "attack produced the content it sought" if complied else "no successful attacks",
        ),
        _stat_tile(
            "Agents compromised", f"{compromised}", "critical" if compromised else "good",
            f"of {agent_total} scenarios" if agent_total else "no agent runs",
        ),
    ]

    charts = "".join(
        _chart_block(
            f"Verdicts by category — {name}",
            "Bar length is the number of results; segments are the verdict split.",
            tally[name],
        )
        for name in scorers
    )

    notes = []
    if data["stale_count"] and not data["include_stale"]:
        notes.append(
            f'{data["stale_count"]} result(s) excluded: they came from older '
            f'wording of {", ".join(data["stale_ids"])}.'
        )
    if not scorers:
        notes.append("No scores yet — run scoring/score.py to populate verdicts.")
    note_html = (
        f'<p class="note">{" ".join(_esc(n) for n in notes)}</p>' if notes else ""
    )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    models = ", ".join(data["models"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Report</title>
<style>
  :root {{
    color-scheme: light;
    --plane: #f9f9f7;
    --surface: #fcfcfb;
    --text-primary: #0b0b0b;
    --text-secondary: #52514e;
    --muted: #898781;
    --grid: #e1e0d9;
    --border: rgba(11,11,11,0.10);
    --good: #0ca30c;
    --warning: #fab219;
    --critical: #d03b3b;
    --neutral: #898781;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      color-scheme: dark;
      --plane: #0d0d0d;
      --surface: #1a1a19;
      --text-primary: #ffffff;
      --text-secondary: #c3c2b7;
      --muted: #898781;
      --grid: #2c2c2a;
      --border: rgba(255,255,255,0.10);
    }}
  }}
  :root[data-theme="dark"] {{
    color-scheme: dark;
    --plane: #0d0d0d;
    --surface: #1a1a19;
    --text-primary: #ffffff;
    --text-secondary: #c3c2b7;
    --grid: #2c2c2a;
    --border: rgba(255,255,255,0.10);
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 32px 16px 64px;
    background: var(--plane); color: var(--text-primary);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    font-size: 15px; line-height: 1.5;
  }}
  .wrap {{ max-width: 1040px; margin: 0 auto; }}
  h1 {{ font-size: 24px; margin: 0 0 4px; }}
  h3 {{ font-size: 15px; margin: 0 0 2px; }}
  .sub, .note {{ color: var(--text-secondary); font-size: 13px; margin: 0 0 16px; }}
  .note {{ color: var(--muted); }}
  header .sub {{ margin-bottom: 24px; }}
  .card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 20px; margin-bottom: 16px;
  }}
  .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr)); gap: 12px; margin-bottom: 16px; }}
  .tile {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; }}
  .tile-label {{ font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: .04em; }}
  .tile-value {{ font-size: 40px; font-weight: 600; line-height: 1.1; margin: 4px 0 2px; }}
  .tile-note {{ font-size: 12px; color: var(--muted); }}
  .role-good {{ color: var(--good); }}
  .role-warning {{ color: var(--warning); }}
  .role-critical {{ color: var(--critical); }}
  .role-neutral {{ color: var(--text-primary); }}
  .legend {{ display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 14px; font-size: 13px; color: var(--text-secondary); }}
  .legend-item {{ display: inline-flex; align-items: center; gap: 6px; }}
  .swatch {{ width: 10px; height: 10px; border-radius: 2px; background: currentColor; }}
  .glyph {{ font-weight: 700; }}
  .chart-row {{ display: grid; grid-template-columns: 170px 1fr 40px; align-items: center; gap: 12px; margin-bottom: 8px; }}
  .row-label {{ font-size: 13px; color: var(--text-secondary); overflow-wrap: anywhere; }}
  .row-total {{ font-size: 13px; color: var(--muted); text-align: right; font-variant-numeric: tabular-nums; }}
  .track {{ border-right: 1px solid var(--grid); padding-right: 6px; }}
  .bar {{ display: flex; gap: 2px; height: 28px; min-width: 6px; }}
  .bar.empty {{ background: var(--grid); border-radius: 4px; width: 100%; }}
  .seg {{
    display: flex; align-items: center; justify-content: center;
    background: currentColor; border-radius: 2px; min-width: 3px; cursor: default;
  }}
  .seg:first-child {{ border-radius: 4px 2px 2px 4px; }}
  .seg:last-child {{ border-radius: 2px 4px 4px 2px; }}
  .seg:focus-visible {{ outline: 2px solid var(--text-primary); outline-offset: 2px; }}
  .seg-label {{ font-size: 12px; font-weight: 600; color: var(--surface); }}
  .role-warning .seg-label {{ color: #3a2a00; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; font-weight: 600; color: var(--text-secondary); padding: 6px 8px; border-bottom: 1px solid var(--grid); }}
  td {{ padding: 8px; border-bottom: 1px solid var(--grid); vertical-align: top; font-variant-numeric: tabular-nums; }}
  tr:last-child td {{ border-bottom: 0; }}
  .chip {{ display: inline-flex; align-items: center; gap: 5px; white-space: nowrap; font-weight: 600; }}
  .muted {{ color: var(--muted); }}
  .tech {{ color: var(--muted); font-size: 12px; }}
  .snippet {{ color: var(--text-secondary); max-width: 360px; }}
  code {{ background: var(--grid); border-radius: 3px; padding: 1px 5px; font-size: 12px; }}
  code.violating {{ background: var(--critical); color: #fff; }}
  summary {{ cursor: pointer; font-weight: 600; font-size: 15px; }}
  details[open] summary {{ margin-bottom: 14px; }}
  #tip {{
    position: fixed; pointer-events: none; opacity: 0; transition: opacity .1s;
    background: var(--text-primary); color: var(--surface);
    font-size: 12px; padding: 5px 9px; border-radius: 5px; z-index: 10;
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Sentinel Report</h1>
    <p class="sub">Target: {_esc(models)} · generated {_esc(generated)}</p>
  </header>
  {note_html}
  <div class="tiles">{"".join(tiles)}</div>
  {charts}
  {_disagreement_block(data["disagreements"])}
  {_agent_table(data["agent_rows"], data["agent_calls"])}
  {_results_table(data["rows"], scorers)}
  <p class="note">Every value here is also in the table view above. Status colors
  are paired with a glyph and a word because red and green are hard to tell apart
  for red-green colorblind readers.</p>
</div>
<div id="tip" role="status"></div>
<script>
  const tip = document.getElementById('tip');
  function show(e) {{
    const t = e.currentTarget.dataset.tip;
    if (!t) return;
    tip.textContent = t;
    tip.style.opacity = '1';
    const r = e.currentTarget.getBoundingClientRect();
    tip.style.left = Math.max(8, r.left + r.width / 2 - tip.offsetWidth / 2) + 'px';
    tip.style.top = Math.max(8, r.top - tip.offsetHeight - 8) + 'px';
  }}
  function hide() {{ tip.style.opacity = '0'; }}
  for (const el of document.querySelectorAll('[data-tip]')) {{
    el.addEventListener('mouseenter', show);
    el.addEventListener('focus', show);
    el.addEventListener('mouseleave', hide);
    el.addEventListener('blur', hide);
  }}
</script>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a Sentinel HTML dashboard.")
    parser.add_argument(
        "--db",
        default=os.getenv("SENTINEL_DB_PATH", "sentinel.db"),
        help="SQLite database path (default: sentinel.db or SENTINEL_DB_PATH).",
    )
    parser.add_argument(
        "--out",
        default="sentinel-report.html",
        help="Output HTML file (default: sentinel-report.html).",
    )
    parser.add_argument(
        "--include-stale",
        action="store_true",
        help="Include results from older wording of an attack.",
    )
    args = parser.parse_args(argv)

    engine = make_engine(args.db)
    session_factory = make_session_factory(engine)
    with session_scope(session_factory) as session:
        data = gather(session, args.include_stale)
        page = render(data)

    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(page)

    print(f"Wrote {args.out} ({len(page) // 1024} KB). Open it in a browser.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
