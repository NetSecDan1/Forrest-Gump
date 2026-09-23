"""Channel payloads: Teams Adaptive Cards (via Workflows webhook) and the SharePoint digest page.

Teams cards carry counts, titles and targets only - never account names or sample lists.
"""

from __future__ import annotations

import html
import re

from .models import SEVERITY_ORDER
from .sanitize import clean_text
from .triage import TriageResult, UrgentItem

STATUS_COLOR = {"Red": "attention", "Amber": "warning", "Green": "good"}
SEV_COLOR = {"Critical": "attention", "High": "warning", "Medium": "accent", "Low": "default", "Info": "default"}
MAX_CARD_ITEMS = 12


def _wrap_card(body: list, actions: list) -> dict:
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "msteams": {"width": "Full"}, "body": body, "actions": actions}
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


def _link_actions(report_url: str | None) -> list:
    return [{"type": "Action.OpenUrl", "title": "Open full report", "url": report_url}] if report_url else []


def teams_urgent_card(t: TriageResult, items: list[UrgentItem], report_url: str | None) -> dict:
    r = t.report
    body = [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "color": "attention", "wrap": True,
         "text": f"AD urgent: {clean_text(r.forest.name, 80)} - {len(items)} item(s) need attention"},
        {"type": "FactSet", "facts": [
            {"title": "Overall", "value": r.summary.overallStatus},
            {"title": "Score", "value": f"{t.score}/100" + (f" (prev {t.score_previous})" if t.score_previous is not None else "")},
            {"title": "Critical / High", "value": f"{t.counts['Critical']} / {t.counts['High']}"},
            {"title": "Coverage", "value": f"{r.summary.checkCoveragePercent:.0f}%"},
            {"title": "Collected", "value": r.generatedUtc.strftime("%Y-%m-%d %H:%M UTC")},
        ]},
    ]
    for u in items[:MAX_CARD_ITEMS]:
        f = u.finding
        text = f"**{u.severity}** · {clean_text(f.title, 140)}\n\n`{clean_text(f.target, 90)}` · {f.checkId} · {clean_text(u.reason, 60)}" if f else f"**{u.severity}** · {clean_text(u.reason, 200)}"
        body.append({"type": "Container", "separator": True, "items": [{"type": "TextBlock", "wrap": True, "text": text, "color": SEV_COLOR.get(u.severity, "default")}]})
    if len(items) > MAX_CARD_ITEMS:
        body.append({"type": "TextBlock", "isSubtle": True, "wrap": True, "text": f"+{len(items) - MAX_CARD_ITEMS} more in the full report."})
    body.append({"type": "TextBlock", "isSubtle": True, "wrap": True, "size": "Small",
                 "text": "Read-only detection. Follow the runbook; any change goes through change control."})
    return _wrap_card(body, _link_actions(report_url))


def teams_digest_card(t: TriageResult, narrative_md: str, period_label: str, report_url: str | None, narrative_source: str) -> dict:
    r = t.report
    exec_summary = _section(narrative_md, "Executive summary") or ""
    d = t.delta
    top = sorted([f for f in t.active if f.severity in ("Critical", "High")], key=lambda f: (SEVERITY_ORDER[f.severity], f.checkId))
    body = [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": True, "text": f"AD forest health - {clean_text(r.forest.name, 80)} - {period_label}"},
        {"type": "ColumnSet", "columns": [
            {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "size": "ExtraLarge", "weight": "Bolder",
                                                             "color": STATUS_COLOR[r.summary.overallStatus], "text": f"{t.score}"}]},
            {"type": "Column", "width": "stretch", "items": [{"type": "FactSet", "facts": [
                {"title": "Status", "value": r.summary.overallStatus},
                {"title": "Previous score", "value": str(t.score_previous) if t.score_previous is not None else "n/a (baseline)"},
                {"title": "C / H / M / L", "value": " / ".join(str(t.counts[k]) for k in ("Critical", "High", "Medium", "Low"))},
                {"title": "New / Resolved", "value": f"{len(d.new) + len(d.escalated)} / {len(d.resolved)}" if d.baseline_report_id else "baseline"},
                {"title": "Coverage", "value": f"{r.summary.checkCoveragePercent:.0f}%"},
            ]}]},
        ]},
        {"type": "TextBlock", "wrap": True, "text": clean_text(_strip_md(exec_summary), 1200)},
    ]
    if top:
        body.append({"type": "TextBlock", "weight": "Bolder", "text": "Top risks", "spacing": "Medium"})
        for f in top[:8]:
            body.append({"type": "TextBlock", "wrap": True, "spacing": "Small", "color": SEV_COLOR[f.severity],
                         "text": f"{f.severity} · {clean_text(f.title, 120)} · {f.checkId}"})
    moved = [m for m in t.trends if m.direction == "worsened"][:6]
    if moved:
        body.append({"type": "TextBlock", "weight": "Bolder", "text": "Worsening metrics", "spacing": "Medium"})
        body.append({"type": "FactSet", "facts": [{"title": m.metric, "value": f"{m.previous:g} → {m.current:g}"} for m in moved]})
    body.append({"type": "TextBlock", "isSubtle": True, "size": "Small", "wrap": True,
                 "text": f"Narrative: {'AI-drafted, validated against report data' if narrative_source == 'llm' else 'template'}. Source of truth: the full report."})
    return _wrap_card(body, _link_actions(report_url))


# ------------------------------------------------------------------------------------------ SharePoint page

def _section(md: str, heading: str) -> str | None:
    m = re.search(rf"^## {re.escape(heading)}\s*$(.*?)(?=^## |\Z)", md, flags=re.M | re.S)
    return m.group(1).strip() if m else None


def _strip_md(s: str) -> str:
    return re.sub(r"[*_`#]", "", s)


def _inline(s: str) -> str:
    s = html.escape(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


def markdown_to_html(md: str) -> str:
    """Tiny, safe converter for the digest's constrained Markdown (headings, bullets, paragraphs, bold, code)."""
    out, in_list = [], False
    for line in md.splitlines():
        s = line.rstrip()
        if s.startswith(("- ", "* ")):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(s[2:])}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if s.startswith("### "):
            out.append(f"<h3>{_inline(s[4:])}</h3>")
        elif s.startswith("## "):
            out.append(f"<h2>{_inline(s[3:])}</h2>")
        elif s.startswith("# "):
            out.append(f"<h1>{_inline(s[2:])}</h1>")
        elif s:
            out.append(f"<p>{_inline(s)}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def digest_html(t: TriageResult, narrative_md: str, period_label: str, narrative_source: str, report_url: str | None) -> str:
    r = t.report
    rows = "".join(
        f"<tr><td class='s-{f.severity.lower()}'>{f.severity}</td><td>{html.escape(f.checkId)}</td><td>{html.escape(f.category)}</td>"
        f"<td>{html.escape(clean_text(f.title, 200))}</td><td>{html.escape(clean_text(f.target, 120))}</td><td>{f.count}</td></tr>"
        for f in sorted(t.active, key=lambda x: (SEVERITY_ORDER[x.severity], x.checkId))
    )
    trend_rows = "".join(
        f"<tr><td>{html.escape(m.metric)}</td><td>{'' if m.previous is None else f'{m.previous:g}'}</td><td>{m.current:g}</td><td>{m.direction}</td></tr>"
        for m in t.trends
    )
    link = f"<p><a href='{html.escape(report_url, quote=True)}'>Full technical report</a></p>" if report_url else ""
    src = "AI-drafted narrative (validated against report data)" if narrative_source == "llm" else "Template narrative"
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Health Digest - {html.escape(r.forest.name)} - {html.escape(period_label)}</title>
<style>
body{{font-family:"Segoe UI",Arial,sans-serif;color:#101828;background:#fff;margin:0;padding:24px;max-width:1100px;line-height:1.5;font-size:14px}}
h1{{font-size:22px}}h2{{font-size:17px;border-bottom:2px solid #eaecf0;padding-bottom:4px;margin-top:26px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border:1px solid #eaecf0;padding:5px 8px;text-align:left;vertical-align:top}}
th{{background:#f9fafb}}.s-critical{{background:#fee4e2;color:#b42318;font-weight:600}}.s-high{{background:#fef0c7;color:#b54708;font-weight:600}}
.s-medium{{background:#fff6ed;color:#c4320a}}.s-low,.s-info{{background:#d1e9ff;color:#175cd3}}
.badge{{display:inline-block;padding:6px 12px;border-radius:6px;font-weight:700}}.Red{{background:#fee4e2;color:#b42318}}.Amber{{background:#fef0c7;color:#b54708}}.Green{{background:#dcfae6;color:#067647}}
.muted{{color:#667085;font-size:12px}}code{{background:#f2f4f7;padding:0 3px;border-radius:3px}}
</style></head><body>
<h1>AD Forest Health Digest - {html.escape(r.forest.name)} - {html.escape(period_label)}</h1>
<p><span class="badge {r.summary.overallStatus}">{r.summary.overallStatus} · {t.score}/100</span>
<span class="muted"> Collected {r.generatedUtc.strftime('%Y-%m-%d %H:%M UTC')} · report {html.escape(r.reportId)} · {src}</span></p>
{link}
{markdown_to_html(narrative_md)}
<h2>Active findings ({len(t.active)})</h2>
<table><thead><tr><th>Severity</th><th>Check</th><th>Category</th><th>Title</th><th>Target</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Suppressed (accepted risk): {len(t.suppressed)}</h2>
<ul>{''.join(f"<li>{html.escape(f.id)} - {html.escape(s.reason)} (owner {html.escape(s.owner)}, expires {s.expires})</li>" for f, s in t.suppressed) or '<li>None</li>'}</ul>
<h2>Metrics</h2>
<table><thead><tr><th>Metric</th><th>Previous</th><th>Current</th><th>Direction</th></tr></thead><tbody>{trend_rows}</tbody></table>
<p class="muted">Generated by adhealth-agent. Detection is read-only; remediation follows change control.</p>
</body></html>"""
