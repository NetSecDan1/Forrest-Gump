"""Model qualification: evidence that a model/config produces faithful digests BEFORE it goes to production.

Runs the real narrator (same prompts, tools, sanitization and faithfulness guard) over one or more verified
bundles, N times each, and reports guard pass rate, failure reasons, latency and token usage. The JSON/Markdown
output is meant to be attached to the change record when a model id, mode or prompt changes.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .config import Settings
from .history import stored_from_report
from .ingest import open_bundle
from .narrative import StrandsNarrator
from .triage import triage


def _pct(values: list[int], q: float) -> int | None:
    if not values:
        return None
    v = sorted(values)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def _reason(warning: str) -> str:
    """Group warnings into stable buckets, e.g. 'rejected: omits checks with Critical findings'."""
    for prefix, label in (("LLM output rejected: ", "rejected"), ("LLM error: ", "error")):
        if warning.startswith(prefix):
            return f"{label}: {warning[len(prefix):].split(':')[0].strip()}"
    return warning[:80]


def run_qualification(s: Settings, bundle_paths: list[Path], runs: int, min_pass_rate: float,
                      narrator: StrandsNarrator | None = None) -> dict:
    if s.llm.provider == "none":
        raise ValueError("llm.provider is 'none' - nothing to qualify")
    narrator = narrator or StrandsNarrator(s.llm)
    reports = sorted((open_bundle(p, s.max_file_bytes, s.integrity).report for p in bundle_paths), key=lambda r: r.generatedUtc)
    attempts, reasons, latencies, tin, tout = [], Counter(), [], [], []
    accepted_example, rejected_example = None, None
    prev_by_forest: dict[str, object] = {}
    for r in reports:
        forest = r.forest.name.lower()
        t = triage(r, prev_by_forest.get(forest), s.policy)
        prev_by_forest[forest] = stored_from_report(r)
        for i in range(runs):
            res = narrator.generate(t, r.generatedUtc.strftime("%B %Y"))
            ok = res.source == "llm"
            for w in res.warnings:
                reasons[_reason(w)] += 1
            lat = res.meta.get("latencyMs")
            if lat is not None:
                latencies.append(lat)
            u = res.meta.get("usage") or {}
            if u:
                tin.append(u.get("inputTokens", 0))
                tout.append(u.get("outputTokens", 0))
            if ok and accepted_example is None:
                accepted_example = res.markdown
            if not ok and rejected_example is None and res.rejected_markdown:
                rejected_example = res.rejected_markdown
            attempts.append({"reportId": r.reportId, "forest": r.forest.name, "run": i + 1, "passed": ok,
                             "warnings": res.warnings, "latencyMs": lat, "usage": u})
    passed = sum(a["passed"] for a in attempts)
    rate = passed / len(attempts) if attempts else 0.0
    return {
        "qualifiedUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": {"provider": s.llm.provider, "modelId": s.llm.model_id, "mode": s.llm.mode, "region": s.llm.bedrock_region,
                  "guardrail": s.llm.bedrock_guardrail_id or None, "maxTokens": s.llm.max_tokens, "temperature": s.llm.temperature},
        "bundles": [str(p) for p in bundle_paths],
        "runsPerBundle": runs,
        "attempts": len(attempts),
        "passed": passed,
        "passRate": round(rate, 3),
        "minPassRate": min_pass_rate,
        "verdict": "PASS" if attempts and rate >= min_pass_rate else "FAIL",
        "failureReasons": dict(reasons.most_common()),
        "latencyMs": {"p50": _pct(latencies, 0.5), "p95": _pct(latencies, 0.95), "max": max(latencies) if latencies else None},
        "tokens": {"avgInput": round(statistics.mean(tin)) if tin else None, "avgOutput": round(statistics.mean(tout)) if tout else None},
        "results": attempts,
        "acceptedExample": accepted_example,
        "rejectedExample": rejected_example,
    }


def write_evidence(result: dict, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_model = "".join(c if c.isalnum() or c in ".-" else "_" for c in result["model"]["modelId"])[:80]
    base = out_dir / f"qualify_{safe_model}_{result['model']['mode']}_{stamp}"
    jpath, mpath = base.with_suffix(".json"), base.with_suffix(".md")
    jpath.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    m = result["model"]
    lines = [
        f"# Model qualification: {result['verdict']}",
        "",
        f"- Model: `{m['modelId']}` ({m['provider']}, mode `{m['mode']}`, region `{m['region']}`, guardrail `{m['guardrail']}`)",
        f"- Attempts: {result['attempts']} ({result['runsPerBundle']} per bundle over {len(result['bundles'])} bundle(s))",
        f"- Guard pass rate: **{result['passRate']:.0%}** (required {result['minPassRate']:.0%})",
        f"- Latency ms p50/p95/max: {result['latencyMs']['p50']} / {result['latencyMs']['p95']} / {result['latencyMs']['max']}",
        f"- Avg tokens in/out: {result['tokens']['avgInput']} / {result['tokens']['avgOutput']}",
        "",
        "## Failure reasons",
        *([f"- {k}: {v}" for k, v in result["failureReasons"].items()] or ["- none"]),
        "",
        "## Example accepted digest",
        "",
        result["acceptedExample"] or "_none_",
        "",
        "## Example rejected output (first)",
        "",
        "```text",
        (result["rejectedExample"] or "none")[:4000],
        "```",
    ]
    mpath.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return jpath, mpath
