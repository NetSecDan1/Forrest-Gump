"""Shaping report data before it reaches the LLM or a chat channel.

Report text originates partly from the directory (object names, event text, error messages) and must be
treated as untrusted DATA: strip control characters, cap length, and drop account names unless allowed.
"""

from __future__ import annotations

import re

from .models import Finding

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")
_WS = re.compile(r"\s+")


def clean_text(value: object, max_len: int = 400) -> str:
    s = "" if value is None else str(value)
    s = _CTRL.sub("", s)
    s = _WS.sub(" ", s).strip()
    s = s.replace("```", "'''")
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


def finding_for_llm(f: Finding, include_names: bool) -> dict:
    d = {
        "findingId": clean_text(f.id, 200),
        "checkId": f.checkId,
        "category": f.category,
        "severity": f.severity,
        "title": clean_text(f.title, 200),
        "target": clean_text(f.target, 200),
        "count": f.count,
        "detail": clean_text(f.detail, 300),
        "recommendation": clean_text(f.recommendation, 300),
    }
    if include_names and f.sample:
        d["sample"] = [clean_text(x, 64) for x in f.sample[:10]]
    return d
