"""Outbound channels. Every publisher honors dry-run by writing the exact payload to the outbox instead."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path


def write_outbox(outbox: Path, name: str, payload: dict | str | bytes) -> Path:
    outbox.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = re.sub(r"[^\w.-]", "_", name)
    p = outbox / f"{stamp}_{safe}"
    n = 1
    while p.exists():  # never overwrite an earlier payload written in the same second
        p = outbox / f"{stamp}_{n}_{safe}"
        n += 1
    if isinstance(payload, dict):
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif isinstance(payload, bytes):
        p.write_bytes(payload)
    else:
        p.write_text(payload, encoding="utf-8")
    return p
