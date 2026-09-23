"""Bundle discovery, integrity verification and schema validation.

A bundle is only trusted if:
  * it contains manifest.json (the collector writes it last, after an atomic rename), and
  * every manifest entry stays inside the bundle, exists, is within size limits and matches its SHA-256, and
  * report.json is listed in the manifest and validates against the schema contract (major version 1).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from . import SUPPORTED_SCHEMA_MAJOR
from .models import Report


class BundleError(Exception):
    """Bundle failed integrity or schema checks. Never partially processed."""


@dataclass
class Bundle:
    path: Path
    report: Report
    manifest: dict


def discover_bundles(inbox: Path) -> list[Path]:
    if not inbox.is_dir():
        raise BundleError(f"Inbox not found or not a directory: {inbox}")
    out = [
        p for p in inbox.iterdir()
        if p.is_dir() and not p.name.startswith(".") and p.name.startswith("ADForestHealth_") and (p / "manifest.json").is_file()
    ]
    return sorted(out, key=lambda p: p.name)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_bundle(path: Path, max_file_bytes: int) -> dict:
    try:
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as e:
        raise BundleError(f"manifest.json unreadable: {e}") from e
    files = manifest.get("files") or []
    if isinstance(files, dict):
        files = [files]
    listed = set()
    root = path.resolve()
    for entry in files:
        rel = str(entry.get("path", ""))
        pp = PurePosixPath(rel)
        if not rel or pp.is_absolute() or ".." in pp.parts or ":" in rel:
            raise BundleError(f"Unsafe manifest path: {rel!r}")
        target = (root / pp).resolve()
        if root not in target.parents:
            raise BundleError(f"Manifest path escapes bundle: {rel!r}")
        if not target.is_file():
            raise BundleError(f"Manifest file missing: {rel}")
        size = target.stat().st_size
        if size > max_file_bytes:
            raise BundleError(f"File exceeds size limit ({size} > {max_file_bytes}): {rel}")
        if _sha256(target) != str(entry.get("sha256", "")).lower():
            raise BundleError(f"SHA-256 mismatch (tampered or partial copy): {rel}")
        listed.add(rel)
    if "report.json" not in listed:
        raise BundleError("report.json is not covered by the manifest")
    return manifest


def load_report(path: Path) -> Report:
    raw = json.loads((path / "report.json").read_text(encoding="utf-8-sig"))
    version = str(raw.get("schemaVersion", "0"))
    try:
        major = int(version.split(".")[0])
    except ValueError as e:
        raise BundleError(f"Invalid schemaVersion {version!r}") from e
    if major != SUPPORTED_SCHEMA_MAJOR:
        raise BundleError(f"Unsupported schema major version {version} (agent supports {SUPPORTED_SCHEMA_MAJOR}.x)")
    try:
        return Report.model_validate(raw)
    except ValidationError as e:
        raise BundleError(f"report.json failed schema validation: {e.error_count()} error(s): {e.errors()[:3]}") from e


def peek_report_id(path: Path) -> str | None:
    """Cheap pre-check: reportId from manifest.json WITHOUT hashing, so an inbox that keeps months of bundles is not
    re-hashed every run. Only used to skip bundles already in history; new bundles are always fully verified."""
    try:
        rid = json.loads((path / "manifest.json").read_text(encoding="utf-8-sig")).get("reportId")
    except (OSError, json.JSONDecodeError, AttributeError):
        return None
    return str(rid) if rid else None


def open_bundle(path: Path, max_file_bytes: int) -> Bundle:
    manifest = verify_bundle(path, max_file_bytes)
    report = load_report(path)
    if manifest.get("reportId") and manifest["reportId"] != report.reportId:
        raise BundleError("manifest.reportId does not match report.json reportId")
    return Bundle(path=path, report=report, manifest=manifest)
