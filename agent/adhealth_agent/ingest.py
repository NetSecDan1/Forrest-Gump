"""Bundle discovery, integrity verification and schema validation.

A bundle is only trusted if:
  * it contains manifest.json (the collector writes it last, after an atomic rename), and
  * every manifest entry stays inside the bundle, exists, is within size limits and matches its SHA-256, and
  * report.json is listed in the manifest and validates against the schema contract (major version 1).
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from . import SUPPORTED_SCHEMA_MAJOR
from .config import IntegrityConfig
from .models import Report


class BundleError(Exception):
    """Bundle failed integrity or schema checks. Never partially processed."""


@dataclass
class Bundle:
    path: Path
    report: Report
    manifest: dict
    signer: dict | None = None  # {"thumbprint", "subject", "trusted"} when manifest.sig.json is present


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


def _norm_thumb(t: str) -> str:
    return "".join(ch for ch in str(t) if ch.isalnum()).upper()


def verify_manifest_signature(path: Path, manifest_bytes: bytes, manifest: dict, integrity: IntegrityConfig | None) -> dict | None:
    """Authenticity: manifest.sig.json must be a valid signature over the exact manifest bytes by a pinned signer.

    Integrity (hashes) proves files match the manifest; this proves the manifest came from the collector's key.
    """
    integrity = integrity or IntegrityConfig()
    sig_path = path / "manifest.sig.json"
    if not sig_path.is_file():
        if integrity.require_signature:
            raise BundleError("Bundle is not signed (manifest.sig.json missing) and integrity.require_signature is true")
        return None
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    try:
        doc = json.loads(sig_path.read_text(encoding="utf-8-sig"))
        der = base64.b64decode(doc["certificate"], validate=True)
        sig = base64.b64decode(doc["signature"], validate=True)
        algorithm = str(doc["algorithm"])
        cert = x509.load_der_x509_certificate(der)
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise BundleError(f"manifest.sig.json unreadable: {type(e).__name__}") from e
    thumb = hashlib.sha1(der).hexdigest().upper()  # noqa: S324 - Windows certificate thumbprint convention, identity only
    if _norm_thumb(doc.get("thumbprint", thumb)) != thumb:
        raise BundleError("manifest.sig.json thumbprint does not match its certificate")
    pinned = {_norm_thumb(t) for t in integrity.trusted_signer_thumbprints}
    trusted = thumb in pinned
    if pinned and not trusted:
        raise BundleError(f"Bundle signed by untrusted certificate {thumb} (not in integrity.trusted_signer_thumbprints)")
    if integrity.require_signature and not pinned:
        raise BundleError("integrity.require_signature is true but no trusted_signer_thumbprints are configured")
    signed_at = _parse_time(manifest.get("generatedUtc"))
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    if signed_at and not (nb <= signed_at <= na):
        raise BundleError(f"Signing certificate was not valid at collection time ({signed_at.isoformat()})")
    key = cert.public_key()
    try:
        if algorithm == "RSA-PKCS1v15-SHA256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, manifest_bytes, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm == "ECDSA-P1363-SHA256" and isinstance(key, ec.EllipticCurvePublicKey):
            n = len(sig) // 2
            key.verify(encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big")),
                       manifest_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            raise BundleError(f"Unsupported signature algorithm/key combination: {algorithm}")
    except InvalidSignature as e:
        raise BundleError("Manifest signature is INVALID (manifest altered after signing, or forged)") from e
    return {"thumbprint": thumb, "subject": cert.subject.rfc4514_string(), "trusted": trusted}


def _parse_time(v) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _read_manifest(path: Path) -> tuple[bytes, dict]:
    try:
        raw = (path / "manifest.json").read_bytes()
        return raw, json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise BundleError(f"manifest.json unreadable: {e}") from e


def verify_bundle(path: Path, max_file_bytes: int, manifest: dict | None = None) -> dict:
    if manifest is None:
        manifest = _read_manifest(path)[1]
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


def open_bundle(path: Path, max_file_bytes: int, integrity: IntegrityConfig | None = None) -> Bundle:
    raw, manifest = _read_manifest(path)
    signer = verify_manifest_signature(path, raw, manifest, integrity)  # authenticity first, then integrity
    verify_bundle(path, max_file_bytes, manifest)
    report = load_report(path)
    if manifest.get("reportId") and manifest["reportId"] != report.reportId:
        raise BundleError("manifest.reportId does not match report.json reportId")
    return Bundle(path=path, report=report, manifest=manifest, signer=signer)
