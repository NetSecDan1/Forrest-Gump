import json
import shutil

import pytest

from adhealth_agent.ingest import BundleError, discover_bundles, open_bundle
from conftest import make_bundle, rehash

MAX = 50 * 1024 * 1024


def test_sample_bundle_is_valid(sample_bundle):
    b = open_bundle(sample_bundle, MAX)
    assert b.report.forest.name == "contoso.test"
    assert b.report.summary.overallStatus == "Red"
    assert len(b.report.findings) > 10
    assert all(f.id.startswith(f.checkId + "|") for f in b.report.findings)


def test_tampered_file_is_rejected(tmp_path, sample_bundle):
    dst = tmp_path / sample_bundle.name
    shutil.copytree(sample_bundle, dst)
    with (dst / "report.json").open("a", encoding="utf-8") as f:
        f.write(" ")
    with pytest.raises(BundleError, match="SHA-256 mismatch"):
        open_bundle(dst, MAX)


def test_manifest_path_traversal_is_rejected(tmp_path, sample_bundle):
    dst = tmp_path / sample_bundle.name
    shutil.copytree(sample_bundle, dst)
    m = json.loads((dst / "manifest.json").read_text(encoding="utf-8"))
    m["files"].append({"path": "../../etc/passwd", "bytes": 1, "sha256": "00"})
    (dst / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(BundleError, match="Unsafe manifest path"):
        open_bundle(dst, MAX)


def test_unsupported_schema_major_is_rejected(tmp_path):
    dst = make_bundle(tmp_path, "2026-09-01T02:00:00Z", mutate=lambda r: r.update(schemaVersion="2.0"))
    with pytest.raises(BundleError, match="Unsupported schema major"):
        open_bundle(dst, MAX)


def test_invalid_severity_is_rejected(tmp_path):
    def bad(r):
        r["findings"][0]["severity"] = "Catastrophic"
    dst = make_bundle(tmp_path, "2026-09-01T02:00:00Z", mutate=bad)
    with pytest.raises(BundleError, match="schema validation"):
        open_bundle(dst, MAX)


def test_scalar_sample_is_normalized(tmp_path):
    """PowerShell 5.1 may emit one-element arrays as scalars."""
    def scalar(r):
        r["findings"][0]["sample"] = "only-one"
    dst = make_bundle(tmp_path, "2026-09-01T02:00:00Z", mutate=scalar)
    assert open_bundle(dst, MAX).report.findings[0].sample == ["only-one"]


def test_discovery_ignores_staging_and_incomplete(tmp_path):
    make_bundle(tmp_path, "2026-09-01T02:00:00Z")
    (tmp_path / ".staging" / "ADForestHealth_x").mkdir(parents=True)
    incomplete = tmp_path / "ADForestHealth_contoso.test_20260902-020000"
    incomplete.mkdir()
    (incomplete / "report.json").write_text("{}", encoding="utf-8")  # no manifest => still being written
    found = discover_bundles(tmp_path)
    assert [p.name for p in found] == ["ADForestHealth_contoso.test_20260901-020000"]


def test_rehash_helper_roundtrip(tmp_path):
    dst = make_bundle(tmp_path, "2026-09-01T02:00:00Z")
    rehash(dst)
    assert open_bundle(dst, MAX).report.is_full_run


def test_sample_validates_against_published_json_schema(sample_bundle):
    jsonschema = pytest.importorskip("jsonschema")
    from conftest import REPO

    schema = json.loads((REPO / "schema" / "ad-health-report.schema.json").read_text(encoding="utf-8"))
    report = json.loads((sample_bundle / "report.json").read_text(encoding="utf-8-sig"))
    jsonschema.validate(report, schema)
