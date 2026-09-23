import hashlib
import json
import shutil
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SAMPLE = REPO / "samples" / "ADForestHealth_contoso.test_20260901-020000"


def rehash(bundle: Path) -> None:
    m = json.loads((bundle / "manifest.json").read_text(encoding="utf-8-sig"))
    r = json.loads((bundle / "report.json").read_text(encoding="utf-8-sig"))
    m["reportId"] = r["reportId"]
    m["generatedUtc"] = r["generatedUtc"]
    for e in m["files"]:
        e["sha256"] = hashlib.sha256((bundle / e["path"]).read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")


def make_bundle(dest_root: Path, generated: str, full_run: bool = True, mutate=None) -> Path:
    """Copy the sample bundle, give it a new id/date, optionally mutate report dict, re-sign the manifest."""
    name = f"ADForestHealth_contoso.test_{generated[:10].replace('-', '')}-020000"
    dst = dest_root / name
    shutil.copytree(SAMPLE, dst)
    r = json.loads((dst / "report.json").read_text(encoding="utf-8-sig"))
    r["reportId"] = str(uuid.uuid4())
    r["generatedUtc"] = generated
    if full_run:
        for k in ("SkipDcDiag", "SkipEventLogs", "SkipRemoteCim", "SkipHygiene"):
            r["collector"]["parameters"][k] = False
    if mutate:
        mutate(r)
    (dst / "report.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    rehash(dst)
    return dst


@pytest.fixture
def sample_bundle() -> Path:
    return SAMPLE


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    (tmp_path / "inbox").mkdir()
    (tmp_path / "config").mkdir()
    shutil.copy(REPO / "agent" / "config" / "policy.yaml", tmp_path / "config" / "policy.yaml")
    (tmp_path / "config" / "settings.yaml").write_text(
        "inbox: ../inbox\nstate_db: ../state/db.sqlite\noutbox: ../outbox\ndry_run: true\npolicy_file: policy.yaml\n"
        "llm:\n  provider: none\n", encoding="utf-8")
    return tmp_path
