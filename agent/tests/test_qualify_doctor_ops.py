import json
import logging

from adhealth_agent.cli import main
from adhealth_agent.config import LlmConfig, load_settings
from adhealth_agent.doctor import run_doctor
from adhealth_agent.narrative import SECTIONS, StrandsNarrator
from adhealth_agent.ops import JsonFormatter
from adhealth_agent.qualify import run_qualification, write_evidence
from conftest import make_bundle


def _settings(workdir, provider_block="  provider: none\n"):
    p = workdir / "config" / "settings.yaml"
    p.write_text(p.read_text(encoding="utf-8").replace("  provider: none\n", provider_block), encoding="utf-8")
    return load_settings(p)


class ScriptedAgent:
    """Fake Strands agent: faithful on even calls, hallucinates on odd calls."""
    calls = 0

    def __call__(self, prompt):
        ScriptedAgent.calls += 1
        md = "\n".join(f"## {h}\n- see (REPL-002) (DC-001) (SYSVOL-002)\n" for h in SECTIONS)
        return md if ScriptedAgent.calls % 2 == 0 else md + "\n(NOPE-999)"


def test_qualification_reports_pass_rate_and_writes_evidence(workdir, tmp_path):
    s = _settings(workdir, "  provider: bedrock\n  model_id: vendor.model-x\n  bedrock_region: us-east-1\n")
    b1 = make_bundle(workdir / "inbox", "2026-08-01T02:00:00Z")
    b2 = make_bundle(workdir / "inbox", "2026-09-01T02:00:00Z")
    ScriptedAgent.calls = 0
    narrator = StrandsNarrator(s.llm, agent_factory=lambda tools: ScriptedAgent())
    res = run_qualification(s, [b2, b1], runs=2, min_pass_rate=0.9, narrator=narrator)
    assert res["attempts"] == 4 and res["passed"] == 2 and res["passRate"] == 0.5
    assert res["verdict"] == "FAIL"
    assert res["failureReasons"] == {"rejected: cites unknown check IDs": 2}
    assert res["model"]["modelId"] == "vendor.model-x"
    j, m = write_evidence(res, tmp_path / "evidence")
    assert json.loads(j.read_text())["verdict"] == "FAIL"
    assert "Guard pass rate: **50%**" in m.read_text()


def test_qualify_refuses_when_llm_disabled(workdir):
    b = make_bundle(workdir / "inbox", "2026-09-01T02:00:00Z")
    assert main(["qualify", "-c", str(workdir / "config" / "settings.yaml"), "-b", str(b)]) == 1


def test_doctor_offline_dry_run_warns_but_does_not_fail(workdir, capsys):
    s = _settings(workdir)
    checks = {c.name: c for c in run_doctor(s)}
    assert checks["inbox readable"].status == "PASS"
    assert checks["state writable"].status == "PASS"
    assert checks["dry_run"].status == "WARN"
    assert checks["Teams urgent webhook"].status == "WARN"  # missing is only a warning in dry-run
    assert checks["bundle signatures"].status == "WARN"
    assert checks["LLM"].status == "SKIP"
    assert main(["doctor", "-c", str(workdir / "config" / "settings.yaml")]) == 2
    assert "https://" not in capsys.readouterr().out


def test_doctor_never_prints_webhook_value(workdir, monkeypatch, capsys):
    monkeypatch.setenv("ADHEALTH_TEAMS_URGENT_WEBHOOK", "https://secret.example/hook?sig=SECRET")
    main(["doctor", "-c", str(workdir / "config" / "settings.yaml")])
    assert "SECRET" not in capsys.readouterr().out


def test_doctor_flags_missing_aws_credentials(workdir, monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(workdir / "none"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(workdir / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    s = _settings(workdir, "  provider: bedrock\n  model_id: vendor.model-x\n  bedrock_region: us-east-1\n")
    checks = {c.name: c for c in run_doctor(s)}
    assert checks["AWS credentials"].status == "FAIL"


def test_json_log_lines_are_parseable():
    rec = logging.LogRecord("adhealth_agent", logging.INFO, __file__, 1, "Processed %s", ("bundle-x",), None)
    doc = json.loads(JsonFormatter().format(rec))
    assert doc["msg"] == "Processed bundle-x" and doc["level"] == "INFO" and len(doc["runId"]) == 12


def test_process_writes_heartbeat(workdir):
    make_bundle(workdir / "inbox", "2026-09-01T02:00:00Z")
    assert main(["--log-format", "json", "process", "-c", str(workdir / "config" / "settings.yaml")]) == 0
    hb = json.loads((workdir / "state" / "heartbeat_process.json").read_text())
    assert hb["exitCode"] == 0 and hb["status"] == "ok" and hb["command"] == "process"


def test_single_shot_mode_config_roundtrip(workdir):
    s = _settings(workdir, "  provider: bedrock\n  model_id: vendor.model-x\n  bedrock_region: us-east-1\n  mode: single_shot\n")
    assert s.llm.mode == "single_shot"
    assert LlmConfig(provider="bedrock", model_id="vendor.m", bedrock_region="us-east-1", mode="single_shot").validate() is None
