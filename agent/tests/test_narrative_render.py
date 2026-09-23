import json
from datetime import datetime, timezone

import pytest

from adhealth_agent.config import LlmConfig, Policy
from adhealth_agent.ingest import open_bundle
from adhealth_agent.narrative import SECTIONS, StrandsNarrator, build_tool_data, deterministic_narrative, validate_narrative
from adhealth_agent.render import digest_html, markdown_to_html, teams_digest_card, teams_urgent_card
from adhealth_agent.triage import triage

MAX = 50 * 1024 * 1024
NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)


@pytest.fixture
def t(sample_bundle):
    return triage(open_bundle(sample_bundle, MAX).report, None, Policy(), NOW)


def _good_md(t) -> str:
    crit = sorted({f.checkId for f in t.active if f.severity == "Critical"})
    body = {h: "- ok" for h in SECTIONS}
    body["Urgent attention"] = "\n".join(f"- Critical issue ({c})" for c in crit)
    return "\n".join(f"## {h}\n{b}\n" for h, b in body.items())


class FakeAgent:
    def __init__(self, reply=None, exc=None):
        self.reply, self.exc, self.tools, self.prompt = reply, exc, None, None

    def __call__(self, prompt):
        self.prompt = prompt
        if self.exc:
            raise self.exc
        return self.reply


def _narrator(agent, mode="agent"):
    def factory(tools):
        agent.tools = tools
        return agent
    cfg = LlmConfig(provider="bedrock", model_id="vendor.test-model", bedrock_region="us-east-1", mode=mode)
    return StrandsNarrator(cfg, agent_factory=factory)


def test_deterministic_has_all_sections_and_passes_guard(t):
    md = deterministic_narrative(t)
    assert validate_narrative(md, t) == []


def test_provider_none_uses_template(t):
    res = StrandsNarrator(LlmConfig(provider="none")).generate(t, "September 2026")
    assert res.source == "deterministic"


def test_llm_output_accepted_when_faithful(t):
    pytest.importorskip("strands")
    res = _narrator(FakeAgent(_good_md(t))).generate(t, "September 2026")
    assert res.source == "llm" and not res.warnings


def test_llm_hallucinated_check_id_rejected(t):
    pytest.importorskip("strands")
    res = _narrator(FakeAgent(_good_md(t) + "\nAlso (ZZZ-999) is broken.")).generate(t, "September 2026")
    assert res.source == "deterministic"
    assert any("unknown check IDs" in w for w in res.warnings)


def test_llm_omitting_critical_rejected(t):
    pytest.importorskip("strands")
    md = "\n".join(f"## {h}\n- fine\n" for h in SECTIONS)
    res = _narrator(FakeAgent(md)).generate(t, "September 2026")
    assert res.source == "deterministic"
    assert any("omits checks with Critical" in w for w in res.warnings)


def test_llm_exception_falls_back(t):
    pytest.importorskip("strands")
    res = _narrator(FakeAgent(exc=TimeoutError("boom"))).generate(t, "September 2026")
    assert res.source == "deterministic" and "TimeoutError" in res.warnings[0]


def test_tools_are_read_only_views_without_names(t):
    pytest.importorskip("strands")
    from adhealth_agent.narrative import make_tools

    data = build_tool_data(t, include_names=False)
    tools = {x.tool_name: x for x in make_tools(data)}
    assert set(tools) == {"get_overview", "list_findings", "list_resolved_findings", "get_metric_trends", "get_metric_history"}
    crit = tools["list_findings"](severity="Critical")
    assert crit and all(f["severity"] == "Critical" for f in crit)
    assert all("sample" not in f for f in data["findings"])
    assert "olduser1" not in json.dumps(data["findings"])  # account names from the sample never reach the model


def test_teams_cards_contain_no_account_names(t):
    urgent = teams_urgent_card(t, t.urgent, "https://example/report.html")
    digest = teams_digest_card(t, deterministic_narrative(t), "September 2026", None, "deterministic")
    blob = json.dumps(urgent) + json.dumps(digest)
    for name in ("olduser1", "legacy_app", "admin1", "WIN7-KIOSK"):
        assert name not in blob
    assert urgent["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert len(json.dumps(urgent)) < 28000  # Teams card payload limit


def test_markdown_renderer_escapes_html():
    out = markdown_to_html("## Head\n- <script>alert(1)</script> **bold**")
    assert "<script>" not in out and "&lt;script&gt;" in out and "<b>bold</b>" in out


def test_digest_html_renders(t):
    page = digest_html(t, deterministic_narrative(t), "September 2026", "deterministic", None)
    assert "<script" not in page and "AD Forest Health Digest" in page


def test_bedrock_model_is_built_with_region_endpoint_and_guardrail(monkeypatch):
    pytest.importorskip("strands")
    pytest.importorskip("boto3")
    from adhealth_agent.llm import build_model

    for k, v in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}.items():
        monkeypatch.setenv(k, v)
    cfg = LlmConfig(provider="bedrock", model_id="us.anthropic.approved-profile", bedrock_region="us-east-1",
                    bedrock_endpoint_url="https://vpce-123.bedrock-runtime.us-east-1.vpce.amazonaws.com",
                    bedrock_guardrail_id="gr-abc", bedrock_guardrail_version="3")
    m = build_model(cfg)  # no network at construction
    assert m.config["model_id"] == "us.anthropic.approved-profile"
    assert m.client.meta.region_name == "us-east-1"
    assert m.client.meta.endpoint_url.startswith("https://vpce-123.")
    req = m.format_request([{"role": "user", "content": [{"text": "hi"}]}], None,
                           system_prompt_content=[{"text": "sys"}])
    assert req["guardrailConfig"]["guardrailIdentifier"] == "gr-abc"
    assert req["modelId"] == "us.anthropic.approved-profile"


def test_single_shot_mode_inlines_sanitized_data_without_tools(t):
    agent = FakeAgent(_good_md(t))
    res = _narrator(agent, mode="single_shot").generate(t, "September 2026")
    assert res.source == "llm"
    assert agent.tools == []
    assert "<report_data>" in agent.prompt and "olduser1" not in agent.prompt
    assert res.meta["mode"] == "single_shot" and res.meta["modelId"] == "vendor.test-model"
    assert res.meta["latencyMs"] >= 0


def test_rejected_output_is_kept_for_qualification_evidence(t):
    pytest.importorskip("strands")
    res = _narrator(FakeAgent("## Executive summary\nnothing")).generate(t, "September 2026")
    assert res.source == "deterministic" and res.rejected_markdown.startswith("## Executive summary")


def test_only_bedrock_provider_is_registered():
    from adhealth_agent.llm import registered_providers

    assert registered_providers() == ["bedrock"]
