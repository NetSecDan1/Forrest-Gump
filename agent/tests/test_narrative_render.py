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
        self.reply, self.exc, self.tools = reply, exc, None

    def __call__(self, prompt):
        if self.exc:
            raise self.exc
        return self.reply


def _narrator(agent):
    def factory(tools):
        agent.tools = tools
        return agent
    return StrandsNarrator(LlmConfig(provider="anthropic"), agent_factory=factory)


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
