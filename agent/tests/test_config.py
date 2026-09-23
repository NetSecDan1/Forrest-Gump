import pytest

from adhealth_agent.config import LlmConfig, load_settings


@pytest.mark.parametrize("cfg, msg", [
    (LlmConfig(provider="anthropic", model_id="x"), "must be bedrock or none"),
    (LlmConfig(provider="bedrock"), "model_id is required"),
    (LlmConfig(provider="bedrock", model_id="claude-model", bedrock_region="us-east-1"), "is not a Bedrock model id"),
    (LlmConfig(provider="bedrock", model_id="us.anthropic.x"), "bedrock_region is required"),
    (LlmConfig(provider="bedrock", model_id="us.anthropic.x", bedrock_region="us-east-1", bedrock_guardrail_id="g"), "guardrail"),
    (LlmConfig(provider="openai"), "must be bedrock or none"),
])
def test_llm_config_rejects_off_golden_path(cfg, msg):
    with pytest.raises(ValueError, match=msg):
        cfg.validate()


@pytest.mark.parametrize("model_id", [
    "anthropic.some-claude-model-v1:0", "us.anthropic.some-profile", "amazon.nova-pro-v1:0",
    "meta.llama-model-v1:0", "mistral.some-model-v1:0",
])
def test_any_bedrock_vendor_is_accepted(model_id):
    LlmConfig(provider="bedrock", model_id=model_id, bedrock_region="us-east-1").validate()


def test_mode_is_validated():
    with pytest.raises(ValueError, match="llm.mode"):
        LlmConfig(provider="none", mode="chat").validate()


def test_valid_configs():
    LlmConfig(provider="none").validate()
    LlmConfig(provider="bedrock", model_id="us.anthropic.x", bedrock_region="us-east-1").validate()
    LlmConfig(provider="bedrock", model_id="arn:aws:bedrock:us-east-1:123:inference-profile/x").validate()


def test_example_settings_fail_loudly_until_model_is_set(tmp_path):
    """The shipped example must not silently run against a default/unapproved model."""
    from conftest import REPO

    text = (REPO / "agent" / "config" / "settings.example.yaml").read_text(encoding="utf-8")
    (tmp_path / "policy.yaml").write_text("urgent: {}\n", encoding="utf-8")
    p = tmp_path / "settings.yaml"
    p.write_text(text.replace('policy_file: "policy.yaml"', 'policy_file: "policy.yaml"'), encoding="utf-8")
    with pytest.raises(ValueError, match="model_id is required"):
        load_settings(p)
    p.write_text(text.replace('model_id: ""', 'model_id: "us.anthropic.approved"').replace('bedrock_region: ""', 'bedrock_region: "us-east-1"'), encoding="utf-8")
    assert load_settings(p).llm.provider == "bedrock"
