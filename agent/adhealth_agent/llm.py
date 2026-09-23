"""Model layer: Strands Agents is the agent framework; the model is configuration.

Nothing in the agent depends on a specific model family. Any model the configured provider serves can be used
(on Bedrock: Anthropic Claude, Amazon Nova, Meta Llama, Mistral, ...), subject to qualification with
``adhealth-agent qualify`` before it goes to production.

Providers are registered here. Only ``bedrock`` is registered because it is the approved golden path; adding
another provider is a one-function change that must go through architecture/security review (see CLAUDE.md).
"""

from __future__ import annotations

from typing import Any, Callable

from .config import LlmConfig

ModelFactory = Callable[[LlmConfig], Any]
_PROVIDERS: dict[str, ModelFactory] = {}


def register_provider(name: str) -> Callable[[ModelFactory], ModelFactory]:
    def deco(fn: ModelFactory) -> ModelFactory:
        _PROVIDERS[name] = fn
        return fn
    return deco


def registered_providers() -> list[str]:
    return sorted(_PROVIDERS)


@register_provider("bedrock")
def _bedrock(cfg: LlmConfig):
    """Amazon Bedrock (Converse API) via Strands. Credentials: standard AWS chain - IAM Roles Anywhere
    credential_process on-prem, task/instance role in AWS. Never from config files."""
    from botocore.config import Config
    from strands.models.bedrock import BedrockModel

    model_cfg: dict[str, Any] = {"model_id": cfg.model_id, "max_tokens": cfg.max_tokens}
    if cfg.temperature is not None:
        model_cfg["temperature"] = cfg.temperature
    if cfg.bedrock_guardrail_id:
        model_cfg.update(guardrail_id=cfg.bedrock_guardrail_id, guardrail_version=cfg.bedrock_guardrail_version)
    kwargs: dict[str, Any] = {
        "boto_client_config": Config(read_timeout=cfg.request_timeout_seconds, connect_timeout=10,
                                     retries={"max_attempts": cfg.max_attempts, "mode": "adaptive"}),
    }
    if cfg.bedrock_region:
        kwargs["region_name"] = cfg.bedrock_region
    if cfg.bedrock_endpoint_url:
        kwargs["endpoint_url"] = cfg.bedrock_endpoint_url
    return BedrockModel(**kwargs, **model_cfg)


def build_model(cfg: LlmConfig):
    cfg.validate()
    factory = _PROVIDERS.get(cfg.provider)
    if factory is None:
        raise ValueError(f"No model provider registered for {cfg.provider!r} (registered: {registered_providers()})")
    return factory(cfg)


def usage_of(result: Any) -> dict[str, int]:
    """Token usage from a Strands AgentResult (empty dict if unavailable, e.g. test fakes)."""
    try:
        u = result.metrics.accumulated_usage
        return {"inputTokens": int(u.get("inputTokens", 0)), "outputTokens": int(u.get("outputTokens", 0)),
                "totalTokens": int(u.get("totalTokens", 0))}
    except AttributeError:
        return {}
