from __future__ import annotations

import logging
import os
from typing import Callable

logger = logging.getLogger(__name__)

LLMFunction = Callable[[str, str], str]



def make_anthropic(model: str = "claude-sonnet-4@20250514") -> LLMFunction:
    import anthropic

    use_vertex = os.environ.get("CLAUDE_CODE_USE_VERTEX") == "1"
    if use_vertex:
        project_id = os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "")
        region = os.environ.get("CLOUD_ML_REGION", "us-east5")
        if region == "global":
            region = "us-east5"
        client = anthropic.AnthropicVertex(project_id=project_id, region=region)
    else:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not set. Export it or set CLAUDE_CODE_USE_VERTEX=1 for Vertex AI."
            )
        client = anthropic.Anthropic(api_key=api_key)

    def call(system: str, user: str) -> str:
        response = client.messages.create(
            model=model, max_tokens=4096, temperature=0,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        if not response.content:
            raise RuntimeError("Empty response from Anthropic")
        return response.content[0].text

    return call


def make_openai(model: str = "gpt-4o") -> LLMFunction:
    import openai
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY not set. Export it before running the eval pipeline."
        )
    client = openai.OpenAI(api_key=api_key)

    def call(system: str, user: str) -> str:
        response = client.chat.completions.create(
            model=model, max_tokens=4096, temperature=0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        content = response.choices[0].message.content
        if content is None:
            raise RuntimeError("None content from OpenAI")
        return content

    return call


def _load_models_corp_config() -> dict:
    """Load models-corp config from ~/.config/ccv/models-corp.json.

    Maps model registry names to their endpoint URL and API key:
    {
        "granite-3.3-8b": {
            "endpoint": "https://...",
            "user_key": "your-key"
        },
        "llama-3.3-70b": {
            "endpoint": "https://...",
            "user_key": "your-key"
        }
    }

    Shorthand (same key for all): use a string value instead of object:
    {
        "granite-3.3-8b": "https://...",
        "user_key": "shared-key-for-all"
    }
    """
    import json
    config_path = os.path.expanduser("~/.config/ccv/models-corp.json")
    if os.path.isfile(config_path):
        try:
            with open(config_path) as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to load %s: %s", config_path, e)
    return {}


def make_models_corp(model_id: str, registry_name: str = "") -> LLMFunction:
    """Create an LLM function for a models-corp hosted model.

    Config resolution:
        1. ~/.config/ccv/models-corp.json (recommended)
        2. MODEL_API + USER_KEY env vars (single model fallback)

    Each model can have its own endpoint and key.
    """
    import openai

    config = _load_models_corp_config()
    model_config = config.get(registry_name, {})

    if isinstance(model_config, str):
        base_url = model_config
        api_key = config.get("user_key", "") or os.environ.get("USER_KEY", "")
    elif isinstance(model_config, dict):
        base_url = model_config.get("endpoint", "")
        api_key = model_config.get("user_key", "") or config.get("user_key", "") or os.environ.get("USER_KEY", "")
    else:
        base_url = os.environ.get("MODEL_API", "")
        api_key = os.environ.get("USER_KEY", "")

    if not base_url:
        base_url = os.environ.get("MODEL_API", "")

    if not base_url:
        raise RuntimeError(
            f"No endpoint for '{registry_name}'. Either:\n"
            f"  1. Create ~/.config/ccv/models-corp.json with endpoint URLs and keys\n"
            f"  2. Set MODEL_API env var\n"
            f"Get URLs and keys from developer.models.corp.redhat.com"
        )
    if not api_key:
        raise RuntimeError(
            "No API key for '{registry_name}'. Set user_key in config file or USER_KEY env var."
        )

    if not base_url.endswith("/v1"):
        base_url = base_url.rstrip("/") + "/v1"

    client = openai.OpenAI(base_url=base_url, api_key=api_key)

    def call(system: str, user: str) -> str:
        response = client.chat.completions.create(
            model=model_id, max_tokens=4096, temperature=0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        content = response.choices[0].message.content
        if content is None:
            raise RuntimeError(f"None content from {model_id}")
        return content

    return call


def make_generic_openai(base_url: str, api_key: str,
                        model: str) -> LLMFunction:
    import openai
    client = openai.OpenAI(base_url=base_url, api_key=api_key)

    def call(system: str, user: str) -> str:
        response = client.chat.completions.create(
            model=model, max_tokens=4096, temperature=0,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        content = response.choices[0].message.content
        if content is None:
            raise RuntimeError(f"None content from {model}")
        return content

    return call


MODEL_REGISTRY: dict[str, dict] = {
    # Anthropic (via Vertex AI)
    "claude-sonnet-4": {"factory": "anthropic", "model": "claude-sonnet-4@20250514"},
    "claude-haiku-4.5": {"factory": "anthropic", "model": "claude-haiku-4-5@20251001"},

    # OpenAI
    "gpt-4o": {"factory": "openai", "model": "gpt-4o"},

    # models-corp (Red Hat internal, VPN required)
    # Set MODEL_API and USER_KEY env vars before use.
    # MODEL_API is the per-model endpoint URL from the developer portal.
    "granite-3.3-8b": {
        "factory": "models-corp",
        "model": "ibm-granite/granite-3.3-8b-instruct",
    },
    "llama-3.3-70b": {
        "factory": "models-corp",
        "model": "RedHatAI/Llama-3.3-70B-Instruct-FP8-dynamic",
    },
    "qwen3-14b": {
        "factory": "models-corp",
        "model": "Qwen/Qwen3-14B",
    },
    "mistral-7b": {
        "factory": "models-corp",
        "model": "mistralai/Mistral-7B-Instruct-v0.3",
    },
    "gpt-oss-20b": {
        "factory": "models-corp",
        "model": "openai/gpt-oss-20b",
    },
}


def get_model(name: str) -> LLMFunction:
    if name not in MODEL_REGISTRY:
        raise ValueError(f"Unknown model: {name}. Available: {list(MODEL_REGISTRY.keys())}")
    config = MODEL_REGISTRY[name]
    if config["factory"] == "anthropic":
        return make_anthropic(config["model"])
    elif config["factory"] == "openai":
        return make_openai(config["model"])
    elif config["factory"] == "models-corp":
        return make_models_corp(config["model"], registry_name=name)
    else:
        raise ValueError(f"Unknown factory: {config['factory']}")
