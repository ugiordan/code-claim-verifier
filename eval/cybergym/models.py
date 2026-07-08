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


def make_models_corp(model_id: str) -> LLMFunction:
    """Create an LLM function for a models-corp hosted model.

    Requires two environment variables:
        MODEL_API: the base URL for the model endpoint
        USER_KEY: your models-corp API key

    Get both from developer.models.corp.redhat.com > Applications & credentials.
    """
    import openai

    base_url = os.environ.get("MODEL_API", "")
    api_key = os.environ.get("USER_KEY", "")
    if not base_url:
        raise RuntimeError(
            "MODEL_API not set. Get the endpoint URL from developer.models.corp.redhat.com"
        )
    if not api_key:
        raise RuntimeError(
            "USER_KEY not set. Get it from developer.models.corp.redhat.com > Applications & credentials"
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
        return make_models_corp(config["model"])
    else:
        raise ValueError(f"Unknown factory: {config['factory']}")
