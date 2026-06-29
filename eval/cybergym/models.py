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
    "claude-sonnet-4": {"factory": "anthropic", "model": "claude-sonnet-4@20250514"},
    "claude-haiku-4.5": {"factory": "anthropic", "model": "claude-haiku-4-5@20251001"},
    "gpt-4o": {"factory": "openai", "model": "gpt-4o"},
}


def get_model(name: str) -> LLMFunction:
    if name not in MODEL_REGISTRY:
        raise ValueError(f"Unknown model: {name}. Available: {list(MODEL_REGISTRY.keys())}")
    config = MODEL_REGISTRY[name]
    if config["factory"] == "anthropic":
        return make_anthropic(config["model"])
    elif config["factory"] == "openai":
        return make_openai(config["model"])
    else:
        raise ValueError(f"Unknown factory: {config['factory']}")
