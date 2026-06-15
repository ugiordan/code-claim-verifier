from __future__ import annotations

import os
from typing import Callable


def make_llm_function(model: str | None = None) -> Callable[[str, str], str]:
    """Create an LLM function using the Anthropic SDK.

    Reads ANTHROPIC_API_KEY from the environment. Returns a callable
    with signature (system_prompt, user_prompt) -> response_text.

    Args:
        model: Model name override. Defaults to claude-sonnet-4-20250514.

    Raises:
        RuntimeError: If the anthropic package is not installed.
        ValueError: If ANTHROPIC_API_KEY is not set.
    """
    try:
        import anthropic  # noqa: F811
    except ImportError:
        raise RuntimeError(
            "The 'anthropic' package is required. "
            "Install it with: pip install 'code-claim-verifier[anthropic]'"
        )

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable is not set")

    resolved_model = model or "claude-sonnet-4-20250514"
    client = anthropic.Anthropic(api_key=api_key)

    def llm_function(system: str, user: str) -> str:
        response = client.messages.create(
            model=resolved_model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text

    return llm_function
