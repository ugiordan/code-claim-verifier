from __future__ import annotations

import os
from typing import Callable


def make_llm_function(model: str | None = None) -> Callable[[str, str], str]:
    """Create an LLM function using the OpenAI SDK.

    Reads OPENAI_API_KEY from the environment. Returns a callable
    with signature (system_prompt, user_prompt) -> response_text.

    Args:
        model: Model name override. Defaults to gpt-4o.

    Raises:
        RuntimeError: If the openai package is not installed.
        ValueError: If OPENAI_API_KEY is not set.
    """
    try:
        import openai  # noqa: F811
    except ImportError:
        raise RuntimeError(
            "The 'openai' package is required. "
            "Install it with: pip install 'code-claim-verifier[openai]'"
        )

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable is not set")

    resolved_model = model or "gpt-4o"
    client = openai.OpenAI(api_key=api_key)

    def llm_function(system: str, user: str) -> str:
        response = client.chat.completions.create(
            model=resolved_model,
            max_tokens=4096,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        content = response.choices[0].message.content
        if content is None:
            raise RuntimeError("OpenAI API returned None content")
        return content

    return llm_function
