from __future__ import annotations

import os
import shutil
import subprocess
from typing import Callable


def make_llm_function(model: str | None = None) -> Callable[[str, str], str]:
    """Create an LLM function backed by the OpenCode CLI.

    Resolves any provider-qualified model ID the local ``opencode`` CLI
    supports (for example ``enmaas/rits/zai-org/glm-5-3``). Reads no API
    keys: the CLI uses its own configured authentication.

    Args:
        model: Model ID override. When empty, the CLI's default model is
            used.

    Raises:
        RuntimeError: If the opencode CLI is not installed, or a call
            exits non-zero.
    """
    opencode_bin = shutil.which("opencode")
    if not opencode_bin:
        raise RuntimeError(
            "The 'opencode' CLI is required. Install it from https://opencode.ai"
        )

    resolved_model = model or ""

    def llm_function(system: str, user: str) -> str:
        prompt = f"{system}\n\n{user}" if system else user
        cmd = [opencode_bin, "run", "--standalone"]
        if resolved_model:
            cmd.extend(["--model", resolved_model])
        cmd.append(prompt)
        env = {**os.environ}
        # Match agent-dispatch conventions: no host skills, no recursion.
        env.pop("CLAUDE_SKILL_DIR", None)
        env["OPENCODE_DISABLE_CLAUDE_CODE"] = "1"
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, env=env,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"opencode run exited {proc.returncode}: {proc.stderr[:200]}"
            )
        return proc.stdout.strip()

    return llm_function
