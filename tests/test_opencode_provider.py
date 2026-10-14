from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import code_claim_verifier.providers.opencode_provider as opencode_provider


class TestOpencodeProvider:
    def test_builds_run_command_with_model(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs["env"]
            return SimpleNamespace(returncode=0, stdout="result\n", stderr="")

        with (
            patch.object(opencode_provider.shutil, "which", return_value="/usr/bin/opencode"),
            patch.object(opencode_provider.subprocess, "run", side_effect=fake_run),
        ):
            fn = opencode_provider.make_llm_function("enmaas/rits/zai-org/glm-5-3")
            assert fn("system", "user") == "result"

        cmd = captured["cmd"]
        assert cmd[:3] == ["/usr/bin/opencode", "run", "--standalone"]
        assert cmd[cmd.index("--model") + 1] == "enmaas/rits/zai-org/glm-5-3"
        assert cmd[-1] == "system\n\nuser"
        assert captured["env"]["OPENCODE_DISABLE_CLAUDE_CODE"] == "1"
        assert "CLAUDE_SKILL_DIR" not in captured["env"]

    def test_omits_model_flag_when_unset(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return SimpleNamespace(returncode=0, stdout="ok", stderr="")

        with (
            patch.object(opencode_provider.shutil, "which", return_value="/usr/bin/opencode"),
            patch.object(opencode_provider.subprocess, "run", side_effect=fake_run),
        ):
            fn = opencode_provider.make_llm_function(None)
            fn("s", "u")

        assert "--model" not in captured["cmd"]

    def test_raises_without_cli(self):
        with patch.object(opencode_provider.shutil, "which", return_value=None):
            try:
                opencode_provider.make_llm_function("m")
                raise AssertionError("expected RuntimeError")
            except RuntimeError:
                pass

    def test_raises_on_nonzero_exit(self):
        response = SimpleNamespace(returncode=1, stdout="", stderr="boom")
        with (
            patch.object(opencode_provider.shutil, "which", return_value="/usr/bin/opencode"),
            patch.object(opencode_provider.subprocess, "run", return_value=response),
        ):
            fn = opencode_provider.make_llm_function("m")
            try:
                fn("s", "u")
                raise AssertionError("expected RuntimeError")
            except RuntimeError as exc:
                assert "boom" in str(exc)

    def test_empty_system_prompt_is_omitted(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return SimpleNamespace(returncode=0, stdout="ok", stderr="")

        with (
            patch.object(opencode_provider.shutil, "which", return_value="/usr/bin/opencode"),
            patch.object(opencode_provider.subprocess, "run", side_effect=fake_run),
        ):
            fn = opencode_provider.make_llm_function("m")
            fn("", "user only")

        assert captured["cmd"][-1] == "user only"
