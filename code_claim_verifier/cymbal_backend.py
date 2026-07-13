"""Optional cymbal backend for tree-sitter-based code analysis.

When cymbal (github.com/1broseidon/cymbal) is on PATH, CCV can use it
for AST-level function/symbol verification instead of grep. Cymbal
requires a git repository (runs `git init` if needed) and indexes
the code with tree-sitter.

Usage:
    verifier = CodeClaimVerifier(llm_function=my_llm, repo_path="/repo")
    verifier.load_cymbal()  # indexes the repo and enables cymbal queries
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


class CymbalBackend:
    """Query interface using cymbal CLI for tree-sitter-based symbol lookups."""

    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        self._ensure_git()
        self._index()

    def _ensure_git(self) -> None:
        git_dir = os.path.join(self.repo_path, ".git")
        if not os.path.isdir(git_dir):
            subprocess.run(
                ["git", "init", "-q"],
                cwd=self.repo_path, capture_output=True, timeout=10,
            )
            subprocess.run(
                ["git", "add", "-A"],
                cwd=self.repo_path, capture_output=True, timeout=30,
            )
            subprocess.run(
                ["git", "commit", "-q", "-m", "init", "--no-verify"],
                cwd=self.repo_path, capture_output=True, timeout=30,
            )

    def _index(self) -> None:
        result = subprocess.run(
            ["cymbal", "index", "."],
            cwd=self.repo_path, capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            logger.warning("cymbal index failed: %s", result.stderr[:200])

    def _run(self, *args: str) -> dict | list | None:
        cmd = ["cymbal", "--json"] + list(args)
        try:
            result = subprocess.run(
                cmd, cwd=self.repo_path,
                capture_output=True, text=True, timeout=30, errors="replace",
            )
            if result.returncode != 0:
                return None
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return None

    def function_exists(self, name: str, file: str | None = None) -> dict | None:
        data = self._run("search", name)
        if not data:
            return None
        results = data.get("results", [])
        for r in results:
            if r.get("kind") == "function" and r.get("name") == name:
                if file and not r.get("rel_path", "").endswith(file):
                    continue
                return r
        return None

    def function_callers(self, name: str) -> list[dict]:
        data = self._run("impact", name)
        if not data:
            return []
        return data.get("results", [])

    def function_callees(self, name: str) -> list[dict]:
        data = self._run("trace", name)
        if not data:
            return []
        return data.get("results", [])

    def investigate(self, name: str) -> dict | None:
        data = self._run("investigate", name)
        if not data:
            return None
        return data.get("results", {}).get("result", {})

    def outline(self, file_path: str) -> list[dict]:
        data = self._run("outline", file_path)
        if not data:
            return []
        return data.get("results", [])


def load_cymbal(repo_path: str) -> CymbalBackend | None:
    """Try to create a cymbal backend. Returns None if cymbal is not on PATH."""
    if not shutil.which("cymbal"):
        return None
    try:
        return CymbalBackend(repo_path)
    except Exception as e:
        logger.warning("Failed to initialize cymbal: %s", e)
        return None
