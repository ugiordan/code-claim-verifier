"""Centralized grep with optional contextvars-based caching."""
from __future__ import annotations

import contextvars
import subprocess

_grep_cache: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "_grep_cache", default=None
)


_SOURCE_EXTENSIONS = [
    "*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hh",
    "*.py", "*.go", "*.rs", "*.java", "*.kt", "*.kts",
    "*.js", "*.ts", "*.tsx", "*.jsx",
    "*.rb", "*.sh", "*.yaml", "*.yml", "*.json", "*.toml",
    "*.mod", "*.sum", "*.txt", "*.cfg", "*.ini", "*.xml",
    "Makefile", "Dockerfile", "CMakeLists.txt",
]


def _run_grep(pattern: str, path: str, fixed: bool = False) -> list[str]:
    """Run grep subprocess and return matching lines. Returns empty list on no match.

    Filters to source file extensions to avoid scanning binaries and test data.
    Uses 120s timeout for large repos.
    """
    import os
    # -H forces the filename prefix on every match. GNU grep omits it when
    # given a single file, which breaks the "path:line:text" parsing used
    # throughout the verifiers; BSD grep always includes it.
    cmd = ["grep", "-rnH", "--binary-files=without-match"]
    if fixed:
        cmd.append("-F")
    else:
        # grep -E has no (?:...) groups: GNU grep treats the dangling ? as
        # an error ("warning: ? at start of expression") and never matches.
        # The verifiers' templates are shared with Python re, which needs
        # them; translate to plain groups here, where numbering does not
        # matter because only match presence is used.
        pattern = pattern.replace("(?:", "(")
        cmd.append("-E")
    if os.path.isdir(path):
        for ext in _SOURCE_EXTENSIONS:
            cmd.extend(["--include", ext])
    cmd.extend([pattern, path])
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=120, errors="replace",
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def grep(pattern: str, path: str, fixed: bool = False) -> list[str]:
    """Grep with optional caching. Returns a defensive copy when cache is active."""
    cache = _grep_cache.get()
    if cache is None:
        return _run_grep(pattern, path, fixed)

    key = (pattern, path, fixed)
    if key not in cache:
        cache[key] = _run_grep(pattern, path, fixed)
    return list(cache[key])


def cache_context() -> contextvars.Token:
    """Activate the grep cache. Returns a token for reset_cache()."""
    return _grep_cache.set({})


def reset_cache(token: contextvars.Token) -> None:
    """Deactivate the grep cache, restoring the previous contextvar state."""
    _grep_cache.reset(token)
