"""Centralized grep with optional contextvars-based caching."""
from __future__ import annotations

import contextvars
import subprocess

_grep_cache: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "_grep_cache", default=None
)


def _run_grep(pattern: str, path: str, fixed: bool = False) -> list[str]:
    """Run grep subprocess and return matching lines. Returns empty list on no match."""
    cmd = ["grep", "-rn"]
    if fixed:
        cmd.append("-F")
    else:
        cmd.append("-E")
    cmd.extend([pattern, path])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
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
