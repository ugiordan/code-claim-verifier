"""Reproducibility metadata for evaluation inputs and outputs."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Iterator


def iter_snapshot_files(root: str) -> Iterator[tuple[str, str]]:
    """Yield stable relative paths and files while excluding VCS metadata."""
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "__pycache__"})
        for filename in sorted(files):
            path = os.path.join(directory, filename)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            yield os.path.relpath(path, root).replace(os.sep, "/"), path


def snapshot_digest(root: str) -> str:
    """Hash file names and bytes for a repository snapshot."""
    digest = hashlib.sha256()
    for relative, path in iter_snapshot_files(root):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        with open(path, "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def text_digest(value: str) -> str:
    """Return a stable digest for a prompt, configuration, or text input."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def is_immutable_revision(value: object) -> bool:
    """Return whether a dataset revision is an immutable commit or digest."""
    if not isinstance(value, str):
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}|sha256:[0-9a-fA-F]{64}", value))


def git_head(root: str) -> str | None:
    """Return the checked-out commit when *root* is a real Git checkout."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def git_is_clean(root: str) -> bool:
    """Return whether a Git checkout has no tracked or untracked changes."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and not result.stdout.strip()
