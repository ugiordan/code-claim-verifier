from __future__ import annotations

import os
import posixpath
import re


_KNOWN_FILE_SUFFIXES = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp",
    ".go", ".java", ".js", ".jsx", ".json", ".kt", ".kts",
    ".py", ".rb", ".rs", ".sh", ".toml", ".ts", ".tsx",
    ".xml", ".yaml", ".yml",
})
_SYMBOL_NAME_RE = re.compile(
    r"[A-Za-z_$~][A-Za-z0-9_$~]*(?:(?:\.|::)[A-Za-z_$~][A-Za-z0-9_$~]*)*"
)
_DESCRIPTIVE_SYMBOL_WORDS = frozenset({
    "a", "an", "the", "called", "function", "method", "procedure",
    "vulnerable", "relevant", "responsible", "that", "which",
})
_ABSENCE_PROSE_WORDS = frozenset({
    "a", "an", "the", "any", "all", "there", "is", "are", "does",
    "not", "no", "function", "method", "code", "claim", "source",
    "input", "validation", "security", "mitigation", "vulnerability",
    "authentication", "authorization", "auth",
})


def _normalize_claim_path(claim_path: object) -> str | None:
    """Normalize a relative claim path without allowing it to escape."""
    if not isinstance(claim_path, str) or not claim_path or "\x00" in claim_path:
        return None

    # Claims are platform-independent paths. Treat backslashes as separators
    # so Windows-style traversal is rejected on POSIX too.
    path = claim_path.replace("\\", "/")
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return None

    normalized = posixpath.normpath(path)
    if normalized == ".." or normalized.startswith("../"):
        return None
    return normalized


def safe_path(claim_path: str, repo_path: str) -> str | None:
    """Resolve a claim's file path safely within the repo.
    Returns None if the path escapes the repo (path traversal)."""
    normalized = _normalize_claim_path(claim_path)
    if normalized is None or not isinstance(repo_path, str):
        return None

    abs_repo = os.path.realpath(os.path.abspath(repo_path))
    resolved = os.path.realpath(os.path.join(abs_repo, normalized))
    try:
        inside_repo = os.path.commonpath((abs_repo, resolved)) == abs_repo
    except ValueError:
        inside_repo = False
    if not inside_repo:
        return None
    return resolved


def split_file_location(location: object) -> tuple[str, int | None] | None:
    """Split a ``path`` or ``path:line`` location when it is well formed."""
    if not isinstance(location, str) or not location:
        return None
    match = re.match(r"^(.*):([0-9]+)$", location)
    if match:
        return match.group(1), int(match.group(2))
    return location, None


def is_file_location(location: object) -> bool:
    """Return whether a location is plausibly an explicit source file."""
    parts = split_file_location(location)
    if parts is None:
        return False
    path, line = parts
    if line is not None:
        return True
    normalized = path.replace("\\", "/")
    suffix = os.path.splitext(normalized)[1].lower()
    if suffix in _KNOWN_FILE_SUFFIXES:
        return True
    return "/" in normalized and not normalized.startswith("/")


def is_concrete_symbol_name(value: object) -> bool:
    """Return whether a value looks like a source symbol, not prose."""
    if not isinstance(value, str) or not value or len(value) > 160:
        return False
    if not _SYMBOL_NAME_RE.fullmatch(value):
        return False
    parts = [part.lower() for part in re.split(r"[.:]+", value) if part]
    return not any(part in _DESCRIPTIVE_SYMBOL_WORDS for part in parts)


def is_concrete_search_pattern(value: object) -> bool:
    """Return whether a value is specific enough for a literal source search."""
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        return False
    words = value.strip().lower().split()
    if len(words) > 4 or any(word in _ABSENCE_PROSE_WORDS for word in words):
        return False
    identifier_parts = [part for part in re.split(r"[_./:-]+", value.lower()) if part]
    if len(identifier_parts) > 1 and any(
        part in _ABSENCE_PROSE_WORDS for part in identifier_parts
    ):
        return False
    if len(words) > 1 and not any(marker in value for marker in "(){}[]=.:/_-"):
        return words[0] in {"return", "throw", "raise", "assert"}
    return True
