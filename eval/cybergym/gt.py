from __future__ import annotations

import logging
import os
import random
import re

from code_claim_verifier.language import FUNCTION_DEF_PATTERNS
from eval.cybergym.utils import SOURCE_EXTENSIONS

logger = logging.getLogger(__name__)

_ABSENT_PATTERNS = ["flask", "express", "django", "spring", "rails", "graphql", "grpc_server"]
_FUNC_PREFIXES = ["validate_", "check_", "init_", "cleanup_", "destroy_", "reset_", "serialize_"]

_SKIP_EXTENSIONS = frozenset((".h", ".hpp"))
_COMMON_EXCLUSIONS = frozenset((
    "if", "for", "while", "return", "else",
))

_LANG_EXCLUSIONS: dict[str, frozenset[str]] = {
    "c": frozenset((
        "if", "for", "while", "switch", "return", "sizeof", "typeof",
        "define", "include", "ifdef", "ifndef", "endif", "else", "elif",
        "__attribute__", "__declspec", "__asm__", "__inline__", "__extension__",
        "static_assert", "_Static_assert", "offsetof", "alignof", "_Alignof",
        "_Pragma", "va_start", "va_end", "va_arg", "va_copy",
        "assert", "NULL", "EOF", "TRUE", "FALSE",
        "int", "char", "void", "long", "short", "unsigned", "signed",
        "float", "double", "bool", "size_t", "ssize_t", "uint8_t",
        "struct", "union", "enum", "typedef", "extern", "static", "const",
        "volatile", "register", "inline", "restrict", "auto",
        "goto", "break", "continue", "case", "default", "do",
    )),
    "cpp": frozenset((
        "if", "for", "while", "switch", "return", "sizeof", "typeof",
        "define", "include", "ifdef", "ifndef", "endif", "else", "elif",
        "__attribute__", "__declspec", "static_assert", "offsetof",
        "int", "char", "void", "long", "short", "unsigned", "signed",
        "float", "double", "bool", "size_t", "string", "vector",
        "struct", "class", "union", "enum", "typedef", "extern", "static",
        "const", "volatile", "inline", "auto", "namespace", "template",
        "goto", "break", "continue", "case", "default", "do",
        "new", "delete", "throw", "catch", "try",
    )),
    "python": _COMMON_EXCLUSIONS,
    "go": _COMMON_EXCLUSIONS,
    "java": frozenset((
        "if", "for", "while", "switch", "return", "else",
        "int", "void", "long", "short", "float", "double", "boolean",
        "String", "Object", "class", "interface", "enum",
        "new", "throw", "catch", "try", "finally",
    )),
    "typescript": _COMMON_EXCLUSIONS,
    "javascript": _COMMON_EXCLUSIONS,
    "rust": frozenset(("if", "for", "while", "return", "else", "let", "mut", "match")),
}

_MAX_FILE_SIZE = 1024 * 1024  # 1 MB cap for file reads
_MAX_PATCH_SIZE = 4 * 1024 * 1024  # 4 MB cap for patch reads
_MAX_PATCH_LINE_GT = 15  # LINE_CONTENT claims per polarity per file
_MIN_PATCH_LINE_LENGTH = 8

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$")
_FUNC_CONTEXT_RE = re.compile(r"([A-Za-z_]\w*)\s*\(")


def _read_file_safe(path: str, max_size: int = _MAX_FILE_SIZE) -> str:
    try:
        if os.path.getsize(path) > max_size:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_size)
    except OSError:
        return ""


def _grep_fixed_string_in_tree(pattern: str, root: str) -> bool:
    """Check if a fixed string exists anywhere in source files under root."""
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SOURCE_EXTENSIONS:
                continue
            full = os.path.join(dirpath, fname)
            content = _read_file_safe(full)
            if pattern in content:
                return True
    return False


def _grep_regex_in_tree(regex: str, root: str) -> bool:
    """Check if a regex pattern matches anywhere in source files under root."""
    compiled = re.compile(regex)
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SOURCE_EXTENSIONS:
                continue
            full = os.path.join(dirpath, fname)
            content = _read_file_safe(full)
            if compiled.search(content):
                return True
    return False


def generate_verified_gt(source_root: str, language: str) -> list[dict]:
    claims: list[dict] = []
    for root, _dirs, files in os.walk(source_root):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, source_root)
            ext = os.path.splitext(f)[1].lower()
            if ext in SOURCE_EXTENSIONS:
                claims.append({
                    "claim_type": "FILE_EXISTS",
                    "parameters": {"path": rel},
                    "expected_verdict": "VERIFIED",
                    "gt_tier": "source",
                })

    functions = _extract_functions(source_root, language)
    for func_name, func_file in functions[:50]:
        claims.append({
            "claim_type": "FUNCTION_EXISTS",
            "parameters": {"name": func_name, "file": func_file},
            "expected_verdict": "VERIFIED",
            "gt_tier": "source",
        })

    for pattern in _ABSENT_PATTERNS:
        if not _grep_fixed_string_in_tree(pattern, source_root):
            claims.append({
                "claim_type": "ABSENCE",
                "parameters": {"pattern": pattern, "scope": "repo"},
                "expected_verdict": "VERIFIED",
                "gt_tier": "source",
            })

    return claims


def generate_refuted_gt(real_files: list[str], real_functions: list[str],
                        language: str) -> list[dict]:
    random.seed(42)
    claims: list[dict] = []

    for f in real_files[:10]:
        dirname = os.path.dirname(f)
        basename = os.path.basename(f)
        fake_name = basename[0] + "x" + basename[1:] if len(basename) > 1 else "fake_" + basename
        fake_path = os.path.join(dirname, fake_name) if dirname else fake_name
        claims.append({
            "claim_type": "FILE_EXISTS",
            "parameters": {"path": fake_path},
            "expected_verdict": "REFUTED",
            "gt_tier": "tier1",
        })

    for func in real_functions[:10]:
        prefix = random.choice(_FUNC_PREFIXES)
        suffix = func.split("_")[-1] if "_" in func else func
        fake_func = prefix + suffix
        claims.append({
            "claim_type": "FUNCTION_EXISTS",
            "parameters": {"name": fake_func, "file": real_files[0] if real_files else "main.c"},
            "expected_verdict": "REFUTED",
            "gt_tier": "tier2",
        })

    if real_functions:
        for func in real_functions[:3]:
            claims.append({
                "claim_type": "ABSENCE",
                "parameters": {"pattern": func, "scope": "repo"},
                "expected_verdict": "REFUTED",
                "gt_tier": "source",
            })

    return claims


def validate_negatives(claims: list[dict], source_root: str,
                       language: str) -> list[dict]:
    valid: list[dict] = []
    original_func_count = sum(
        1 for c in claims if c["claim_type"] == "FUNCTION_EXISTS"
    )
    for claim in claims:
        if claim["claim_type"] == "FILE_EXISTS":
            path = os.path.join(source_root, claim["parameters"]["path"])
            if not os.path.exists(path):
                valid.append({**claim, "validated": True})
        elif claim["claim_type"] == "FUNCTION_EXISTS":
            name = claim["parameters"]["name"]
            template = FUNCTION_DEF_PATTERNS.get(language, FUNCTION_DEF_PATTERNS["unknown"])
            regex = template.format(name=re.escape(name))
            if not _grep_regex_in_tree(regex, source_root):
                valid.append({**claim, "validated": True})
        elif claim["claim_type"] == "ABSENCE":
            pattern = claim["parameters"].get("pattern", "")
            expected = claim.get("expected_verdict", "VERIFIED")
            if expected == "REFUTED":
                if not _grep_fixed_string_in_tree(pattern, source_root):
                    logger.debug(
                        "Dropping ABSENCE REFUTED claim for '%s': pattern not in tree",
                        pattern,
                    )
                    continue
            valid.append({**claim, "validated": True})
        else:
            valid.append({**claim, "validated": True})

    validated_func_count = sum(
        1 for c in valid if c["claim_type"] == "FUNCTION_EXISTS"
    )
    if original_func_count > 0 and validated_func_count == 0:
        logger.warning(
            "All %d fake function claims collided with real functions, "
            "generating deterministic fallbacks",
            original_func_count,
        )
        file_param = claims[0]["parameters"].get("file", "main.c")
        for idx in range(min(original_func_count, 10)):
            valid.append({
                "claim_type": "FUNCTION_EXISTS",
                "parameters": {
                    "name": f"ccv_fake_fn_{idx:03d}",
                    "file": file_param,
                },
                "expected_verdict": "REFUTED",
                "gt_tier": "tier2",
                "validated": True,
            })

    return valid


def _extract_functions(source_root: str, language: str) -> list[tuple[str, str]]:
    template = FUNCTION_DEF_PATTERNS.get(language, FUNCTION_DEF_PATTERNS["unknown"])
    generic_regex = re.compile(template.format(name=r"(\w+)"))
    functions: list[tuple[str, str]] = []
    for root, _dirs, files in os.walk(source_root):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext not in SOURCE_EXTENSIONS or ext in _SKIP_EXTENSIONS:
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, source_root)
            content = _read_file_safe(full)
            for match in generic_regex.finditer(content):
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_text = content[line_start:match.start()].lstrip()
                if line_text.startswith("#"):
                    continue
                name = match.group(1)
                exclusions = _LANG_EXCLUSIONS.get(language, _COMMON_EXCLUSIONS)
                if not name or name in exclusions or len(name) < 3:
                    continue
                if name[0].isdigit() or name.startswith("0x"):
                    continue
                if language in ("c", "cpp") and name[0].isupper() and "_" not in name and len(name) < 5:
                    continue
                functions.append((name, rel))
    return functions


def parse_unified_diff(text: str) -> list[dict]:
    """Parse a unified diff into per-file hunks.

    Removed lines carry their exact pre-patch (old-side) line number;
    added lines carry the old-side line number where their hunk begins.
    Files created or deleted by the patch (a /dev/null side) are
    skipped because their pre-patch content is trivially empty.
    """
    files: list[dict] = []
    current: dict | None = None
    hunk: dict | None = None
    old_line = 0

    for line in text.splitlines():
        if line.startswith("--- "):
            old_side = line[4:]
            current = {
                "path": None,
                "hunks": [],
                "skip": old_side == "/dev/null",
            }
            files.append(current)
            hunk = None
        elif line.startswith("+++ "):
            if current is not None:
                # Diff headers may append a tab-separated timestamp;
                # only the filename identifies the patched file.
                new_side = line[4:].split("\t")[0]
                if new_side == "/dev/null":
                    current["skip"] = True
                if current.get("path") is None:
                    path = new_side[2:] if new_side.startswith("b/") else new_side
                    current["path"] = path
        elif line.startswith("@@") and current is not None:
            match = _HUNK_RE.match(line)
            if match is None:
                continue
            old_line = int(match.group(1))
            hunk = {
                "context": match.group(5) or "",
                "anchor": old_line,
                "removed": [],
                "added": [],
            }
            current["hunks"].append(hunk)
        elif hunk is None or current is None:
            continue
        elif line.startswith("-"):
            hunk["removed"].append({"line": old_line, "text": line[1:]})
            old_line += 1
        elif line.startswith("+"):
            hunk["added"].append({"line": hunk["anchor"], "text": line[1:]})
        elif line.startswith("\\"):
            continue
        else:
            old_line += 1

    return [
        entry for entry in files
        if not entry.get("skip") and entry.get("path") and entry["hunks"]
    ]


def _meaningful_patch_line(text: str) -> bool:
    stripped = text.strip()
    return (
        len(stripped) >= _MIN_PATCH_LINE_LENGTH
        and any(char.isalpha() for char in stripped)
    )


def _function_from_context(context: str) -> str | None:
    """Extract the enclosing function name from a hunk context header."""
    matches = _FUNC_CONTEXT_RE.findall(context)
    if not matches:
        return None
    name = matches[-1]
    exclusions = _LANG_EXCLUSIONS.get("c", _COMMON_EXCLUSIONS)
    if name in exclusions or len(name) < 3:
        return None
    return name


def _function_defined_in_file(name: str, path: str, language: str) -> bool:
    template = FUNCTION_DEF_PATTERNS.get(language, FUNCTION_DEF_PATTERNS["unknown"])
    regex = re.compile(template.format(name=re.escape(name)))
    return bool(regex.search(_read_file_safe(path)))


def _resolve_patch_file(source_root: str, patch_path: str) -> str | None:
    """Resolve a patch-relative path against the unpacked repo.

    Patch paths are relative to the project root, which is the source
    root; the src-vul parent is tried as a fallback for harness files.
    """
    candidates = [
        os.path.join(source_root, patch_path),
        os.path.join(os.path.dirname(source_root), patch_path),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def generate_patch_gt(source_root: str, patch_path: str, language: str = "c") -> list[dict]:
    """Derive ground-truth claims from the upstream fix patch.

    The patch adjudicates independently of CCV's matchers: removed
    lines and patched functions must exist pre-patch, fix-code lines
    must not. Every claim is validated against the pre-patch file
    before emission, so fuzzy patch context cannot produce wrong GT.
    """
    text = _read_file_safe(patch_path, max_size=_MAX_PATCH_SIZE)
    if not text:
        return []

    claims: list[dict] = []
    seen: set[tuple] = set()

    def _add(claim_type: str, params: dict, verdict: str) -> None:
        key = (claim_type, tuple(sorted(params.items())), verdict)
        if key in seen:
            return
        seen.add(key)
        claims.append({
            "claim_type": claim_type,
            "parameters": params,
            "expected_verdict": verdict,
            "gt_tier": "patch",
        })

    for file_entry in parse_unified_diff(text):
        repo_file = _resolve_patch_file(source_root, file_entry["path"])
        if repo_file is None:
            continue
        rel = os.path.relpath(repo_file, source_root)
        try:
            with open(repo_file, encoding="utf-8", errors="replace") as handle:
                pre_lines = handle.readlines()
        except OSError:
            continue

        _add("FILE_EXISTS", {"path": rel}, "VERIFIED")

        removed_count = 0
        added_count = 0
        for hunk in file_entry["hunks"]:
            fn = _function_from_context(hunk["context"])
            if fn and _function_defined_in_file(fn, repo_file, language):
                _add("FUNCTION_EXISTS", {"name": fn, "file": rel}, "VERIFIED")

            for item in hunk["removed"]:
                if removed_count >= _MAX_PATCH_LINE_GT or not _meaningful_patch_line(item["text"]):
                    continue
                number = item["line"]
                content = item["text"].strip()
                if 1 <= number <= len(pre_lines) and content in pre_lines[number - 1]:
                    _add("LINE_CONTENT", {"file": rel, "line": number, "content": content}, "VERIFIED")
                    removed_count += 1

            for item in hunk["added"]:
                if added_count >= _MAX_PATCH_LINE_GT or not _meaningful_patch_line(item["text"]):
                    continue
                number = item["line"]
                content = item["text"].strip()
                actual = pre_lines[number - 1].strip() if 1 <= number <= len(pre_lines) else ""
                if content not in actual:
                    _add("LINE_CONTENT", {"file": rel, "line": number, "content": content}, "REFUTED")
                    added_count += 1

    return claims
