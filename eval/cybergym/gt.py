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
_KEYWORD_EXCLUSIONS = frozenset((
    "if", "for", "while", "switch", "return", "sizeof", "typeof",
    "define", "include", "ifdef", "ifndef", "endif", "else", "elif",
))

_MAX_FILE_SIZE = 1024 * 1024  # 1 MB cap for file reads


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
                if name not in _KEYWORD_EXCLUSIONS:
                    functions.append((name, rel))
    return functions
