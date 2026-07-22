from __future__ import annotations

import logging
import os
import random
import re

from code_claim_verifier.language import FUNCTION_DEF_PATTERNS, IMPORT_PATTERNS
from eval.cybergym.utils import load_jsonl, save_jsonl, SOURCE_EXTENSIONS
from eval.multilang.constants import CandidateStatus

logger = logging.getLogger(__name__)

_ABSENT_PATTERNS = ["flask", "express", "django", "spring", "rails", "graphql", "grpc_server"]
_FUNC_PREFIXES = ["validate_", "check_", "init_", "cleanup_", "destroy_", "reset_", "serialize_"]
_IMPORT_PREFIXES = ["fake_", "mock_", "test_", "old_"]

_SKIP_EXTENSIONS = frozenset((".h", ".hpp"))
_COMMON_EXCLUSIONS = frozenset(("if", "for", "while", "return", "else"))
_LANG_EXCLUSIONS: dict[str, frozenset[str]] = {
    "c": frozenset((
        "if", "for", "while", "switch", "return", "sizeof", "typeof",
        "define", "include", "ifdef", "ifndef", "endif", "else", "elif",
        "__attribute__", "__declspec", "__asm__", "__inline__", "__extension__",
        "static_assert", "_Static_assert", "offsetof", "alignof", "_Alignof",
        "int", "char", "void", "long", "short", "unsigned", "signed",
        "float", "double", "bool", "size_t", "ssize_t", "uint8_t",
        "struct", "union", "enum", "typedef", "extern", "static", "const",
        "volatile", "register", "inline", "restrict", "auto",
        "goto", "break", "continue", "case", "default", "do",
    )),
    "cpp": frozenset((
        "if", "for", "while", "switch", "return", "sizeof", "typeof",
        "define", "include", "ifdef", "ifndef", "endif", "else", "elif",
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

_MAX_FILE_SIZE = 1024 * 1024


def _read_file_safe(path: str, max_size: int = _MAX_FILE_SIZE) -> str:
    try:
        if os.path.getsize(path) > max_size:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_size)
    except OSError:
        return ""


def _grep_fixed_in_tree(pattern: str, root: str) -> bool:
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != '.git']
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SOURCE_EXTENSIONS:
                continue
            content = _read_file_safe(os.path.join(dirpath, fname))
            if pattern in content:
                return True
    return False


def _grep_regex_in_tree(regex: str, root: str) -> bool:
    compiled = re.compile(regex)
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != '.git']
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SOURCE_EXTENSIONS:
                continue
            content = _read_file_safe(os.path.join(dirpath, fname))
            if compiled.search(content):
                return True
    return False


def _strip_block_comments(content: str) -> str:
    """Strip /* ... */ block comments from content."""
    return re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)


def _extract_functions(source_root: str, language: str) -> list[tuple[str, str]]:
    template = FUNCTION_DEF_PATTERNS.get(language, FUNCTION_DEF_PATTERNS["unknown"])
    generic_regex = re.compile(template.format(name=r"(\w+)"))
    functions: list[tuple[str, str]] = []
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d != '.git']
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext not in SOURCE_EXTENSIONS or ext in _SKIP_EXTENSIONS:
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, source_root)
            content = _read_file_safe(full)
            content = _strip_block_comments(content)
            for match in generic_regex.finditer(content):
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_text = content[line_start:match.start()].lstrip()
                if line_text.startswith("#") or line_text.startswith("//"):
                    continue
                # Bug #1 fix: Check if "new" appears right before the captured name
                if language == "java":
                    match_text = content[match.start():match.end()]
                    if " new " in match_text or match_text.lstrip().startswith("new "):
                        continue
                # Bug #5 fix: Handle multi-group regex (JS/TS arrow functions)
                name = next((g for g in match.groups() if g), None)
                if not name:
                    continue
                exclusions = _LANG_EXCLUSIONS.get(language, _COMMON_EXCLUSIONS)
                if name in exclusions or len(name) < 3:
                    continue
                if name[0].isdigit() or name.startswith("0x"):
                    continue
                if language in ("c", "cpp") and name[0].isupper() and "_" not in name and len(name) < 5:
                    continue
                functions.append((name, rel))
    return functions


def _extract_imports(source_root: str, language: str) -> list[str]:
    """Extract imports from source files. Returns list of module names."""
    imports: set[str] = set()

    if language == "python":
        import_re = re.compile(r"^(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import)", re.MULTILINE)
    elif language == "go":
        # Bug #11 fix: Only match imports within import blocks or import lines
        import_re = re.compile(r'(?:^import\s+"([^"]+)"|^import\s+\(\s*\n(?:\s*"([^"]+)"\s*\n)+\s*\))', re.MULTILINE)
    elif language in ("javascript", "typescript"):
        import_re = re.compile(r"""(?:from\s+['"]([^'"]+)['"]|require\(['"]([^'"]+)['"]\))""")
    elif language == "java":
        import_re = re.compile(r"^import\s+(?:static\s+)?([\w.]+)", re.MULTILINE)
    elif language == "rust":
        import_re = re.compile(r"^use\s+([\w:]+)", re.MULTILINE)
    else:
        return []

    for dirpath, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d != '.git']
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SOURCE_EXTENSIONS:
                continue
            content = _read_file_safe(os.path.join(dirpath, fname))

            # For Go, need special handling
            if language == "go":
                # Find all import statements
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("import "):
                        # Single import: import "path" or import alias "path" or import . "path" or import _ "path"
                        m = re.search(r'import\s+(?:\w+\s+)?"([^"]+)"', line)
                        if m:
                            module = m.group(1).split("/")[-1] if "/" in m.group(1) else m.group(1)
                            imports.add(module)
                # Find import blocks
                in_import_block = False
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("import ("):
                        in_import_block = True
                        continue
                    if in_import_block:
                        if line.startswith(")"):
                            in_import_block = False
                            continue
                        m = re.search(r'"([^"]+)"', line)
                        if m:
                            module = m.group(1).split("/")[-1] if "/" in m.group(1) else m.group(1)
                            imports.add(module)
            else:
                for m in import_re.finditer(content):
                    for g in m.groups():
                        if g:
                            if language in ("python", "java"):
                                module = g.split(".")[0]
                            elif language == "go":
                                module = g.split("/")[-1] if "/" in g else g
                            else:
                                module = g
                            imports.add(module)

    return sorted(imports)


def _extract_call_sites(source_root: str, func_names: list[str],
                        language: str) -> list[tuple[str, str]]:
    """Find where functions are called. Returns list of (func_name, file)."""
    calls: list[tuple[str, str]] = []
    for func_name in func_names:
        call_pattern = re.compile(r"\b" + re.escape(func_name) + r"\s*\(")
        func_def_template = FUNCTION_DEF_PATTERNS.get(language, FUNCTION_DEF_PATTERNS["unknown"])
        func_def_re = re.compile(func_def_template.format(name=re.escape(func_name)))

        for dirpath, dirs, files in os.walk(source_root):
            dirs[:] = [d for d in dirs if d != '.git']
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in SOURCE_EXTENSIONS or ext in _SKIP_EXTENSIONS:
                    continue
                full = os.path.join(dirpath, fname)
                rel = os.path.relpath(full, source_root)
                content = _read_file_safe(full)

                # Bug #4 fix: Store definition ranges not just start positions
                # Find all definition ranges first
                def_ranges: list[tuple[int, int]] = []
                for def_match in func_def_re.finditer(content):
                    # Store the range of the entire definition match
                    def_ranges.append((def_match.start(), def_match.end()))

                for m in call_pattern.finditer(content):
                    # Skip if this call overlaps with any definition range
                    is_def = any(ds <= m.start() <= de for ds, de in def_ranges)
                    if is_def:
                        continue
                    line_start = content.rfind("\n", 0, m.start()) + 1
                    line_text = content[line_start:m.start()].lstrip()
                    if line_text.startswith("#") or line_text.startswith("//") or line_text.startswith("/*") or line_text.startswith("*"):
                        continue
                    calls.append((func_name, rel))
                    break
    return calls


def generate_verified_gt(source_root: str, language: str) -> list[dict]:
    """Generate verified (positive) ground truth claims."""
    claims: list[dict] = []

    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d != '.git']
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
    func_names = []
    for func_name, func_file in functions[:50]:
        claims.append({
            "claim_type": "FUNCTION_EXISTS",
            "parameters": {"name": func_name, "file": func_file},
            "expected_verdict": "VERIFIED",
            "gt_tier": "source",
        })
        func_names.append(func_name)

    imports = _extract_imports(source_root, language)
    for module in imports[:30]:
        claims.append({
            "claim_type": "IMPORT_EXISTS",
            "parameters": {"module": module},
            "expected_verdict": "VERIFIED",
            "gt_tier": "source",
        })

    call_sites = _extract_call_sites(source_root, func_names[:20], language)
    seen_calls: set[str] = set()
    for func_name, call_file in call_sites:
        key = f"{func_name}:{call_file}"
        if key in seen_calls:
            continue
        seen_calls.add(key)
        claims.append({
            "claim_type": "FUNCTION_CALLED",
            "parameters": {"name": func_name, "file": call_file},
            "expected_verdict": "VERIFIED",
            "gt_tier": "derived",
        })

    for pattern in _ABSENT_PATTERNS:
        if not _grep_fixed_in_tree(pattern, source_root):
            claims.append({
                "claim_type": "ABSENCE",
                "parameters": {"pattern": pattern, "scope": "repo"},
                "expected_verdict": "VERIFIED",
                "gt_tier": "source",
            })

    return claims


def generate_refuted_gt(real_files: list[str], real_functions: list[str],
                        real_imports: list[str], language: str) -> list[dict]:
    """Generate refuted (negative) ground truth claims."""
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
            "parameters": {"name": fake_func, "file": real_files[0] if real_files else "main.go"},
            "expected_verdict": "REFUTED",
            "gt_tier": "tier2",
        })

    for module in real_imports[:5]:
        prefix = random.choice(_IMPORT_PREFIXES)
        fake_module = prefix + module
        claims.append({
            "claim_type": "IMPORT_EXISTS",
            "parameters": {"module": fake_module},
            "expected_verdict": "REFUTED",
            "gt_tier": "tier2",
        })

    for func in real_functions[:5]:
        fake_caller = "ccv_nonexistent_caller_" + func[:8]
        claims.append({
            "claim_type": "FUNCTION_CALLED",
            "parameters": {"name": fake_caller, "file": real_files[0] if real_files else "main.go"},
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
    """Validate that negative claims don't collide with real code."""
    valid: list[dict] = []
    original_func_count = sum(1 for c in claims if c["claim_type"] == "FUNCTION_EXISTS")

    for claim in claims:
        ct = claim["claim_type"]
        if ct == "FILE_EXISTS":
            path = os.path.join(source_root, claim["parameters"]["path"])
            if not os.path.exists(path):
                valid.append({**claim, "validated": True})
        elif ct == "FUNCTION_EXISTS":
            name = claim["parameters"]["name"]
            template = FUNCTION_DEF_PATTERNS.get(language, FUNCTION_DEF_PATTERNS["unknown"])
            regex = template.format(name=re.escape(name))
            if not _grep_regex_in_tree(regex, source_root):
                valid.append({**claim, "validated": True})
        elif ct == "IMPORT_EXISTS":
            module = claim["parameters"]["module"]
            patterns = IMPORT_PATTERNS.get(language, IMPORT_PATTERNS.get("unknown", []))
            found = False
            for pat_template in patterns:
                pat = pat_template.format(module=re.escape(module))
                if _grep_regex_in_tree(pat, source_root):
                    found = True
                    break
            if not found:
                valid.append({**claim, "validated": True})
        elif ct == "FUNCTION_CALLED":
            name = claim["parameters"]["name"]
            call_re = re.escape(name) + r"\s*\("
            if not _grep_regex_in_tree(call_re, source_root):
                valid.append({**claim, "validated": True})
        elif ct == "ABSENCE":
            pattern = claim["parameters"].get("pattern", "")
            expected = claim.get("expected_verdict", "VERIFIED")
            if expected == "REFUTED":
                if not _grep_fixed_in_tree(pattern, source_root):
                    continue
            valid.append({**claim, "validated": True})
        else:
            valid.append({**claim, "validated": True})

    validated_func_count = sum(1 for c in valid if c["claim_type"] == "FUNCTION_EXISTS")
    if original_func_count > 0 and validated_func_count == 0:
        func_claims = [c for c in claims if c["claim_type"] == "FUNCTION_EXISTS"]
        file_param = func_claims[0]["parameters"].get("file", "main.go") if func_claims else "main.go"
        for idx in range(min(original_func_count, 10)):
            valid.append({
                "claim_type": "FUNCTION_EXISTS",
                "parameters": {"name": f"ccv_fake_fn_{idx:03d}", "file": file_param},
                "expected_verdict": "REFUTED",
                "gt_tier": "tier2",
                "validated": True,
            })

    return valid


def generate_gt_for_case(candidate: dict, base_dir: str) -> dict:
    """Generate ground truth claims for a single candidate."""
    source_root = candidate.get("source_root", "")
    language = candidate.get("language", "unknown")
    source_path = os.path.join(base_dir, source_root) if not os.path.isabs(source_root) else source_root

    verified_gt = generate_verified_gt(source_path, language)

    func_names = [c["parameters"]["name"] for c in verified_gt if c["claim_type"] == "FUNCTION_EXISTS"]
    import_names = [c["parameters"]["module"] for c in verified_gt if c["claim_type"] == "IMPORT_EXISTS"]
    src_files: list[str] = []
    for root, dirs, files in os.walk(source_path):
        dirs[:] = [d for d in dirs if d != '.git']
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in SOURCE_EXTENSIONS:
                src_files.append(os.path.relpath(os.path.join(root, f), source_path))

    refuted_gt = generate_refuted_gt(src_files, func_names, import_names, language)
    refuted_gt = validate_negatives(refuted_gt, source_path, language)

    all_gt = verified_gt + refuted_gt

    candidate["gt_claims"] = all_gt
    candidate["source_files"] = src_files[:100]
    candidate["source_functions"] = func_names[:50]

    verified_count = sum(1 for c in all_gt if c["expected_verdict"] == "VERIFIED")
    refuted_count = sum(1 for c in all_gt if c["expected_verdict"] == "REFUTED")
    if verified_count >= 5 and refuted_count >= 3:
        candidate["status"] = CandidateStatus.READY
    else:
        candidate["status"] = CandidateStatus.FAILED
        candidate["failure_reason"] = f"GT quality: {verified_count} verified, {refuted_count} refuted"
        candidate["failure_stage"] = "generate_gt"

    return candidate


def run_generate_gt(candidates_path: str, base_dir: str) -> None:
    """Main entry point: generate ground truth for all verified candidates."""
    candidates = load_jsonl(candidates_path)
    _SAVE_INTERVAL = 50
    gt_count = 0

    for i, c in enumerate(candidates):
        if c.get("status") == CandidateStatus.READY:
            continue
        if c.get("status") != CandidateStatus.VERIFIED:
            continue

        logger.info("[%d/%d] Generating GT for %s", i + 1, len(candidates), c["osv_id"])
        candidates[i] = generate_gt_for_case(c, base_dir)
        gt_count += 1

        if gt_count % _SAVE_INTERVAL == 0:
            save_jsonl(candidates, candidates_path)
            ready_so_far = sum(1 for x in candidates if x.get("status") == CandidateStatus.READY)
            logger.info("Checkpoint: %d ready so far (%d processed)", ready_so_far, gt_count)

    save_jsonl(candidates, candidates_path)
    ready = sum(1 for c in candidates if c.get("status") == CandidateStatus.READY)
    logger.info("Ready: %d / %d", ready, len(candidates))
