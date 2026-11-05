"""Verifiers for authentication and authorization chain claims."""
from __future__ import annotations

import os
import re

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.security import (
    is_concrete_symbol_name,
    is_file_location,
    safe_path,
    split_file_location,
)
from code_claim_verifier.grep import grep as _grep


def _parse_grep_location(match: str) -> tuple[str, int] | None:
    parsed = re.match(r"^(.*):([0-9]+):", match)
    if not parsed:
        return None
    return parsed.group(1), int(parsed.group(2))


def _parse_grep_line(match: str) -> int | None:
    location = _parse_grep_location(match)
    return location[1] if location else None


def _resolve_grep_path(path: str, repo_path: str) -> str | None:
    if os.path.isabs(path):
        path = os.path.relpath(path, os.path.realpath(repo_path))
    else:
        # grep preserves the spelling of a relative search root. If that
        # spelling is already relative to the current working directory,
        # avoid prepending the repository path a second time.
        path_from_cwd = os.path.realpath(os.path.abspath(path))
        repo_real = os.path.realpath(os.path.abspath(repo_path))
        try:
            if os.path.commonpath((repo_real, path_from_cwd)) == repo_real:
                return path_from_cwd if os.path.isfile(path_from_cwd) else None
        except ValueError:
            pass
    resolved = safe_path(path, repo_path)
    return resolved if resolved and os.path.isfile(resolved) else None


def _call_chain_definition_pattern(name: str, language: str) -> str | None:
    escaped = re.escape(name)
    if language == "go":
        return (
            r"^[[:space:]]*func[[:space:]]+"
            r"(\([^)]*\)[[:space:]]+)?"
            + escaped + r"[[:space:]]*\("
        )
    if language in {"c", "cpp", "java"}:
        return (
            r"^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*[[:space:]*&<>:,]*)+"
            r"[[:space:]]+" + escaped
            + r"[[:space:]]*\([^;{}]*\)[[:space:]]*(const[[:space:]]*)?"
        )
    return None


def _mask_brace_text(text: str) -> str:
    """Mask comments and literals while preserving brace positions."""
    chars = list(text)
    state = "normal"
    i = 0
    while i < len(chars):
        if state == "line_comment":
            if chars[i] == "\n":
                state = "normal"
            else:
                chars[i] = " "
            i += 1
            continue
        if state == "block_comment":
            if chars[i:i + 2] == ["*", "/"]:
                chars[i] = chars[i + 1] = " "
                state = "normal"
                i += 2
            else:
                if chars[i] != "\n":
                    chars[i] = " "
                i += 1
            continue
        if state in {"single_quote", "double_quote", "raw_quote"}:
            terminator = "`" if state == "raw_quote" else (
                "'" if state == "single_quote" else '"'
            )
            if chars[i] == "\\" and state != "raw_quote":
                chars[i] = " "
                if i + 1 < len(chars) and chars[i + 1] != "\n":
                    chars[i + 1] = " "
                i += 2
            elif chars[i] == terminator:
                chars[i] = " "
                state = "normal"
                i += 1
            else:
                if chars[i] != "\n":
                    chars[i] = " "
                i += 1
            continue

        if chars[i:i + 2] == ["/", "/"]:
            chars[i] = chars[i + 1] = " "
            state = "line_comment"
            i += 2
        elif chars[i:i + 2] == ["/", "*"]:
            chars[i] = chars[i + 1] = " "
            state = "block_comment"
            i += 2
        elif chars[i] == '"':
            chars[i] = " "
            state = "double_quote"
            i += 1
        elif chars[i] == "'":
            chars[i] = " "
            state = "single_quote"
            i += 1
        elif chars[i] == "`":
            chars[i] = " "
            state = "raw_quote"
            i += 1
        else:
            i += 1
    return "".join(chars)


def _extract_brace_body(path: str, start_line: int) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None

    lines_before = text.splitlines(keepends=True)[:max(start_line - 1, 0)]
    start_offset = sum(len(line) for line in lines_before)
    masked = _mask_brace_text(text)
    opening = masked.find("{", start_offset)
    if opening < 0:
        return None

    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return masked[opening + 1:index]
    return None


def _function_body_range(path: str, line_number: int, language: str) -> tuple[int, int] | None:
    """Return the byte range of the function containing a source line."""
    if language not in {"go", "c", "cpp", "java"}:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            text = stream.read()
    except OSError:
        return None

    masked = _mask_brace_text(text)
    if language == "go":
        signature = re.compile(
            r"(?m)^\s*func\s+"
            r"(?:\([^)]*\)\s+)?[A-Za-z_][A-Za-z0-9_]*"
            r"\s*\([^;{}]*\)[^{;]*\{"
        )
    else:
        signature = re.compile(
            r"(?m)^\s*(?!if\b|for\b|while\b|switch\b|catch\b)"
            r"[^{};\n]*[A-Za-z_][A-Za-z0-9_]*\s*"
            r"\([^;{}]*\)\s*(?:const\s*)?\{"
        )

    line_start = sum(len(line) for line in text.splitlines(keepends=True)[:line_number - 1])
    ranges: list[tuple[int, int]] = []
    for match in signature.finditer(masked):
        opening = match.end() - 1
        depth = 0
        for index in range(opening, len(masked)):
            if masked[index] == "{":
                depth += 1
            elif masked[index] == "}":
                depth -= 1
                if depth == 0:
                    ranges.append((opening, index + 1))
                    break

    containing = [item for item in ranges if item[0] <= line_start < item[1]]
    return min(containing, key=lambda item: item[1] - item[0]) if containing else None


def _find_function_definitions(
    name: str, repo_path: str, language: str,
) -> list[tuple[str, int]]:
    languages = [language] if language in {"go", "c", "cpp", "java"} else ["go", "c", "cpp"]
    definitions: set[tuple[str, int]] = set()
    for candidate_language in languages:
        pattern = _call_chain_definition_pattern(name, candidate_language)
        if pattern is None:
            continue
        for match in _grep(pattern, repo_path):
            location = _parse_grep_location(match)
            if location is None:
                continue
            path, line_num = location
            resolved = _resolve_grep_path(path, repo_path)
            if resolved:
                definitions.add((resolved, line_num))
    return sorted(definitions)


def verify_call_chain(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    """Verify that function A calls B (multi-hop supported via chain parameter).

    Parameters:
        chain: list of function names ["A", "B", "C"] meaning A->B->C
        OR caller/callee pair for single hop.
    """
    chain = claim.parameters.get("chain", [])
    caller = claim.parameters.get("caller", "")
    callee = claim.parameters.get("callee", "")

    if not chain and caller and callee:
        chain = [caller, callee]

    if len(chain) < 2:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="Need at least 2 functions in chain", method="call_chain",
        )
    if not all(is_concrete_symbol_name(item) for item in chain):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Call chain contains a descriptive or invalid symbol: {chain}",
            method="call_chain",
        )

    broken_at = None
    evidence_parts = []

    for i in range(len(chain) - 1):
        src, dst = chain[i], chain[i + 1]
        definitions = _find_function_definitions(src, repo_path, language)
        if not definitions:
            broken_at = f"{src} definition not found in analyzed source"
            break

        call_pattern = re.compile(
            r"(?<![A-Za-z0-9_$])" + re.escape(dst) + r"\s*\("
        )
        found_call = False
        unavailable_body = False
        parsed_bodies = 0
        for src_file, start_line in definitions:
            body = _extract_brace_body(src_file, start_line)
            if body is None:
                unavailable_body = True
                continue
            parsed_bodies += 1
            call_match = call_pattern.search(body)
            if call_match:
                evidence_parts.append(
                    f"{src}->{dst}: {src_file}:{start_line} body contains {dst}()"
                )
                found_call = True
                break

        if found_call:
            continue
        if unavailable_body or parsed_bodies == 0:
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence=(f"Unable to analyze {src}'s function body precisely; "
                          f"did not search unrelated callee occurrences"),
                method="call_chain",
            )
        broken_at = f"{src} does not call {dst}"
        break

    if broken_at:
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.70,
            evidence=f"Chain broken: {broken_at}. Verified: {'; '.join(evidence_parts)}",
            method="call_chain",
        )
    return VerifiedClaim(
        claim=claim, verdict="VERIFIED", method_confidence=0.70,
        evidence=f"Chain verified: {'; '.join(evidence_parts)}",
        method="call_chain",
    )


def verify_default_value(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    """Verify what a variable/config defaults to when empty/nil.

    Parameters:
        variable: name of the variable or config field
        file: optional file to search in
        default_behavior: "allow" or "deny" (what the agent claims)
    """
    variable = claim.parameters.get("variable", "")
    file_param = claim.parameters.get("file", "")
    claimed_behavior = claim.parameters.get("default_behavior", "")
    if not isinstance(claimed_behavior, str):
        claimed_behavior = ""
    claimed_behavior = claimed_behavior.lower()

    if not isinstance(variable, str) or not variable:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="No variable specified", method="default_value",
        )
    if claimed_behavior and claimed_behavior not in {"allow", "deny"}:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Unsupported default behavior: {claimed_behavior}",
            method="default_value",
        )

    search_path = repo_path
    if file_param:
        resolved = safe_path(file_param, repo_path)
        if resolved is None or not os.path.isfile(resolved):
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence=(f"Invalid default-value file path: {file_param}"
                          if resolved is None else f"Default-value file not found: {file_param}"),
                method="file_scope",
            )
        search_path = resolved

    escaped_variable = re.escape(variable)
    check_pattern = (
        rf"(len\s*\(\s*{escaped_variable}\s*\)\s*"
        rf"(==|<=|<)\s*0\b|{escaped_variable}\s*==\s*nil\b|"
        rf"{escaped_variable}\s*!=\s*nil\b)"
    )
    found_checks = _grep(check_pattern, search_path)
    var_matches = _grep(rf"\b{escaped_variable}\b", search_path)

    if not var_matches:
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.80,
            evidence=f"Variable '{variable}' not found in searched scope",
            method="default_value",
        )

    if not found_checks:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=(f"Variable '{variable}' found, but no empty/nil behavior check "
                      "was found"),
            method="default_value",
        )

    boolean_matches = _grep(r"\breturn\s+(true|false)\b", search_path)
    related_boolean: list[str] = []
    for check in found_checks:
        check_location = _parse_grep_location(check)
        if check_location is None:
            continue
        check_path, check_line = check_location
        check_resolved = _resolve_grep_path(check_path, repo_path)
        if check_resolved is None:
            continue
        body_range = _function_body_range(check_resolved, check_line, language)
        for boolean in boolean_matches:
            boolean_location = _parse_grep_location(boolean)
            if boolean_location is None:
                continue
            boolean_path, boolean_line = boolean_location
            boolean_resolved = _resolve_grep_path(boolean_path, repo_path)
            if boolean_resolved != check_resolved or not (check_line <= boolean_line <= check_line + 6):
                continue
            if body_range is not None:
                with open(check_resolved, "r", encoding="utf-8", errors="replace") as stream:
                    offsets = [0]
                    for line in stream:
                        offsets.append(offsets[-1] + len(line))
                boolean_offset = offsets[boolean_line - 1] if boolean_line > 0 else -1
                if not (body_range[0] <= boolean_offset < body_range[1]):
                    continue
            if boolean_resolved == check_resolved:
                related_boolean.append(boolean)

    if not related_boolean:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=(f"Variable '{variable}' has an empty/nil check, but no nearby "
                      "allow/deny behavior was found"),
            method="default_value",
        )

    allow_hits = [m for m in related_boolean if re.search(r"return\s+true\b", m)]
    deny_hits = [m for m in related_boolean if re.search(r"return\s+false\b", m)]
    evidence = (f"Variable '{variable}' found with behavior check: "
                f"{found_checks[0][:150]}; {related_boolean[0][:150]}")

    if claimed_behavior == "allow":
        if allow_hits:
            verdict = "VERIFIED"
        elif deny_hits:
            verdict = "REFUTED"
        else:
            verdict = "UNVERIFIABLE"
    elif claimed_behavior == "deny":
        if deny_hits:
            verdict = "VERIFIED"
        elif allow_hits:
            verdict = "REFUTED"
        else:
            verdict = "UNVERIFIABLE"
    else:
        verdict = "VERIFIED"

    return VerifiedClaim(
        claim=claim, verdict=verdict,
        method_confidence=0.55 if verdict != "UNVERIFIABLE" else 0.0,
        evidence=evidence,
        method="default_value",
    )


def verify_config_flag(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    """Verify a config flag is set in deployment templates or code.

    Parameters:
        flag: the flag name (e.g., "enable-k8s-token-validation")
        value: expected value (e.g., "true")
        scope: "code" or "manifests" or "all"
    """
    flag = claim.parameters.get("flag", "")
    expected_value = claim.parameters.get("value", "")
    raw_scope = claim.parameters.get("scope", "all")
    if not isinstance(raw_scope, str):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Invalid config scope: {raw_scope}", method="config_flag",
        )
    scope = raw_scope.lower()

    if not isinstance(flag, str) or not flag:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="No flag specified", method="config_flag",
        )

    if scope not in {"all", "code", "manifests"}:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Unsupported config scope: {raw_scope}", method="config_flag",
        )

    file_param = claim.parameters.get("file", "")
    location = claim.parameters.get("location", "")
    line_num = claim.parameters.get("line")
    location_parts = split_file_location(location) if is_file_location(location) else None
    if not file_param and location_parts is not None:
        file_param, location_line = location_parts
        if line_num is None:
            line_num = location_line

    search_path = repo_path
    if file_param:
        resolved = safe_path(file_param, repo_path)
        if resolved is None or not os.path.isfile(resolved):
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence=(f"Invalid config file path: {file_param}"
                          if resolved is None else f"Config file not found: {file_param}"),
                method="file_scope",
            )
        search_path = resolved

    if line_num is not None and (
        isinstance(line_num, bool) or not isinstance(line_num, int) or line_num < 1
    ):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Invalid config line: {line_num}", method="file_scope",
        )

    code_extensions = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".go",
        ".java", ".js", ".jsx", ".kt", ".kts", ".py", ".rb", ".rs",
        ".sh", ".ts", ".tsx",
    }
    manifest_extensions = {
        ".cfg", ".ini", ".json", ".mod", ".toml", ".xml", ".yaml", ".yml",
    }
    if file_param and scope != "all":
        suffix = os.path.splitext(file_param)[1].lower()
        basename = os.path.basename(file_param).lower()
        allowed = code_extensions if scope == "code" else manifest_extensions
        if suffix not in allowed and basename not in {"dockerfile", "makefile", "cmakelists.txt"}:
            return VerifiedClaim(
                claim=claim, verdict="REFUTED", method_confidence=0.85,
                evidence=f"File '{file_param}' is outside the requested {scope} scope",
                method="config_scope",
            )

    matches = _grep(flag, search_path, fixed=True)
    if scope != "all" and search_path == repo_path:
        allowed_extensions = code_extensions if scope == "code" else manifest_extensions
        filtered: list[str] = []
        for match in matches:
            parsed = _parse_grep_location(match)
            if parsed is None:
                continue
            match_path = parsed[0].replace("\\", "/").lower()
            base = os.path.basename(match_path)
            if os.path.splitext(base)[1] in allowed_extensions or base in {
                "dockerfile", "makefile", "cmakelists.txt",
            }:
                filtered.append(match)
        matches = filtered

    if line_num is not None:
        matches = [m for m in matches if _parse_grep_line(m) == line_num]

    if not matches:
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.85,
            evidence=f"Flag '{flag}' not found anywhere in repo",
            method="config_flag",
        )

    if expected_value:
        value_matches = [m for m in matches if expected_value in m]
        if value_matches:
            return VerifiedClaim(
                claim=claim, verdict="VERIFIED", method_confidence=0.80,
                evidence=f"Flag '{flag}' set to '{expected_value}': {value_matches[0][:200]}",
                method="config_flag",
            )
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.75,
            evidence=f"Flag '{flag}' found but not with value '{expected_value}': {matches[0][:200]}",
            method="config_flag",
        )

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED", method_confidence=0.80,
        evidence=f"Flag '{flag}' found: {matches[0][:200]}",
        method="config_flag",
    )
