from __future__ import annotations

import os
import re

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.security import (
    is_file_location,
    is_concrete_search_pattern,
    safe_path,
    split_file_location,
)
from code_claim_verifier.grep import grep as _grep


def _grep_line_number(match: str) -> int | None:
    """Extract the line number from grep's ``path:line:text`` output."""
    parsed = re.match(r"^.*:([0-9]+):", match)
    return int(parsed.group(1)) if parsed else None


def _entry_point_scope(
    claim: TypedClaim, repo_path: str,
) -> tuple[str | None, int | None, str | None]:
    """Resolve an optional ENTRY_POINT file/location scope."""
    file_param = claim.parameters.get("file", "")
    location = claim.parameters.get("location", "")
    line_num = claim.parameters.get("line")

    target_file = file_param
    location_parts = split_file_location(location) if is_file_location(location) else None
    if not target_file and location_parts is not None:
        target_file, location_line = location_parts
        if line_num is None:
            line_num = location_line

    if not target_file:
        return repo_path, line_num, None
    if not isinstance(target_file, str) or not target_file:
        return None, None, f"Invalid entry-point file path: {target_file}"
    resolved = safe_path(target_file, repo_path)
    if resolved is None:
        return None, None, f"Invalid entry-point file path: {target_file}"
    if not os.path.isfile(resolved):
        return None, None, f"Entry-point file not found: {target_file}"
    if line_num is not None and (
        isinstance(line_num, bool) or not isinstance(line_num, int) or line_num < 1
    ):
        return None, None, f"Invalid entry-point line: {line_num}"
    return resolved, line_num, None


def verify_absence(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    pattern = (claim.parameters.get("pattern", "")
               or claim.parameters.get("item", "")
               or claim.parameters.get("description", "")
               or claim.parameters.get("name", "")
               or claim.parameters.get("type", ""))
    if not is_concrete_search_pattern(pattern):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="Absence claim does not contain a concrete source pattern",
            method="grep_absent",
        )
    raw_scope = claim.parameters.get("scope", "repo")
    if not isinstance(raw_scope, str):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Invalid absence scope: {raw_scope}", method="grep_absent",
        )
    scope = raw_scope.lower()

    if scope == "file":
        file_path = claim.parameters.get("file", "")
        if not file_path:
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence="File scope requested but no file path was supplied",
                method="grep_absent",
            )
        resolved = safe_path(file_path, repo_path)
        if resolved is None or not os.path.isfile(resolved):
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence=(f"Invalid absence file path: {file_path}"
                          if resolved is None else f"Absence file not found: {file_path}"),
                method="grep_absent",
            )
        search_path = resolved
    elif scope == "directory":
        dir_path = claim.parameters.get("directory", "")
        if not dir_path:
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence="Directory scope requested but no directory path was supplied",
                method="grep_absent",
            )
        resolved = safe_path(dir_path, repo_path)
        if resolved is None or not os.path.isdir(resolved):
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence=(f"Invalid absence directory path: {dir_path}"
                          if resolved is None else f"Absence directory not found: {dir_path}"),
                method="grep_absent",
            )
        search_path = resolved
    elif scope == "repo":
        search_path = repo_path
    else:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Unsupported absence scope: {raw_scope}", method="grep_absent",
        )

    matches = _grep(pattern, search_path, fixed=True)
    absent = len(matches) == 0

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED" if absent else "REFUTED",
        method_confidence=0.60,
        evidence=f"grep_absent: {'no matches' if absent else f'{len(matches)} matches found: {matches[0][:200]}'}",
        method="grep_absent",
    )


def verify_mitigation_exists(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    file_param = claim.parameters.get("file", "")
    line_num = claim.parameters.get("line")

    # The mitigation description is not executable evidence. Only a concrete
    # code pattern can establish presence deterministically.
    pattern = claim.parameters.get("pattern", "")
    if not isinstance(pattern, str) or not pattern.strip():
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="No concrete mitigation pattern supplied", method="grep_mitigation",
        )
    if not file_param:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="No mitigation file specified", method="file_scope",
        )

    resolved = safe_path(file_param, repo_path)
    if resolved is None or not os.path.isfile(resolved):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=(f"Invalid mitigation file path: {file_param}"
                      if resolved is None else f"Mitigation file not found: {file_param}"),
            method="file_scope",
        )

    matches = _grep(pattern.strip(), resolved, fixed=True)
    if line_num is not None:
        if isinstance(line_num, bool) or not isinstance(line_num, int) or line_num < 1:
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence=f"Invalid mitigation line: {line_num}", method="file_scope",
            )
        matches = [m for m in matches if _grep_line_number(m) == line_num]
    if matches:
        return VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.75,
                             evidence=f"Pattern found: {matches[0][:200]}", method="grep_mitigation")

    return VerifiedClaim(
        claim=claim, verdict="REFUTED", method_confidence=0.75,
        evidence=f"Concrete mitigation pattern not found: {pattern}",
        method="grep_mitigation",
    )


def verify_entry_point(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    name = claim.parameters.get("name", "")
    location = claim.parameters.get("location", "")
    ep_type = claim.parameters.get("type", "")
    if not isinstance(ep_type, str):
        ep_type = ""
    ep_type = ep_type.lower()
    if not isinstance(name, str):
        name = ""

    if not name and not location:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="No entry-point name or location specified", method="grep_entry_point",
        )

    search_path, line_num, scope_error = _entry_point_scope(claim, repo_path)
    if scope_error:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=scope_error, method="file_scope",
        )
    target_name = name
    if not target_name and not is_file_location(location):
        target_name = location

    http_patterns = [r"Handle\w*Func", r"\.GET\(", r"\.POST\(", r"\.PUT\(", r"\.DELETE\(",
                     r"@app\.route", r"@router\.", r"\.HandleFunc\(", r"http\.Handle"]
    grpc_patterns = [r"Register\w*Server", r"pb\.\w+Server"]
    cli_patterns = [r"cobra\.Command", r"argparse\.", r"click\.command", r"flag\."]

    if ep_type in ("http", "rest", "api"):
        patterns = http_patterns
    elif ep_type in ("grpc", "rpc"):
        patterns = grpc_patterns
    elif ep_type in ("cli", "command"):
        patterns = cli_patterns
    else:
        patterns = http_patterns + grpc_patterns + cli_patterns

    for pattern in patterns:
        matches = _grep(pattern, search_path or repo_path)
        if target_name:
            matches = [m for m in matches if target_name in m]
        if line_num is not None:
            matches = [m for m in matches if _grep_line_number(m) == line_num]
        if matches:
            return VerifiedClaim(
                claim=claim, verdict="VERIFIED", method_confidence=0.65,
                evidence=f"Entry point pattern found: {matches[0][:200]}", method="grep_entry_point",
            )

    return VerifiedClaim(
        claim=claim, verdict="REFUTED", method_confidence=0.65,
        evidence=f"No {ep_type or 'any'} entry point patterns found", method="grep_entry_point",
    )
