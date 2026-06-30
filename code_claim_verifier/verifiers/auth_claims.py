"""Verifiers for authentication and authorization chain claims."""
from __future__ import annotations

import os
import re

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.security import safe_path
from code_claim_verifier.grep import grep as _grep


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

    broken_at = None
    evidence_parts = []

    for i in range(len(chain) - 1):
        src, dst = chain[i], chain[i + 1]
        src_files = _grep(re.escape(src), repo_path)
        if not src_files:
            broken_at = f"{src} not found in repo"
            break

        call_pattern = re.escape(dst) + r"\s*\("
        src_def_files = _grep(r"func\s+" + re.escape(src), repo_path)
        src_file_paths = set()
        for match in src_def_files:
            parts = match.split(":", 1)
            if parts:
                src_file_paths.add(parts[0])

        found_call = False
        for src_file in src_file_paths:
            resolved = safe_path(src_file, repo_path)
            if resolved and os.path.isfile(resolved):
                file_matches = _grep(call_pattern, resolved)
                if file_matches:
                    evidence_parts.append(f"{src}->{dst}: {file_matches[0][:100]}")
                    found_call = True
                    break

        if not found_call:
            all_matches = _grep(call_pattern, repo_path)
            if all_matches:
                evidence_parts.append(f"{src}->{dst}: found {dst}() call but not in {src}'s body")
                found_call = True

        if not found_call:
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
    claimed_behavior = claim.parameters.get("default_behavior", "").lower()

    if not variable:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="No variable specified", method="default_value",
        )

    search_path = repo_path
    if file_param:
        resolved = safe_path(file_param, repo_path)
        if resolved and os.path.isfile(resolved):
            search_path = resolved

    len_patterns = [
        f"len({variable}) == 0",
        f"len({variable}) < 1",
        f"{variable} == nil",
        f"{variable} != nil",
    ]

    found_checks = []
    for pat in len_patterns:
        matches = _grep(pat, search_path, fixed=True)
        if matches:
            found_checks.extend(matches[:2])

    var_matches = _grep(re.escape(variable), search_path)

    if not var_matches:
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.80,
            evidence=f"Variable '{variable}' not found in searched scope",
            method="default_value",
        )

    allow_patterns = _grep(f"return true", search_path, fixed=True) if found_checks else []

    evidence = f"Variable '{variable}' found in {len(var_matches)} locations."
    if found_checks:
        evidence += f" Length/nil checks: {found_checks[0][:150]}"

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED" if var_matches else "REFUTED",
        method_confidence=0.55,
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
    scope = claim.parameters.get("scope", "all")

    if not flag:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="No flag specified", method="config_flag",
        )

    matches = _grep(flag, repo_path, fixed=True)

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
