from __future__ import annotations

import os
import re

from code_claim_verifier.grep import grep as _grep
from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.language import get_function_pattern, detect_language
from code_claim_verifier.security import safe_path


def _strip_qualifier(name: str) -> str:
    """Strip type/module qualifier from a method name.

    finder.Find -> Find, Args::parse -> parse, Foo.Bar.baz -> baz
    """
    for sep in ("::", "."):
        if sep in name:
            return name.rsplit(sep, 1)[-1]
    return name


def verify_function_exists(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    name = claim.parameters.get("name", "")
    if not name:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence="No function name specified", method="grep_function_def")
    file_param = claim.parameters.get("file", "")

    if file_param:
        lang = detect_language(file_param)
        resolved = safe_path(file_param, repo_path)
        search_path = resolved if resolved and os.path.isfile(resolved) else repo_path
    else:
        lang = language
        search_path = repo_path

    bare_name = _strip_qualifier(name)
    pattern = get_function_pattern(bare_name, lang)
    matches = _grep(pattern, search_path)
    found = len(matches) > 0

    if not found and bare_name != name:
        pattern = get_function_pattern(name, lang)
        matches = _grep(pattern, search_path)
        found = len(matches) > 0

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED" if found else "REFUTED",
        method_confidence=0.85,
        evidence=matches[0][:200] if matches else f"No definition found for {name}",
        method="grep_function_def",
    )


def verify_function_called(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    name = (claim.parameters.get("name", "")
            or claim.parameters.get("callee", "")
            or claim.parameters.get("function", ""))
    if not name:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence="No function name specified", method="grep_call")
    expected = claim.parameters.get("expected", True)

    call_pattern = re.escape(name) + r"\s*\("
    matches = _grep(call_pattern, repo_path)

    def_pattern = get_function_pattern(name, language)
    def_matches = set(_grep(def_pattern, repo_path))
    call_only = [m for m in matches if m not in def_matches]

    found = len(call_only) > 0
    match = found == expected

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED" if match else "REFUTED",
        method_confidence=0.65,
        evidence=f"{'Found' if found else 'No'} call sites ({len(call_only)} matches). "
                 + (call_only[0][:200] if call_only else ""),
        method="grep_call_site",
    )


def verify_has_callers(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    name = claim.parameters.get("name", "")
    if not name:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence="No function name specified", method="grep_callers")
    expected = claim.parameters.get("expected", True)

    call_pattern = re.escape(name) + r"\s*\("
    matches = _grep(call_pattern, repo_path)

    def_pattern = get_function_pattern(name, language)
    def_matches = set(_grep(def_pattern, repo_path))
    call_only = [m for m in matches if m not in def_matches]

    has = len(call_only) > 0
    match = has == expected

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED" if match else "REFUTED",
        method_confidence=0.65,
        evidence=f"callers={'yes' if has else 'no'} ({len(call_only)} call sites)",
        method="grep_callers",
    )
