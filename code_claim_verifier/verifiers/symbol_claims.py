import os
import re
import subprocess

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.language import get_function_pattern, detect_language
from code_claim_verifier.security import safe_path


def _grep(pattern: str, path: str, fixed: bool = False) -> list[str]:
    """Run grep and return matching lines. Returns empty list on no match."""
    cmd = ["grep", "-rn"]
    if fixed:
        cmd.append("-F")
    else:
        cmd.extend(["-E"])
    cmd.extend([pattern, path])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout.strip().split("\n")
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def verify_function_exists(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    name = claim.parameters.get("name", "")
    file_param = claim.parameters.get("file", "")

    if file_param:
        lang = detect_language(file_param)
        resolved = safe_path(file_param, repo_path)
        search_path = resolved if resolved and os.path.isfile(resolved) else repo_path
    else:
        lang = language
        search_path = repo_path

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
    name = claim.parameters.get("name", "")
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
