import os

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.security import safe_path
from code_claim_verifier.verifiers.symbol_claims import _grep


def verify_absence(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    pattern = claim.parameters.get("pattern", "")
    scope = claim.parameters.get("scope", "repo")

    if scope == "file":
        file_path = claim.parameters.get("file", "")
        resolved = safe_path(file_path, repo_path)
        search_path = resolved if resolved and os.path.isfile(resolved) else repo_path
    elif scope == "directory":
        dir_path = claim.parameters.get("directory", "")
        resolved = safe_path(dir_path, repo_path)
        search_path = resolved if resolved and os.path.isdir(resolved) else repo_path
    else:
        search_path = repo_path

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
    line_num = claim.parameters.get("line", 0)

    resolved = safe_path(file_param, repo_path)
    if resolved is None or not os.path.isfile(resolved):
        return VerifiedClaim(claim=claim, verdict="REFUTED", method_confidence=0.70,
                             evidence=f"File not found: {file_param}", method="file_read")
    try:
        with open(resolved, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if line_num < 1 or line_num > len(lines):
            return VerifiedClaim(claim=claim, verdict="REFUTED", method_confidence=0.70,
                                 evidence=f"Line {line_num} out of range", method="file_read")
        actual = lines[line_num - 1].strip()
        if actual and len(actual) > 5:
            return VerifiedClaim(
                claim=claim, verdict="VERIFIED", method_confidence=0.70,
                evidence=f"Line {line_num}: {actual[:200]}", method="file_read",
            )
        return VerifiedClaim(claim=claim, verdict="REFUTED", method_confidence=0.70,
                             evidence=f"Line {line_num} is empty or trivial", method="file_read")
    except Exception as e:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence="", method="file_read", error=str(e)[:200])


def verify_entry_point(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    location = claim.parameters.get("location", "")
    ep_type = claim.parameters.get("type", "").lower()

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
        matches = _grep(pattern, repo_path)
        if matches:
            return VerifiedClaim(
                claim=claim, verdict="VERIFIED", method_confidence=0.65,
                evidence=f"Entry point pattern found: {matches[0][:200]}", method="grep_entry_point",
            )

    return VerifiedClaim(
        claim=claim, verdict="REFUTED", method_confidence=0.65,
        evidence=f"No {ep_type or 'any'} entry point patterns found", method="grep_entry_point",
    )
