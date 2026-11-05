"""Reachability claims for CVE triage: presence is not reachability.

VULNERABLE_SYMBOL_CALLED verifies "the vulnerable function <symbol> in
<package> is called from shipped code" as a three-step chain:

1. Is the package present in the build-path lockfiles? Absence refutes
   the claim (nothing ships the vulnerable code), following the
   lockfile verification semantics.
2. Is the package imported by the source code?
3. Does the specific symbol appear in any call site (excluding its own
   definition)?

The reachability_detail field carries the distinction the verdict enum
does not: "symbol_called" (invoked), "package_imported" (present and
imported but never invoked — presence, not reachability), and
"no_call_sites" (zero call sites for the symbol). An agent claiming
NOT_REACHABLE gets a mechanical check instead of a prompt rule.
"""
from __future__ import annotations

import re

from code_claim_verifier.grep import grep as _grep
from code_claim_verifier.language import get_function_pattern, get_import_patterns
from code_claim_verifier.lockfiles import build_path_filter, find_lockfiles, parse_lockfile
from code_claim_verifier.security import is_concrete_symbol_name
from code_claim_verifier.types import TypedClaim, VerifiedClaim


def _package_in_build_path_lockfiles(repo_path: str, package: str) -> tuple[bool, list[str]]:
    """Whether the package resolves in a build-path lockfile, and which."""
    lockfiles = find_lockfiles(repo_path)
    if not lockfiles:
        return False, []
    build_scope = build_path_filter(repo_path, lockfiles)
    consulted: list[str] = []
    for lf in lockfiles:
        if build_scope is not None and lf.rel not in build_scope:
            continue
        consulted.append(lf.rel)
        versions = parse_lockfile(lf)
        if lf.ecosystem == "python":
            if package.lower() in {name.lower() for name in versions}:
                return True, [lf.rel]
        elif package in versions:
            return True, [lf.rel]
    return False, consulted


def verify_vulnerable_symbol_called(
    claim: TypedClaim, repo_path: str, language: str,
) -> VerifiedClaim:
    symbol = (claim.parameters.get("function")
              or claim.parameters.get("symbol")
              or claim.parameters.get("name")
              or "")
    package = (claim.parameters.get("package")
               or claim.parameters.get("module")
               or "")
    expected = claim.parameters.get("expected", True)

    if not isinstance(expected, bool):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Invalid expected polarity: {expected!r}",
            method="reachability_trace",
        )
    if not symbol or not package:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="VULNERABLE_SYMBOL_CALLED requires a function symbol and "
                     "a package name",
            method="reachability_trace",
        )
    if not is_concrete_symbol_name(symbol):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Invalid or descriptive function name: {symbol!r}",
            method="reachability_trace",
        )

    # Step 1: package presence in the shipped build path. Absent
    # lockfiles are inconclusive (missing files never prove absence),
    # not a refutation.
    present, consulted = _package_in_build_path_lockfiles(repo_path, package)
    lockfile_note = (
        f"package {package} in build-path lockfile(s) {', '.join(consulted)}"
        if present
        else (f"package {package} not found in build-path lockfiles "
              f"({', '.join(consulted) or 'none found'})"
              if consulted else "no lockfiles found; lockfile presence "
                                "inconclusive")
    )
    if consulted and not present:
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.85,
            evidence=f"{lockfile_note}; the vulnerable code does not ship, "
                     "so the symbol cannot be called from shipped code",
            method="reachability_trace",
        )

    # Step 2: imports of the package.
    imports_found = False
    import_evidence = ""
    for pattern in get_import_patterns(package, language):
        matches = _grep(pattern, repo_path)
        if matches:
            imports_found = True
            import_evidence = matches[0][:200]
            break

    # Step 3: call sites for the specific symbol, excluding definitions.
    call_pattern = re.escape(symbol) + r"\s*\("
    matches = _grep(call_pattern, repo_path)
    def_pattern = get_function_pattern(symbol, language)
    def_matches = set(_grep(def_pattern, repo_path))
    call_only = [m for m in matches if m not in def_matches]
    called = len(call_only) > 0

    detail = None
    if called:
        detail = "symbol_called"
    elif imports_found:
        detail = "package_imported"
    else:
        detail = "no_call_sites"

    match = called == expected
    if detail == "package_imported":
        explanation = (f"package {package} is imported ({import_evidence}) but "
                       f"the symbol {symbol} has no call sites: presence, not "
                       f"reachability")
    elif detail == "no_call_sites":
        explanation = (f"no imports of {package} and no call sites for "
                       f"{symbol} found in the source")
    else:
        explanation = f"call site for {symbol}: {call_only[0][:200]}"

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED" if match else "REFUTED",
        method_confidence=0.75,
        evidence=f"{lockfile_note}; {explanation}",
        method="reachability_trace",
        reachability_detail=detail,
    )
