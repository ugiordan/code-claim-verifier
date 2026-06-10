from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.verifiers.file_claims import verify_file_exists, verify_line_content, verify_file_classification, verify_generated_or_vendored
from code_claim_verifier.verifiers.symbol_claims import verify_function_exists, verify_function_called, verify_has_callers
from code_claim_verifier.verifiers.import_claims import verify_import_exists, verify_package_version, verify_dependency_type, verify_cve_affects
from code_claim_verifier.verifiers.security_claims import verify_absence, verify_mitigation_exists, verify_entry_point

VERIFIER_REGISTRY: dict[str, callable] = {
    "FILE_EXISTS": verify_file_exists,
    "LINE_CONTENT": verify_line_content,
    "FILE_CLASSIFICATION": verify_file_classification,
    "GENERATED_OR_VENDORED": verify_generated_or_vendored,
    "FUNCTION_EXISTS": verify_function_exists,
    "FUNCTION_CALLED": verify_function_called,
    "HAS_CALLERS": verify_has_callers,
    "IMPORT_EXISTS": verify_import_exists,
    "PACKAGE_VERSION": verify_package_version,
    "DEPENDENCY_TYPE": verify_dependency_type,
    "CVE_AFFECTS_VERSION": verify_cve_affects,
    "ABSENCE": verify_absence,
    "MITIGATION_EXISTS": verify_mitigation_exists,
    "ENTRY_POINT": verify_entry_point,
}


def safe_verify(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    """Dispatch to the right verifier with error handling."""
    verifier = VERIFIER_REGISTRY.get(claim.claim_type)
    if not verifier:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Unknown claim type: {claim.claim_type}", method="error", error="unknown_type",
        )
    try:
        return verifier(claim, repo_path, language)
    except Exception as e:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="", method="error", error=f"{type(e).__name__}: {str(e)[:200]}",
        )
