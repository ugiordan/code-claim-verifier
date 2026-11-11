from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.verifiers.file_claims import verify_file_exists, verify_line_content, verify_file_classification, verify_generated_or_vendored
from code_claim_verifier.verifiers.symbol_claims import verify_function_exists, verify_function_called, verify_has_callers
from code_claim_verifier.verifiers.import_claims import (
    OsvAssessment as OsvAssessment,
    fetch_osv_assessment as fetch_osv_assessment,
    verify_cve_affects,
    verify_dependency_type,
    verify_import_exists,
    verify_package_absent,
    verify_package_version,
    verify_upgrade_fixes,
    verify_version_in_range,
)
from code_claim_verifier.verifiers.reachability_claims import verify_vulnerable_symbol_called
from code_claim_verifier.verifiers.vex_claims import (
    VexAssessment as VexAssessment,
    fetch_redhat_vex_assessment as fetch_redhat_vex_assessment,
    verify_redhat_vex_status,
)
from code_claim_verifier.verifiers.security_claims import verify_absence, verify_mitigation_exists, verify_entry_point
from code_claim_verifier.verifiers.auth_claims import verify_call_chain, verify_default_value, verify_config_flag

# Controlled vocabulary for VerifiedClaim.verification_source, derived from
# the verifier's method string. Evidence quality follows the source: lockfile
# and CPG/AST evidence outranks grep; API evidence is external and may be
# stale; "source_code" covers direct file reads and grep-based checks.
VERIFICATION_SOURCES = frozenset({
    "source_code", "lockfile", "manifest", "cpg", "cymbal",
    "call_graph", "osv_api", "vex_api", "version_compare", "config",
    "clair_report", "unknown",
})

_METHOD_SOURCE_PREFIXES = (
    ("cpg_", "cpg"),
    ("cymbal_", "cymbal"),
    ("grep_", "source_code"),
    ("os.", "source_code"),
)

_METHOD_SOURCE_EXACT = {
    "lockfile_parse": "lockfile",
    "manifest_parse": "manifest",
    "osv_api": "osv_api",
    "vex_api": "vex_api",
    "reachability_trace": "source_code",
    "version_compare": "version_compare",
    "clair_report": "clair_report",
    "call_chain": "call_graph",
    "file_read": "source_code",
    "file_scope": "source_code",
    "path_check": "source_code",
    "path_regex": "source_code",
    "header_check": "source_code",
    "schema": "source_code",
    "config_flag": "source_code",
    "config_scope": "source_code",
    "default_value": "source_code",
    "cpg_absence": "cpg",
}


def derive_verification_source(method: str) -> str:
    """Map a verifier method string to its evidence source."""
    if method in _METHOD_SOURCE_EXACT:
        return _METHOD_SOURCE_EXACT[method]
    for prefix, source in _METHOD_SOURCE_PREFIXES:
        if method.startswith(prefix):
            return source
    return "unknown"

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
    "PACKAGE_ABSENT": verify_package_absent,
    "VERSION_IN_RANGE": verify_version_in_range,
    "UPGRADE_FIXES": verify_upgrade_fixes,
    "VULNERABLE_SYMBOL_CALLED": verify_vulnerable_symbol_called,
    "REDHAT_VEX_STATUS": verify_redhat_vex_status,
    "DEPENDENCY_TYPE": verify_dependency_type,
    "CVE_AFFECTS_VERSION": verify_cve_affects,
    "ABSENCE": verify_absence,
    "MITIGATION_EXISTS": verify_mitigation_exists,
    "ENTRY_POINT": verify_entry_point,
    "CALL_CHAIN": verify_call_chain,
    "DEFAULT_VALUE": verify_default_value,
    "CONFIG_FLAG": verify_config_flag,
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
        result = verifier(claim, repo_path, language)
    except Exception as e:
        result = VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="", method="error", error=f"{type(e).__name__}: {str(e)[:200]}",
        )
    if result.verification_source is None:
        result.verification_source = derive_verification_source(result.method)
    return result
