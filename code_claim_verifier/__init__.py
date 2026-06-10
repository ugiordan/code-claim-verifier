from code_claim_verifier.types import TypedClaim, VerifiedClaim, VerificationReport, CLAIM_TYPES
from code_claim_verifier.extractor import extract_claims, LLMFunction
from code_claim_verifier.calibrator import calibrate
from code_claim_verifier.verifiers import safe_verify
from code_claim_verifier.language import detect_language


class CodeClaimVerifier:
    """Extract typed code claims from LLM reasoning and verify deterministically."""

    def __init__(
        self,
        llm_function: LLMFunction,
        repo_path: str,
    ):
        self.llm_function = llm_function
        self.repo_path = repo_path

    def verify(
        self,
        reasoning: str,
        evidence: dict | None = None,
        finding_file: str = "",
    ) -> VerificationReport:
        language = detect_language(finding_file) if finding_file else "unknown"

        claims = extract_claims(reasoning, evidence or {}, self.llm_function)
        if not claims:
            return calibrate([])

        verified = [safe_verify(c, self.repo_path, language) for c in claims]
        return calibrate(verified)


__all__ = [
    "CodeClaimVerifier",
    "TypedClaim", "VerifiedClaim", "VerificationReport",
    "CLAIM_TYPES", "extract_claims", "calibrate",
]
