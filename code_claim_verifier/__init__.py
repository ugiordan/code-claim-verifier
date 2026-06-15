from __future__ import annotations

from code_claim_verifier.types import TypedClaim, VerifiedClaim, VerificationReport, CLAIM_TYPES
from code_claim_verifier.extractor import extract_claims, LLMFunction
from code_claim_verifier.calibrator import calibrate
from code_claim_verifier.verifiers import safe_verify
from code_claim_verifier.language import detect_language


class CodeClaimVerifier:
    """Extract typed code claims from LLM reasoning and verify deterministically.

    Works with any LLM output that makes assertions about source code:
    security triage, code review, refactoring analysis, migration verification,
    documentation accuracy, architecture assessment, and more.

    The only LLM call is for claim extraction. All verification is deterministic
    (grep, file read, lockfile parse). Grep doesn't hallucinate.
    """

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
        domain_context: str = "",
    ) -> VerificationReport:
        """Verify claims in LLM reasoning against the actual codebase.

        Args:
            reasoning: The LLM's natural language reasoning about code.
            evidence: Optional structured evidence dict.
            finding_file: File path for per-finding language detection.
            domain_context: Optional domain instructions for extraction
                (e.g., "This is a security triage context" or
                "This is a code review for a Go microservice").
        """
        language = detect_language(finding_file) if finding_file else "unknown"

        claims = extract_claims(
            reasoning, evidence or {}, self.llm_function,
            domain_context=domain_context,
        )
        if not claims:
            return calibrate([])

        verified = [safe_verify(c, self.repo_path, language) for c in claims]
        return calibrate(verified)


__all__ = [
    "CodeClaimVerifier",
    "TypedClaim", "VerifiedClaim", "VerificationReport",
    "CLAIM_TYPES", "extract_claims", "calibrate",
]
