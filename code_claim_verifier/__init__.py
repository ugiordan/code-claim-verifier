from __future__ import annotations

from code_claim_verifier.types import TypedClaim, VerifiedClaim, VerificationReport, CLAIM_TYPES
from code_claim_verifier.extractor import extract_claims, LLMFunction
from code_claim_verifier.calibrator import calibrate
from code_claim_verifier.engine import VerificationEngine, VerifierFunction
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
        self.engine = VerificationEngine()
        self._extraction_hints: list[str] = []

    def register(self, claim_type: str, verifier_fn: VerifierFunction,
                 extraction_hint: str,
                 depends_on: list[tuple[str, str, str]] | None = None):
        """Register a custom claim type with its verifier function.

        Args:
            claim_type: The claim type identifier (must not collide with builtins).
            verifier_fn: Function(claim, repo_path, language) -> VerifiedClaim.
            extraction_hint: Description for the extraction prompt (<= 500 chars).
            depends_on: Optional list of (prereq_type, source_param, target_param).

        Raises:
            ValueError: If the claim type is already registered or hint is too long.
        """
        if len(extraction_hint) > 500:
            raise ValueError("extraction_hint must be <= 500 characters")
        self.engine.register(claim_type, verifier_fn, depends_on=depends_on)
        if extraction_hint:
            self._extraction_hints.append(extraction_hint)

    def register_dependency(self, claim_type: str, depends_on: str,
                            source_param: str, target_param: str):
        """Register a dependency rule between claim types.

        Args:
            claim_type: The dependent claim type.
            depends_on: The prerequisite claim type.
            source_param: Parameter in the dependent claim.
            target_param: Parameter in the prerequisite claim.
        """
        self.engine.register_dependency(claim_type, depends_on, source_param, target_param)

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
        valid_types = frozenset(self.engine.registry.keys())
        claims = extract_claims(
            reasoning, evidence or {}, self.llm_function,
            domain_context=domain_context,
            custom_hints=self._extraction_hints or None,
            valid_types=valid_types,
        )
        if not claims:
            return calibrate([])
        verified = self.engine.verify_claims_with_chaining(claims, self.repo_path, language)
        return calibrate(verified)

    def verify_batch(self, items: list[dict], domain_context: str = "",
                     max_chars_per_batch: int = 6000,
                     batch_fallback: str = "partial") -> list[VerificationReport]:
        """Verify multiple items in a batch.

        Args:
            items: List of dicts with keys: reasoning, evidence, finding_file.
            domain_context: Optional domain instructions for extraction.
            max_chars_per_batch: Max characters per batch (currently unused).
            batch_fallback: Fallback strategy (currently unused).

        Returns:
            List of VerificationReport, one per item.
        """
        reports = []
        valid_types = frozenset(self.engine.registry.keys())
        for item in items:
            reasoning = item.get("reasoning", "")
            evidence = item.get("evidence", {})
            finding_file = item.get("finding_file", "")
            language = detect_language(finding_file) if finding_file else "unknown"
            claims = extract_claims(
                reasoning, evidence, self.llm_function,
                domain_context=domain_context,
                custom_hints=self._extraction_hints or None,
                valid_types=valid_types,
            )
            if not claims:
                reports.append(calibrate([]))
                continue
            verified = self.engine.verify_claims_with_chaining(claims, self.repo_path, language)
            reports.append(calibrate(verified))
        return reports


__all__ = [
    "CodeClaimVerifier",
    "TypedClaim", "VerifiedClaim", "VerificationReport",
    "CLAIM_TYPES", "extract_claims", "calibrate",
]
