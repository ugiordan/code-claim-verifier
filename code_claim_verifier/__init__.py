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

    def as_tools(self) -> list[dict]:
        """Return tool definitions including any custom-registered claim types.

        Merges custom types (registered via .register()) into the standard
        tool schemas, so LLM tool-use integrations can discover them.
        """
        from code_claim_verifier.tools import instance_tools
        extra: dict[str, str] = {}
        custom_types = [ct for ct in self.engine.registry if ct not in CLAIM_TYPES]
        for ct, hint in zip(custom_types, self._extraction_hints):
            extra[ct] = hint
        return instance_tools(extra)

    @classmethod
    def default_tools(cls) -> list[dict]:
        """Return tool definitions for all built-in claim types."""
        from code_claim_verifier.tools import default_tools
        return default_tools()

    def verify_batch(self, items: list[dict], domain_context: str = "",
                     max_chars_per_batch: int = 6000,
                     batch_fallback: str = "partial") -> list[VerificationReport]:
        """Verify multiple items with adaptive batching and shared caches.

        Groups items by cumulative reasoning length. Multi-item batches use
        a single LLM call via extract_claims_batch. Single-item batches use
        extract_claims. Verification shares grep and verifier caches across
        all items, but dependency graphs are per-finding.

        Args:
            items: List of dicts with keys: reasoning, evidence, finding_file.
            domain_context: Optional domain instructions for extraction.
            max_chars_per_batch: Max characters of reasoning per extraction batch.
            batch_fallback: "partial"|"skip" for batch extraction failures.
        """
        from code_claim_verifier.extractor import extract_claims_batch
        from code_claim_verifier import grep as grep_module

        if not items:
            return []

        valid_types = frozenset(self.engine.registry.keys())
        hints = self._extraction_hints or None

        batches = self._group_into_batches(items, max_chars_per_batch)
        all_claims: dict[int, list[TypedClaim]] = {}

        for batch_items, batch_offset in batches:
            if len(batch_items) == 1:
                reasoning = batch_items[0].get("reasoning", "")
                evidence = batch_items[0].get("evidence", {})
                claims = extract_claims(
                    reasoning, evidence, self.llm_function,
                    domain_context=domain_context,
                    custom_hints=hints,
                    valid_types=valid_types,
                )
                all_claims[batch_offset] = claims
            else:
                batch_result = extract_claims_batch(
                    batch_items, self.llm_function,
                    domain_context=domain_context,
                    custom_hints=hints,
                    valid_types=valid_types,
                    fallback=batch_fallback,
                )
                for local_idx, claims in batch_result.items():
                    all_claims[batch_offset + local_idx] = claims

        reports = []
        token = None
        try:
            token = grep_module.cache_context()
            for i, item in enumerate(items):
                finding_file = item.get("finding_file", "")
                language = detect_language(finding_file) if finding_file else "unknown"
                claims = all_claims.get(i, [])
                if not claims:
                    reports.append(calibrate([]))
                    continue
                verified = self.engine.verify_claims_with_chaining(
                    claims, self.repo_path, language,
                )
                reports.append(calibrate(verified))
        finally:
            if token is not None:
                grep_module.reset_cache(token)

        return reports

    @staticmethod
    def _group_into_batches(items: list[dict], max_chars: int) -> list[tuple[list[dict], int]]:
        batches: list[tuple[list[dict], int]] = []
        current_batch: list[dict] = []
        current_len = 0
        batch_start = 0

        for i, item in enumerate(items):
            reasoning_len = len(item.get("reasoning", ""))
            if reasoning_len >= max_chars:
                if current_batch:
                    batches.append((current_batch, batch_start))
                batches.append(([item], i))
                current_batch = []
                current_len = 0
                batch_start = i + 1
            elif current_len + reasoning_len > max_chars:
                if current_batch:
                    batches.append((current_batch, batch_start))
                current_batch = [item]
                current_len = reasoning_len
                batch_start = i
            else:
                current_batch.append(item)
                current_len += reasoning_len

        if current_batch:
            batches.append((current_batch, batch_start))

        return batches


__all__ = [
    "CodeClaimVerifier",
    "TypedClaim", "VerifiedClaim", "VerificationReport",
    "CLAIM_TYPES", "extract_claims", "calibrate",
]
