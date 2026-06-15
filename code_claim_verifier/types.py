from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

CLAIM_TYPES = frozenset({
    "FILE_EXISTS", "LINE_CONTENT", "FILE_CLASSIFICATION", "GENERATED_OR_VENDORED",
    "FUNCTION_EXISTS", "FUNCTION_CALLED", "HAS_CALLERS",
    "IMPORT_EXISTS", "PACKAGE_VERSION", "DEPENDENCY_TYPE", "CVE_AFFECTS_VERSION",
    "ABSENCE", "MITIGATION_EXISTS", "ENTRY_POINT",
})

Verdict = Literal["VERIFIED", "REFUTED", "UNVERIFIABLE"]
Action = Literal["BOOST", "FLAG", "OVERRIDE", "NO_CHANGE"]


@dataclass
class TypedClaim:
    claim_type: str
    parameters: dict[str, Any]
    source_sentence: str
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    extraction_confidence: float = 1.0


@dataclass
class VerifiedClaim:
    claim: TypedClaim
    verdict: Verdict
    method_confidence: float
    evidence: str
    method: str
    error: str | None = None
    suspect_reason: str | None = None
    synthesized: bool = False


@dataclass
class VerificationReport:
    total_claims: int
    verifiable_claims: int
    verified: int
    refuted: int
    unverifiable: int
    errored: int
    verification_rate: float
    hallucination_rate: float
    calibrated_confidence: float
    action: Action
    reason: str
    per_claim: list[VerifiedClaim] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_claims": self.total_claims,
            "verifiable_claims": self.verifiable_claims,
            "verified": self.verified,
            "refuted": self.refuted,
            "unverifiable": self.unverifiable,
            "errored": self.errored,
            "verification_rate": self.verification_rate,
            "hallucination_rate": self.hallucination_rate,
            "calibrated_confidence": self.calibrated_confidence,
            "action": self.action,
            "reason": self.reason,
            "claims": [
                {
                    "type": vc.claim.claim_type,
                    "params": vc.claim.parameters,
                    "source": vc.claim.source_sentence,
                    "verdict": vc.verdict,
                    "confidence": vc.method_confidence,
                    "evidence": vc.evidence[:500],
                    "method": vc.method,
                    "suspect_reason": vc.suspect_reason,
                    "synthesized": vc.synthesized,
                }
                for vc in self.per_claim
            ],
        }
