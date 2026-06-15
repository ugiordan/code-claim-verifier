from __future__ import annotations

from code_claim_verifier.types import TypedClaim, VerifiedClaim, VerificationReport

class TestVerifiedClaimFields:
    def test_defaults(self):
        claim = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="test")
        vc = VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="os.path.isfile")
        assert vc.suspect_reason is None
        assert vc.synthesized is False

    def test_suspect_reason(self):
        claim = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="test")
        vc = VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="test", suspect_reason="FILE_EXISTS was REFUTED")
        assert vc.suspect_reason == "FILE_EXISTS was REFUTED"

    def test_synthesized(self):
        claim = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="")
        vc = VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="test", synthesized=True)
        assert vc.synthesized is True

class TestToDictIncludesNewFields:
    def test_suspect_reason_in_dict(self):
        claim = TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "a.py"}, source_sentence="test")
        vc = VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="test", suspect_reason="dep failed")
        report = VerificationReport(
            total_claims=1, verifiable_claims=1, verified=1, refuted=0,
            unverifiable=0, errored=0, verification_rate=1.0, hallucination_rate=0.0,
            calibrated_confidence=1.0, action="BOOST", reason="1/1", per_claim=[vc],
        )
        d = report.to_dict()
        assert d["claims"][0]["suspect_reason"] == "dep failed"
        assert d["claims"][0]["synthesized"] is False
