from __future__ import annotations

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.calibrator import calibrate


def _claim(ctype="FILE_EXISTS", params=None):
    return TypedClaim(claim_type=ctype, parameters=params or {"path": "a.py"}, source_sentence="test")


def _vc(verdict="VERIFIED", confidence=0.85, suspect_reason=None, synthesized=False):
    return VerifiedClaim(
        claim=_claim(), verdict=verdict, method_confidence=confidence,
        evidence="test", method="test", suspect_reason=suspect_reason,
        synthesized=synthesized,
    )


class TestSynthesizedExclusion:
    def test_synthesized_excluded_from_counts(self):
        claims = [_vc("VERIFIED", 0.99), _vc("VERIFIED", 0.99, synthesized=True)]
        report = calibrate(claims)
        assert report.total_claims == 1
        assert report.verified == 1
        assert report.verifiable_claims == 1

    def test_synthesized_still_in_per_claim(self):
        claims = [_vc("VERIFIED", 0.99), _vc("VERIFIED", 0.99, synthesized=True)]
        report = calibrate(claims)
        assert len(report.per_claim) == 2

    def test_all_synthesized_returns_no_change(self):
        claims = [_vc("VERIFIED", 0.99, synthesized=True)]
        report = calibrate(claims)
        assert report.action == "NO_CHANGE"
        assert report.total_claims == 0


class TestSuspectWeighting:
    def test_suspect_verified_lowers_rate(self):
        normal = _vc("VERIFIED", 0.85)
        suspect = _vc("VERIFIED", 0.85, suspect_reason="dep failed")
        report_normal = calibrate([normal, _vc("VERIFIED", 0.85)])
        report_suspect = calibrate([normal, suspect])
        assert report_suspect.verification_rate < report_normal.verification_rate

    def test_suspect_verified_asymmetric(self):
        suspect = _vc("VERIFIED", 0.80, suspect_reason="dep REFUTED")
        report = calibrate([suspect])
        assert report.verification_rate == 0.5

    def test_suspect_refuted_no_special_treatment(self):
        refuted = _vc("REFUTED", 0.85)
        suspect_refuted = _vc("REFUTED", 0.85, suspect_reason="dep failed")
        r1 = calibrate([_vc("VERIFIED", 0.85), refuted])
        r2 = calibrate([_vc("VERIFIED", 0.85), suspect_refuted])
        assert r1.verification_rate == r2.verification_rate


class TestActionThresholds:
    def test_boost_above_80(self):
        claims = [_vc("VERIFIED", 0.90)] * 5
        assert calibrate(claims).action == "BOOST"

    def test_flag_between_50_80(self):
        claims = [_vc("VERIFIED", 0.85), _vc("REFUTED", 0.85)]
        assert calibrate(claims).action == "FLAG"

    def test_override_below_50(self):
        claims = [_vc("REFUTED", 0.85)] * 3
        assert calibrate(claims).action == "OVERRIDE"
