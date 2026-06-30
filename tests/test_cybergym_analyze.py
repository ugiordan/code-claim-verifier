from __future__ import annotations
from eval.cybergym.analyze import compute_rq1, compute_rq2, compute_rq4


class TestRQ1:
    def test_hallucination_rate(self):
        results = [
            {"model": "claude", "ccv": {"total_claims": 5, "verified": 4, "refuted": 1, "verification_rate": 0.80}},
            {"model": "claude", "ccv": {"total_claims": 3, "verified": 1, "refuted": 2, "verification_rate": 0.33}},
        ]
        rq1 = compute_rq1(results)
        assert "claude" in rq1
        assert rq1["claude"]["total_claims"] == 8
        assert rq1["claude"]["total_refuted"] == 3


class TestRQ2:
    def test_accuracy_against_gt(self):
        results = [
            {"gt_comparison": {"results": [
                {"expected": "VERIFIED", "actual": "VERIFIED", "claim_type": "FILE_EXISTS"},
                {"expected": "REFUTED", "actual": "REFUTED", "claim_type": "FILE_EXISTS"},
                {"expected": "REFUTED", "actual": "VERIFIED", "claim_type": "FUNCTION_EXISTS"},
            ]}},
        ]
        rq2 = compute_rq2(results)
        assert rq2["ccv_accuracy"] == round(2 / 3, 4)
        assert rq2["ccv_false_verified"] == 1


class TestRQ4:
    def test_per_type_breakdown(self):
        results = [
            {"gt_comparison": {"results": [
                {"expected": "VERIFIED", "actual": "VERIFIED", "claim_type": "FILE_EXISTS", "confidence": 0.99},
                {"expected": "REFUTED", "actual": "REFUTED", "claim_type": "FUNCTION_EXISTS", "confidence": 0.85},
            ]}},
        ]
        rq4 = compute_rq4(results)
        assert "FILE_EXISTS" in rq4
        assert rq4["FILE_EXISTS"]["accuracy"] == 1.0
