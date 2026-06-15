"""Tests for the evaluation framework."""
from __future__ import annotations

import pytest

from code_claim_verifier.types import TypedClaim
from code_claim_verifier.eval.extraction_eval import claims_match, compute_extraction_metrics
from code_claim_verifier.eval.verification_eval import compute_verification_metrics
from code_claim_verifier.eval.calibration_eval import compute_calibration_metrics


# ------------------------------------------------------------------
# TestClaimMatching
# ------------------------------------------------------------------

class TestClaimMatching:
    def test_exact_match(self):
        gt = {"claim_type": "FILE_EXISTS", "parameters": {"path": "main.py"}}
        pred = TypedClaim(
            claim_type="FILE_EXISTS",
            parameters={"path": "main.py"},
            source_sentence="main.py exists",
        )
        assert claims_match(gt, pred) is True

    def test_extra_params_ok(self):
        """Predicted claim has extra parameters beyond ground truth. Should still match."""
        gt = {"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "foo"}}
        pred = TypedClaim(
            claim_type="FUNCTION_EXISTS",
            parameters={"name": "foo", "file": "bar.py"},
            source_sentence="foo exists",
        )
        assert claims_match(gt, pred) is True

    def test_missing_param_no_match(self):
        """Predicted claim is missing a ground truth parameter. Should not match."""
        gt = {"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "foo", "file": "bar.py"}}
        pred = TypedClaim(
            claim_type="FUNCTION_EXISTS",
            parameters={"name": "foo"},
            source_sentence="foo exists",
        )
        assert claims_match(gt, pred) is False

    def test_wrong_type_no_match(self):
        gt = {"claim_type": "FILE_EXISTS", "parameters": {"path": "main.py"}}
        pred = TypedClaim(
            claim_type="FUNCTION_EXISTS",
            parameters={"path": "main.py"},
            source_sentence="main.py exists",
        )
        assert claims_match(gt, pred) is False


# ------------------------------------------------------------------
# TestExtractionMetrics
# ------------------------------------------------------------------

class TestExtractionMetrics:
    def test_perfect_extraction(self):
        gt = [
            {"claim_type": "FILE_EXISTS", "parameters": {"path": "main.py"}},
            {"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "foo"}},
        ]
        pred = [
            TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.py"}, source_sentence=""),
            TypedClaim(claim_type="FUNCTION_EXISTS", parameters={"name": "foo"}, source_sentence=""),
        ]
        metrics = compute_extraction_metrics(gt, pred)
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["f1"] == 1.0
        assert metrics["matched"] == 2

    def test_no_predictions(self):
        gt = [
            {"claim_type": "FILE_EXISTS", "parameters": {"path": "main.py"}},
        ]
        pred: list[TypedClaim] = []
        metrics = compute_extraction_metrics(gt, pred)
        assert metrics["precision"] == 0.0
        assert metrics["recall"] == 0.0
        assert metrics["f1"] == 0.0
        assert metrics["matched"] == 0


# ------------------------------------------------------------------
# TestVerificationMetrics
# ------------------------------------------------------------------

class TestVerificationMetrics:
    def test_perfect_accuracy(self):
        results = [
            {"expected_verdict": "VERIFIED", "actual_verdict": "VERIFIED", "claim_type": "FILE_EXISTS"},
            {"expected_verdict": "REFUTED", "actual_verdict": "REFUTED", "claim_type": "FILE_EXISTS"},
        ]
        metrics = compute_verification_metrics(results)
        assert metrics["accuracy"] == 1.0
        assert metrics["false_refuted_rate"] == 0.0
        assert metrics["false_verified_rate"] == 0.0

    def test_false_refuted(self):
        results = [
            {"expected_verdict": "VERIFIED", "actual_verdict": "REFUTED", "claim_type": "FILE_EXISTS"},
            {"expected_verdict": "VERIFIED", "actual_verdict": "VERIFIED", "claim_type": "FILE_EXISTS"},
        ]
        metrics = compute_verification_metrics(results)
        assert metrics["accuracy"] == 0.5
        assert metrics["false_refuted_rate"] == 0.5
        assert metrics["false_verified_rate"] == 0.0


# ------------------------------------------------------------------
# TestCalibrationMetrics
# ------------------------------------------------------------------

class TestCalibrationMetrics:
    def test_ece_computation(self):
        """ECE should be 0 when confidence matches accuracy perfectly."""
        results = [
            {
                "expected_verdict": "VERIFIED",
                "actual_verdict": "VERIFIED",
                "claim_type": "FILE_EXISTS",
                "confidence": 1.0,
            },
            {
                "expected_verdict": "VERIFIED",
                "actual_verdict": "VERIFIED",
                "claim_type": "FILE_EXISTS",
                "confidence": 1.0,
            },
        ]
        metrics = compute_calibration_metrics(results)
        # All correct at confidence 1.0, so ECE should be 0
        assert metrics["ece"] == 0.0
        assert metrics["per_type_accuracy"]["FILE_EXISTS"] == 1.0

    def test_ece_nonzero(self):
        """ECE should be nonzero when confidence doesn't match accuracy."""
        results = [
            {
                "expected_verdict": "VERIFIED",
                "actual_verdict": "REFUTED",
                "claim_type": "FILE_EXISTS",
                "confidence": 0.9,
            },
            {
                "expected_verdict": "VERIFIED",
                "actual_verdict": "VERIFIED",
                "claim_type": "FILE_EXISTS",
                "confidence": 0.9,
            },
        ]
        metrics = compute_calibration_metrics(results)
        # Accuracy is 0.5 but avg confidence is 0.9, so ECE > 0
        assert metrics["ece"] > 0

    def test_empty_results(self):
        metrics = compute_calibration_metrics([])
        assert metrics["ece"] == 0.0
        assert metrics["per_type_accuracy"] == {}
