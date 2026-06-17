from __future__ import annotations

import json
import os
from pathlib import Path

from code_claim_verifier.types import TypedClaim
from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.language import detect_language
from code_claim_verifier.eval.extraction_eval import compute_extraction_metrics
from code_claim_verifier.eval.verification_eval import compute_verification_metrics
from code_claim_verifier.eval.calibration_eval import compute_calibration_metrics
from code_claim_verifier.eval.report import generate_report


def _load_dataset(dataset_path: str) -> list[dict]:
    """Load a JSONL dataset file, one JSON object per line."""
    entries = []
    with open(dataset_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Invalid JSON on line {line_num} of {dataset_path}: {e}"
                ) from e
    return entries


def run_evaluation(
    dataset_path: str,
    fixtures_path: str,
    mock_extraction: bool = True,
) -> dict:
    """Run the full evaluation pipeline.

    Stages:
    1. Extraction: if mock_extraction is True, use ground truth claims
       directly (skipping the LLM extraction step) and report perfect
       extraction metrics. Otherwise, would use LLM extraction (not yet
       implemented).
    2. Verification: run each ground truth claim through the verification
       engine against its fixture repo.
    3. Calibration: compute calibration metrics from verification results.

    Args:
        dataset_path: Path to the JSONL dataset file.
        fixtures_path: Path to the directory containing fixture repos.
        mock_extraction: If True, skip LLM extraction and use ground truth.

    Returns:
        Combined evaluation report dict.
    """
    entries = _load_dataset(dataset_path)
    engine = VerificationEngine()

    all_extraction_gt: list[dict] = []
    all_extraction_pred: list[TypedClaim] = []
    verification_results: list[dict] = []

    for entry in entries:
        fixture_repo = entry.get("fixture_repo", "")
        repo_path = os.path.join(fixtures_path, fixture_repo)
        finding_file = entry.get("finding_file", "")
        language = detect_language(finding_file) if finding_file else "unknown"
        ground_truth_claims = entry.get("ground_truth_claims", [])

        if mock_extraction:
            # Use ground truth claims as both GT and predicted (perfect extraction)
            predicted_claims = [
                TypedClaim(
                    claim_type=gt["claim_type"],
                    parameters=gt.get("parameters", {}),
                    source_sentence=entry.get("reasoning", "")[:200],
                )
                for gt in ground_truth_claims
            ]
            all_extraction_gt.extend(ground_truth_claims)
            all_extraction_pred.extend(predicted_claims)
        else:
            # Real extraction would go here (requires LLM function)
            predicted_claims = []
            all_extraction_gt.extend(ground_truth_claims)

        if predicted_claims:
            verified = engine.verify_claims(predicted_claims, repo_path, language)
            if len(ground_truth_claims) != len(verified):
                raise ValueError(
                    f"Entry {entry.get('id', '?')}: ground truth has "
                    f"{len(ground_truth_claims)} claims but verification "
                    f"produced {len(verified)} results"
                )
            for gt, vc in zip(ground_truth_claims, verified):
                if "expected_verdict" not in gt:
                    raise ValueError(
                        f"Entry {entry.get('id', '?')}: ground truth claim "
                        f"missing expected_verdict"
                    )
                verification_results.append({
                    "expected_verdict": gt["expected_verdict"],
                    "actual_verdict": vc.verdict,
                    "claim_type": vc.claim.claim_type,
                    "confidence": vc.method_confidence,
                    "entry_id": entry.get("id", ""),
                })

    # Compute metrics for each stage
    extraction_metrics = compute_extraction_metrics(
        all_extraction_gt, all_extraction_pred
    )
    verification_metrics = compute_verification_metrics(verification_results)
    calibration_metrics = compute_calibration_metrics(verification_results)

    return generate_report(extraction_metrics, verification_metrics, calibration_metrics)
