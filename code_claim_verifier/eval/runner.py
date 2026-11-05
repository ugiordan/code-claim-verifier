from __future__ import annotations

import json
import os

from code_claim_verifier.types import TypedClaim
from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.language import detect_language
from code_claim_verifier.extractor import extract_claims, LLMFunction
from code_claim_verifier.eval.extraction_eval import claims_match, compute_extraction_metrics
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
    llm_function: LLMFunction | None = None,
    domain_context: str = "",
) -> dict:
    """Run the full evaluation pipeline.

    Stages:
    1. Extraction: if mock_extraction is True, use ground truth claims
       directly (skipping the LLM extraction step). Otherwise, use the
       supplied LLM function.
    2. Verification: run each ground truth claim through the verification
       engine against its fixture repo.
    3. Calibration: compute calibration metrics from verification results.

    Args:
        dataset_path: Path to the JSONL dataset file.
        fixtures_path: Path to the directory containing fixture repos.
        mock_extraction: If True, skip LLM extraction and use ground truth.
        llm_function: Required when mock_extraction is False.

    Returns:
        Combined evaluation report dict.
    """
    entries = _load_dataset(dataset_path)
    if not mock_extraction and llm_function is None:
        raise ValueError(
            "llm_function is required when mock_extraction is False"
        )
    engine = VerificationEngine()

    all_extraction_gt: list[dict] = []
    all_extraction_pred: list[TypedClaim] = []
    verification_results: list[dict] = []
    unmatched_predictions = 0
    unmatched_ground_truth = 0

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
            predicted_claims = extract_claims(
                entry.get("reasoning", ""),
                entry.get("evidence", {}),
                llm_function,
                domain_context=domain_context,
            )
            all_extraction_gt.extend(ground_truth_claims)
            all_extraction_pred.extend(predicted_claims)

        if predicted_claims:
            verified = engine.verify_claims(predicted_claims, repo_path, language)
            used_gt: set[int] = set()
            for vc in verified:
                gt_match = None
                for index, gt in enumerate(ground_truth_claims):
                    if index in used_gt or "expected_verdict" not in gt:
                        continue
                    if claims_match(gt, vc.claim):
                        used_gt.add(index)
                        gt_match = gt
                        break
                if gt_match is None:
                    continue
                verification_results.append({
                    "expected_verdict": gt_match["expected_verdict"],
                    "actual_verdict": vc.verdict,
                    "claim_type": vc.claim.claim_type,
                    "confidence": vc.method_confidence,
                    "entry_id": entry.get("id", ""),
                })
            unmatched_predictions += len(predicted_claims) - len(used_gt)
            unmatched_ground_truth += sum(
                1 for index, gt in enumerate(ground_truth_claims)
                if index not in used_gt and "expected_verdict" in gt
            )
        else:
            unmatched_ground_truth += sum(
                1 for gt in ground_truth_claims if "expected_verdict" in gt
            )

    # Compute metrics for each stage
    extraction_metrics = compute_extraction_metrics(
        all_extraction_gt, all_extraction_pred
    )
    verification_metrics = compute_verification_metrics(verification_results)
    calibration_metrics = compute_calibration_metrics(verification_results)
    verification_metrics.update({
        "matched_claims": len(verification_results),
        "unmatched_predictions": unmatched_predictions,
        "unmatched_ground_truth": unmatched_ground_truth,
        "conditional_on_claim_match": True,
    })
    calibration_metrics["matched_claims"] = len(verification_results)

    return generate_report(extraction_metrics, verification_metrics, calibration_metrics)
