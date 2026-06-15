from __future__ import annotations

import json
from pathlib import Path


def generate_report(
    extraction: dict,
    verification: dict,
    calibration: dict,
) -> dict:
    """Generate a combined evaluation report from all three stages.

    Args:
        extraction: Metrics from compute_extraction_metrics
        verification: Metrics from compute_verification_metrics
        calibration: Metrics from compute_calibration_metrics

    Returns:
        Combined report dict with all stages and a summary.
    """
    # Compute an overall score as the average of extraction F1,
    # verification accuracy, and (1 - ECE)
    extraction_f1 = extraction.get("f1", 0.0)
    verification_acc = verification.get("accuracy", 0.0)
    calibration_ece = calibration.get("ece", 0.0)
    calibration_score = 1.0 - calibration_ece

    components = [extraction_f1, verification_acc, calibration_score]
    overall = sum(components) / len(components) if components else 0.0

    return {
        "extraction": extraction,
        "verification": verification,
        "calibration": calibration,
        "summary": {
            "extraction_f1": round(extraction_f1, 4),
            "verification_accuracy": round(verification_acc, 4),
            "calibration_ece": round(calibration_ece, 4),
            "overall_score": round(overall, 4),
        },
    }


def write_report(report: dict, path: str | Path) -> None:
    """Write a report dict to a JSON file.

    Creates parent directories if they don't exist.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
