# Evaluation Framework

CCV includes an evaluation framework for measuring verification accuracy against ground truth datasets. The framework runs three evaluation stages: extraction, verification, and calibration.

## Dataset format

The dataset is a JSONL file (one JSON object per line). Each entry represents a finding with ground truth claims and expected verdicts.

```jsonl
{"id": "001", "fixture_repo": "repo-a", "finding_file": "src/config.py", "reasoning": "The file src/config.py contains a call to yaml.load()", "ground_truth_claims": [{"claim_type": "FILE_EXISTS", "parameters": {"path": "src/config.py"}, "expected_verdict": "VERIFIED"}, {"claim_type": "FUNCTION_CALLED", "parameters": {"name": "yaml.load", "expected": true}, "expected_verdict": "VERIFIED"}]}
{"id": "002", "fixture_repo": "repo-a", "finding_file": "src/auth.py", "reasoning": "The function validate_token does not exist", "ground_truth_claims": [{"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "validate_token"}, "expected_verdict": "REFUTED"}]}
```

### Entry schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | recommended | Unique identifier for the entry |
| `fixture_repo` | string | yes | Directory name under the fixtures path |
| `finding_file` | string | no | File path for language detection |
| `reasoning` | string | no | LLM reasoning text (used for extraction eval) |
| `ground_truth_claims` | array | yes | List of claim objects with expected verdicts |

### Ground truth claim schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `claim_type` | string | yes | One of the 14 built-in claim types |
| `parameters` | object | yes | Claim parameters |
| `expected_verdict` | string | yes | `"VERIFIED"`, `"REFUTED"`, or `"UNVERIFIABLE"` |

## Fixture repo structure

Fixture repos are minimal repositories set up to produce known verification results. Each fixture repo is a directory under the fixtures path.

```
tests/eval/fixtures/
  repo-a/
    src/
      config.py      # contains yaml.load() call
      auth.py         # does NOT define validate_token
    requirements.txt  # pins PyYAML==5.3.1
  repo-b/
    cmd/
      main.go
    go.mod
```

The fixture repos don't need to be real git repositories. They just need to contain the files and content that the ground truth claims reference. The verifiers operate on the filesystem directly.

## Evaluation stages

### 1. Extraction evaluation

Measures how well the LLM extracts claims from reasoning text.

**Mock mode (default):** Ground truth claims are used directly as both the expected and predicted claims. This gives perfect extraction scores (precision=1.0, recall=1.0, F1=1.0) and isolates the verification stage for testing.

**Real mode** (`--no-mock-extraction`): Would use the LLM to extract claims from the reasoning text, then compare against ground truth. Matching criteria: same `claim_type` AND all ground truth parameters exist in the predicted claim with equal values (extra predicted params are OK).

**Metrics:**

| Metric | Description |
|--------|-------------|
| `precision` | matched / predicted_total |
| `recall` | matched / gt_total |
| `f1` | harmonic mean of precision and recall |
| `matched` | number of matched claim pairs |
| `gt_total` | total ground truth claims |
| `pred_total` | total predicted claims |

### 2. Verification evaluation

Measures whether the verifiers produce the correct verdicts for known claims.

Each ground truth claim is run through the `VerificationEngine` against its fixture repo. The actual verdict is compared to the `expected_verdict`.

**Metrics:**

| Metric | Description |
|--------|-------------|
| `accuracy` | correct / total |
| `false_refuted_rate` | expected VERIFIED but got REFUTED |
| `false_verified_rate` | expected REFUTED but got VERIFIED |
| `total` | total claims evaluated |
| `confusion_matrix` | `{expected: {actual: count}}` |
| `per_type` | per-claim-type accuracy breakdown |

### 3. Calibration evaluation

Measures how well the verifiers' confidence scores match their actual accuracy.

**Metrics:**

| Metric | Description |
|--------|-------------|
| `per_type_accuracy` | actual accuracy per claim type |
| `ece` | Expected Calibration Error: weighted average of `\|accuracy - confidence\|` across 10 confidence bins |
| `confidence_adjustments` | suggested confidence per type based on actual accuracy |

A well-calibrated verifier has `ece` close to 0. The `confidence_adjustments` map can be used to tune `method_confidence` values in verifier implementations.

## Report output

The evaluation produces a combined report with all three stages plus a summary:

```json
{
  "extraction": {
    "precision": 1.0,
    "recall": 1.0,
    "f1": 1.0,
    "matched": 15,
    "gt_total": 15,
    "pred_total": 15
  },
  "verification": {
    "accuracy": 0.9333,
    "false_refuted_rate": 0.0667,
    "false_verified_rate": 0.0,
    "total": 15,
    "confusion_matrix": {
      "VERIFIED": {"VERIFIED": 8, "REFUTED": 1},
      "REFUTED": {"REFUTED": 6}
    },
    "per_type": {
      "FILE_EXISTS": {"correct": 5, "total": 5, "accuracy": 1.0},
      "FUNCTION_CALLED": {"correct": 3, "total": 4, "accuracy": 0.75}
    }
  },
  "calibration": {
    "per_type_accuracy": {
      "FILE_EXISTS": 1.0,
      "FUNCTION_CALLED": 0.75
    },
    "ece": 0.05,
    "confidence_adjustments": {
      "FILE_EXISTS": 1.0,
      "FUNCTION_CALLED": 0.75
    }
  },
  "summary": {
    "extraction_f1": 1.0,
    "verification_accuracy": 0.9333,
    "calibration_ece": 0.05,
    "overall_score": 0.9611
  }
}
```

The `overall_score` is the average of: extraction F1, verification accuracy, and (1 - ECE).

## CLI usage

```bash
# Basic evaluation with mock extraction
ccv eval --dataset tests/eval/dataset.jsonl --fixtures tests/eval/fixtures/

# Save report to file
ccv eval --dataset tests/eval/dataset.jsonl --fixtures tests/eval/fixtures/ --output eval-report.json

# Real extraction (requires LLM API key)
ccv eval --dataset tests/eval/dataset.jsonl --fixtures tests/eval/fixtures/ --no-mock-extraction
```

## Python API

```python
from code_claim_verifier.eval import run_evaluation
from code_claim_verifier.eval.report import write_report

report = run_evaluation(
    dataset_path="tests/eval/dataset.jsonl",
    fixtures_path="tests/eval/fixtures/",
    mock_extraction=True,
)

# Access metrics directly
print(f"Verification accuracy: {report['verification']['accuracy']}")
print(f"Overall score: {report['summary']['overall_score']}")

# Write to file
write_report(report, "eval-report.json")
```
