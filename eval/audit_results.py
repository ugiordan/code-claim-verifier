#!/usr/bin/env python3
"""Audit collected evaluation artifacts without rewriting them.

The audit deliberately separates provenance validity from verifier output.
Missing provenance, mutable checkouts, or incomplete GT matching make a run
unsuitable for headline accuracy claims even when its raw JSON is readable.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
from pathlib import Path

from code_claim_verifier.calibrator import calibrate
from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.types import TypedClaim
from eval.cybergym.utils import load_json, load_jsonl
from eval.cybergym.verify import _canonicalize_parameters
from eval.provenance import git_head, git_is_clean, is_immutable_revision, snapshot_digest


def _json_files(root: str):
    for path in sorted(Path(root).glob("*/*/*.json")):
        yield path


def _claim_from_record(record: dict) -> TypedClaim:
    claim_type = record.get("claim_type", record.get("type", ""))
    parameters = record.get("parameters", record.get("params", {}))
    return TypedClaim(
        claim_type=claim_type,
        parameters=_canonicalize_parameters(claim_type, parameters),
        source_sentence=record.get("source", ""),
    )


def _is_claim_record(value: object) -> bool:
    return isinstance(value, dict)


def _claim_parameter_issues(claim: TypedClaim) -> list[str]:
    required = {
        "FILE_EXISTS": ("path",),
        "LINE_CONTENT": ("path", "line", "content"),
        "FILE_CLASSIFICATION": ("path",),
        "GENERATED_OR_VENDORED": ("path",),
        "FUNCTION_EXISTS": ("name",),
        "FUNCTION_CALLED": ("name", "expected"),
        "HAS_CALLERS": ("name", "expected"),
        "IMPORT_EXISTS": ("module",),
        "PACKAGE_VERSION": ("package", "version"),
        "DEPENDENCY_TYPE": ("package",),
        "CVE_AFFECTS_VERSION": ("package", "version"),
        "ABSENCE": ("pattern",),
        "MITIGATION_EXISTS": ("file", "pattern"),
        "CONFIG_FLAG": ("flag",),
    }.get(claim.claim_type, ())
    missing = [key for key in required if key not in claim.parameters]
    if claim.claim_type == "FILE_CLASSIFICATION" and not (
        claim.parameters.get("category") or claim.parameters.get("classification")
    ):
        missing.append("category_or_classification")
    if claim.claim_type == "DEPENDENCY_TYPE" and not (
        claim.parameters.get("dep_type") or claim.parameters.get("type")
    ):
        missing.append("dep_type_or_type")
    if claim.claim_type == "ENTRY_POINT":
        if not claim.parameters.get("name") and not claim.parameters.get("location"):
            missing.append("name_or_location")
    if claim.claim_type == "CALL_CHAIN":
        if not claim.parameters.get("chain") and not (
            claim.parameters.get("caller") and claim.parameters.get("callee")
        ):
            missing.append("chain_or_caller_callee")
    return missing


def _gt_comparison_issues(comparison: dict) -> list[str]:
    results = comparison.get("results")
    if not isinstance(results, list):
        return ["missing_results"]
    items = [item for item in results if isinstance(item, dict)]
    issues: list[str] = []
    if len(items) != len(results):
        issues.append("malformed_results")
    counts = collections.Counter(item.get("status") for item in items)
    expected_counts = {
        "matched": comparison.get("matched", 0),
        "unmatched_prediction": comparison.get("unmatched_predictions", 0),
        "unmatched_ground_truth": comparison.get("unmatched_ground_truth", 0),
    }
    issues.extend(
        status for status, expected in expected_counts.items()
        if not isinstance(expected, int) or counts[status] != expected
    )
    if sum(expected_counts.values()) != len(results):
        issues.append("incomplete_counts")
    return issues


def _source_matches_manifest(
    entry: dict,
    digest_cache: dict[str, str],
    clean_cache: dict[str, bool] | None = None,
    require_canonical: bool = True,
) -> bool:
    """Validate a source identity without rehashing known-good Git checkouts."""
    root = entry.get("source_root", "")
    expected_digest = entry.get("source_digest", "")
    if not root or not os.path.isdir(root) or not expected_digest:
        return False
    if require_canonical and entry.get("manifest_schema") == 2:
        expected_head = entry.get("source_head")
        actual_head = git_head(root)
        if clean_cache is None:
            clean_cache = {}
        if root not in clean_cache:
            clean_cache[root] = git_is_clean(root)
        if expected_head and actual_head == expected_head and clean_cache[root]:
            return True
    if root not in digest_cache:
        digest_cache[root] = snapshot_digest(root)
    return digest_cache[root] == expected_digest


def audit_cybergym(
    manifest_path: str,
    results_dir: str,
    reverify_model: str | None = None,
    reverify_limit: int = 0,
) -> dict:
    manifest = {item["vuln_id"]: item for item in load_jsonl(manifest_path)}
    summary = {
        "dataset": "cybergym",
        "manifest_entries": len(manifest),
        "result_files": 0,
        "missing_manifest": 0,
        "missing_source_root": 0,
        "missing_provenance": 0,
        "provenance_mismatch": 0,
        "source_digest_mismatch": 0,
        "invalid_dataset_revision": 0,
        "invalid_manifest_schema": 0,
        "invalid_ground_truth": 0,
        "incomplete_gt_matching": 0,
        "legacy_gt_comparison": 0,
        "claims": 0,
        "malformed_claims": 0,
        "models": {},
        "canonical_reverification": None,
        "valid_for_headline_accuracy": False,
    }
    reverify_results: list[dict] = []
    digest_cache: dict[str, str] = {}
    clean_cache: dict[str, bool] = {}
    summary["invalid_dataset_revision"] = sum(
        1 for entry in manifest.values()
        if not is_immutable_revision(entry.get("dataset_revision"))
    )
    summary["invalid_manifest_schema"] = sum(
        1 for entry in manifest.values()
        if entry.get("manifest_schema") not in (2, 3)
    )
    summary["invalid_ground_truth"] = sum(
        1 for entry in manifest.values()
        if entry.get("ground_truth_validation") not in ("independent", "patch-derived")
    )

    for path in _json_files(results_dir):
        result = load_json(str(path))
        if not result:
            continue
        summary["result_files"] += 1
        vuln_id = result.get("vuln_id", path.stem)
        entry = manifest.get(vuln_id)
        if entry is None:
            summary["missing_manifest"] += 1
            continue
        source_root = entry.get("source_root", "")
        if not os.path.isdir(source_root):
            summary["missing_source_root"] += 1
        provenance = result.get("provenance", {})
        if not provenance or not entry.get("source_digest"):
            summary["missing_provenance"] += 1
        expected_metadata = {
            "manifest_schema": entry.get("manifest_schema"),
            "dataset_revision": entry.get("dataset_revision"),
            "source_digest": entry.get("source_digest"),
            "source_head": entry.get("source_head"),
        }
        if any(provenance.get(key) != value for key, value in expected_metadata.items()):
            summary["provenance_mismatch"] += 1
        if source_root and os.path.isdir(source_root) and entry.get("source_digest"):
            if not _source_matches_manifest(entry, digest_cache, clean_cache):
                summary["source_digest_mismatch"] += 1
        gt_comparison = result.get("gt_comparison", {})
        if "unmatched_predictions" not in gt_comparison:
            summary["legacy_gt_comparison"] += 1
        elif _gt_comparison_issues(gt_comparison):
            summary["incomplete_gt_matching"] += 1
        extraction = provenance.get("extraction", {})
        required_extraction_metadata = (
            "provider", "resolved_model", "max_tokens", "temperature",
            "config_version", "extraction_version", "system_prompt_digest",
            "user_prompt_digest",
        )
        if provenance and any(key not in extraction for key in required_extraction_metadata):
            summary["missing_provenance"] += 1

        key = f"{result.get('model', 'unknown')}/{result.get('condition', 'informed')}"
        model_stats = summary["models"].setdefault(
            key, {"results": 0, "claims": 0, "malformed_claims": 0}
        )
        model_stats["results"] += 1
        claims = result.get("ccv", {}).get("claims", [])
        model_stats["claims"] += len(claims)
        summary["claims"] += len(claims)
        for record in claims:
            if not _is_claim_record(record):
                model_stats["malformed_claims"] += 1
                summary["malformed_claims"] += 1
                continue
            claim = _claim_from_record(record)
            issues = _claim_parameter_issues(claim)
            model_stats["malformed_claims"] += bool(issues)
            summary["malformed_claims"] += bool(issues)

        if reverify_model and result.get("model") == reverify_model:
            if reverify_limit and len(reverify_results) >= reverify_limit:
                continue
            if not os.path.isdir(source_root):
                continue
            claims = [
                _claim_from_record(record) for record in claims
                if _is_claim_record(record)
            ]
            language = entry.get("language", "unknown")
            verified = VerificationEngine().verify_claims_with_chaining(
                claims, source_root, language
            )
            report = calibrate(verified)
            reverify_results.append({
                "vuln_id": vuln_id,
                "model": result.get("model"),
                "condition": result.get("condition"),
                "total_claims": report.total_claims,
                "verified": report.verified,
                "refuted": report.refuted,
                "unverifiable": report.unverifiable,
                "verification_rate": report.verification_rate,
            })

    if reverify_results:
        totals = collections.Counter()
        for item in reverify_results:
            totals.update({
                "results": 1,
                "claims": item["total_claims"],
                "verified": item["verified"],
                "refuted": item["refuted"],
                "unverifiable": item["unverifiable"],
            })
        denominator = totals["verified"] + totals["refuted"]
        summary["canonical_reverification"] = {
            **dict(totals),
            "refutation_rate": (
                round(totals["refuted"] / denominator, 4)
                if denominator else 0.0
            ),
            "scope": reverify_model,
        }

    summary["valid_for_headline_accuracy"] = bool(manifest) and bool(
        summary["result_files"]
    ) and not any(
        summary[key] for key in (
            "missing_manifest", "missing_source_root", "missing_provenance",
            "provenance_mismatch", "source_digest_mismatch",
            "invalid_dataset_revision", "invalid_manifest_schema",
            "invalid_ground_truth", "incomplete_gt_matching",
            "legacy_gt_comparison", "malformed_claims",
        )
    )
    return summary


def audit_multiswe(manifest_path: str, results_dir: str) -> dict:
    manifest = load_jsonl(manifest_path)
    manifest_by_id = {item.get("vuln_id"): item for item in manifest}
    by_root: dict[str, set[str]] = collections.defaultdict(set)
    current_matches = 0
    digest_cache: dict[str, str] = {}
    clean_cache: dict[str, bool] = {}
    for entry in manifest:
        root = entry.get("source_root", "")
        sha = entry.get("base_sha", "")
        by_root[root].add(sha)
        actual = git_head(root) if root else None
        if root not in clean_cache:
            clean_cache[root] = git_is_clean(root)
        if sha and actual and actual.startswith(sha[:12]) and clean_cache[root]:
            current_matches += 1
    shared_roots = {
        root: sorted(shas)
        for root, shas in by_root.items()
        if len(shas) > 1
    }
    result_files = 0
    missing_result_manifest = 0
    missing_result_provenance = 0
    provenance_mismatch = 0
    source_digest_mismatch = 0
    incomplete_gt_matching = 0
    valid_result_files = 0
    for path in _json_files(results_dir):
        result = load_json(str(path))
        if not result:
            continue
        result_files += 1
        entry = manifest_by_id.get(result.get("vuln_id"))
        if entry is None:
            missing_result_manifest += 1
            continue
        provenance = result.get("provenance", {})
        if not provenance:
            missing_result_provenance += 1
            continue
        expected = {
            "manifest_schema": entry.get("manifest_schema"),
            "dataset_revision": entry.get("dataset_revision"),
            "base_sha": entry.get("base_sha"),
            "source_digest": entry.get("source_digest"),
            "source_head": entry.get("source_head"),
        }
        if any(provenance.get(key) != value for key, value in expected.items()):
            provenance_mismatch += 1
        root = entry.get("source_root", "")
        if root and entry.get("source_digest"):
            if not _source_matches_manifest(entry, digest_cache, clean_cache):
                source_digest_mismatch += 1
        if provenance.get("include_patch_files"):
            provenance_mismatch += 1
        if _gt_comparison_issues(result.get("gt_comparison", {})):
            incomplete_gt_matching += 1
        required = (
            "provider", "resolved_model", "max_tokens", "temperature",
            "config_version",
        )
        if any(key not in provenance for key in required):
            missing_result_provenance += 1
        if not any((
            any(provenance.get(key) != value for key, value in expected.items()),
            provenance.get("include_patch_files"),
            _gt_comparison_issues(result.get("gt_comparison", {})),
            any(key not in provenance for key in required),
        )):
            valid_result_files += 1
    return {
        "dataset": "multiswe",
        "manifest_entries": len(manifest),
        "repositories": len(by_root),
        "shared_roots_with_multiple_base_shas": len(shared_roots),
        "current_checkout_matches": current_matches,
        "result_files": result_files,
        "valid_result_files": valid_result_files,
        "missing_result_manifest": missing_result_manifest,
        "missing_result_provenance": missing_result_provenance,
        "provenance_mismatch": provenance_mismatch,
        "source_digest_mismatch": source_digest_mismatch,
        "invalid_dataset_revision": sum(
            1 for item in manifest
            if not is_immutable_revision(item.get("dataset_revision"))
        ),
        "invalid_manifest_schema": sum(
            1 for item in manifest if item.get("manifest_schema") != 2
        ),
        "invalid_ground_truth": sum(
            1 for item in manifest
            if item.get("ground_truth_validation") != "independent"
        ),
        "incomplete_gt_matching": incomplete_gt_matching,
        "shared_roots": shared_roots,
        "valid_for_headline_accuracy": bool(manifest) and bool(result_files) and not any((
            shared_roots,
            current_matches != len(manifest),
            valid_result_files != result_files,
            missing_result_manifest,
            missing_result_provenance,
            provenance_mismatch,
            source_digest_mismatch,
            sum(1 for item in manifest if not is_immutable_revision(item.get("dataset_revision"))),
            sum(1 for item in manifest if item.get("manifest_schema") != 2),
            sum(1 for item in manifest if item.get("ground_truth_validation") != "independent"),
            incomplete_gt_matching,
        )),
    }


def audit_multilang(manifest_path: str, results_dir: str) -> dict:
    manifest = load_jsonl(manifest_path)
    manifest_by_id = {item.get("vuln_id"): item for item in manifest}
    summary = {
        "dataset": "multilang",
        "manifest_entries": len(manifest),
        "result_files": 0,
        "valid_result_files": 0,
        "missing_manifest": 0,
        "missing_source_root": 0,
        "missing_provenance": 0,
        "provenance_mismatch": 0,
        "source_digest_mismatch": 0,
        "invalid_dataset_revision": 0,
        "invalid_manifest_schema": 0,
        "invalid_ground_truth": 0,
        "incomplete_gt_matching": 0,
        "legacy_gt_comparison": 0,
        "claims": 0,
        "malformed_claims": 0,
        "valid_for_headline_accuracy": False,
    }
    digest_cache: dict[str, str] = {}
    clean_cache: dict[str, bool] = {}
    summary["invalid_dataset_revision"] = sum(
        1 for item in manifest
        if not is_immutable_revision(item.get("dataset_revision"))
    )
    summary["invalid_manifest_schema"] = sum(
        1 for item in manifest if item.get("manifest_schema") != 2
    )
    # PolyVuln ground truth is validated per entry by the prepare pipeline
    # (build + CCV vulnerability verification); require that evidence.
    summary["invalid_ground_truth"] = sum(
        1 for item in manifest
        if not (item.get("verification_method") and item.get("vuln_verified"))
    )

    for path in _json_files(results_dir):
        result = load_json(str(path))
        if not result:
            continue
        summary["result_files"] += 1
        entry = manifest_by_id.get(result.get("vuln_id"))
        if entry is None:
            summary["missing_manifest"] += 1
            continue
        file_issues = False
        source_root = entry.get("source_root", "")
        if not os.path.isdir(source_root):
            summary["missing_source_root"] += 1
            file_issues = True
        provenance = result.get("provenance", {})
        if not provenance or not entry.get("source_digest"):
            summary["missing_provenance"] += 1
            file_issues = True
        expected_metadata = {
            "manifest_schema": entry.get("manifest_schema"),
            "dataset_revision": entry.get("dataset_revision"),
            "source_digest": entry.get("source_digest"),
            "source_head": entry.get("source_head"),
        }
        metadata_mismatch = any(
            provenance.get(key) != value for key, value in expected_metadata.items()
        )
        if metadata_mismatch:
            summary["provenance_mismatch"] += 1
            file_issues = True
        if source_root and os.path.isdir(source_root) and entry.get("source_digest"):
            if not _source_matches_manifest(entry, digest_cache, clean_cache):
                summary["source_digest_mismatch"] += 1
                file_issues = True
        gt_comparison = result.get("gt_comparison", {})
        legacy_gt = "unmatched_predictions" not in gt_comparison
        if legacy_gt:
            summary["legacy_gt_comparison"] += 1
            file_issues = True
        elif _gt_comparison_issues(gt_comparison):
            summary["incomplete_gt_matching"] += 1
            file_issues = True
        extraction = provenance.get("extraction", {})
        required_extraction_metadata = (
            "provider", "resolved_model", "max_tokens", "temperature",
            "config_version", "extraction_version", "system_prompt_digest",
            "user_prompt_digest",
        )
        if provenance and any(
            key not in extraction for key in required_extraction_metadata
        ):
            summary["missing_provenance"] += 1
            file_issues = True
        claims = result.get("ccv", {}).get("claims", [])
        summary["claims"] += len(claims)
        for record in claims:
            if not _is_claim_record(record):
                summary["malformed_claims"] += 1
                file_issues = True
                continue
            if _claim_parameter_issues(_claim_from_record(record)):
                summary["malformed_claims"] += 1
                file_issues = True
        if not file_issues:
            summary["valid_result_files"] += 1

    summary["valid_for_headline_accuracy"] = bool(manifest) and bool(
        summary["result_files"]
    ) and not any(
        summary[key] for key in (
            "missing_manifest", "missing_source_root", "missing_provenance",
            "provenance_mismatch", "source_digest_mismatch",
            "invalid_dataset_revision", "invalid_manifest_schema",
            "invalid_ground_truth", "incomplete_gt_matching",
            "legacy_gt_comparison", "malformed_claims",
        )
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cybergym-manifest", default="eval/cybergym/manifest.jsonl")
    parser.add_argument("--cybergym-results", default="eval/cybergym/results")
    parser.add_argument("--multiswe-manifest", default="eval/multiswe/manifest-full.jsonl")
    parser.add_argument("--multiswe-results", default="eval/multiswe/results")
    parser.add_argument("--multilang-manifest", default="eval/multilang/manifest.jsonl")
    parser.add_argument("--multilang-results", default="eval/multilang/results")
    parser.add_argument("--reverify-model", default=None)
    parser.add_argument("--reverify-limit", type=int, default=0)
    parser.add_argument("--output", default="eval/audit/validity-report.json")
    args = parser.parse_args()

    report = {
        "cybergym": audit_cybergym(
            args.cybergym_manifest,
            args.cybergym_results,
            args.reverify_model,
            args.reverify_limit,
        ),
        "multiswe": audit_multiswe(args.multiswe_manifest, args.multiswe_results),
        "multilang": audit_multilang(args.multilang_manifest, args.multilang_results),
    }
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
