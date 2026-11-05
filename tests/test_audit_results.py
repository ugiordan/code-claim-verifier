"""Tests for eval/audit_results.py: headline-accuracy gating per dataset."""
from __future__ import annotations

import json

from eval.audit_results import audit_cybergym, audit_multilang, audit_multiswe
from eval.provenance import snapshot_digest

_REVISION = "0123456789abcdef0123456789abcdef01234567"

_EXTRACTION_PROVENANCE = {
    "provider": "anthropic",
    "resolved_model": "claude-sonnet-4",
    "max_tokens": 8192,
    "temperature": 0,
    "config_version": "model-config-v1",
    "extraction_version": "typed-claims-v1",
    "system_prompt_digest": "a" * 64,
    "user_prompt_digest": "b" * 64,
}


def _make_source_root(tmp_path, name: str) -> str:
    root = tmp_path / name
    root.mkdir()
    (root / "main.go").write_text("package main\nfunc vuln() {}\n")
    return str(root)


def _manifest_entry(source_root: str, **overrides) -> dict:
    entry = {
        "vuln_id": "GHSA-0000-0000-0000",
        "source_root": source_root,
        "source_digest": snapshot_digest(source_root),
        "source_head": None,
        "manifest_schema": 2,
        "dataset_revision": _REVISION,
        "language": "go",
        "gt_claims": [],
    }
    entry.update(overrides)
    return entry


def _result(vuln_id: str, provenance: dict, **overrides) -> dict:
    result = {
        "vuln_id": vuln_id,
        "model": "test-model",
        "condition": "informed",
        "ccv": {
            "total_claims": 1, "verified": 1, "refuted": 0, "unverifiable": 0,
            "verification_rate": 1.0, "action": "BOOST",
            "claims": [
                {
                    "claim_type": "FUNCTION_EXISTS",
                    "parameters": {"name": "vuln"},
                    "verdict": "VERIFIED",
                }
            ],
        },
        "provenance": provenance,
        "gt_comparison": {
            "matched": 1,
            "unmatched_predictions": 0,
            "unmatched_ground_truth": 0,
            "results": [{"status": "matched"}],
        },
    }
    result.update(overrides)
    return result


def _write_manifest(tmp_path, entries: list[dict], name: str = "manifest.jsonl") -> str:
    path = tmp_path / name
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))
    return str(path)


def _write_result(tmp_path, result: dict, model: str = "test-model") -> str:
    out_dir = tmp_path / "results" / model / "informed"
    out_dir.mkdir(parents=True)
    path = out_dir / f"{result['vuln_id']}.json"
    path.write_text(json.dumps(result))
    return str(tmp_path / "results")


def _clean_provenance(entry: dict) -> dict:
    return {
        "manifest_schema": entry.get("manifest_schema"),
        "dataset_revision": entry.get("dataset_revision"),
        "source_digest": entry.get("source_digest"),
        "source_head": entry.get("source_head"),
        "extraction": dict(_EXTRACTION_PROVENANCE),
    }


class TestAuditCybergym:
    def test_clean_run_is_valid_for_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(tmp_path, _result(entry["vuln_id"], _clean_provenance(entry)))
        summary = audit_cybergym(manifest, results)
        assert summary["result_files"] == 1
        assert summary["valid_for_headline_accuracy"] is True

    def test_zero_result_files_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        empty_results = tmp_path / "results"
        empty_results.mkdir()
        summary = audit_cybergym(manifest, str(empty_results))
        assert summary["result_files"] == 0
        assert summary["valid_for_headline_accuracy"] is False

    def test_result_for_unknown_vuln_id_counts_missing_manifest(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(tmp_path, _result("GHSA-unknown", _clean_provenance(entry)))
        summary = audit_cybergym(manifest, results)
        assert summary["missing_manifest"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_corrupt_result_file_is_skipped_not_crashed(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        results_dir = tmp_path / "results" / "test-model" / "informed"
        results_dir.mkdir(parents=True)
        (results_dir / "broken.json").write_text("{not valid json")
        summary = audit_cybergym(manifest, str(tmp_path / "results"))
        assert summary["result_files"] == 0
        assert summary["valid_for_headline_accuracy"] is False

    def test_non_dict_claim_record_counts_as_malformed(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        result = _result(entry["vuln_id"], _clean_provenance(entry))
        result["ccv"]["claims"] = ["just a string", 42]
        results = _write_result(tmp_path, result)
        summary = audit_cybergym(manifest, results)
        assert summary["malformed_claims"] == 2
        assert summary["valid_for_headline_accuracy"] is False

    def test_non_dict_gt_result_item_is_flagged_not_crashed(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        result = _result(entry["vuln_id"], _clean_provenance(entry))
        result["gt_comparison"] = {
            "matched": 1, "unmatched_predictions": 0, "unmatched_ground_truth": 0,
            "results": [{"status": "matched"}, "garbage"],
        }
        results = _write_result(tmp_path, result)
        summary = audit_cybergym(manifest, results)
        assert summary["incomplete_gt_matching"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_gt_counts_mismatch_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        result = _result(entry["vuln_id"], _clean_provenance(entry))
        result["gt_comparison"] = {
            "matched": 2, "unmatched_predictions": 0, "unmatched_ground_truth": 0,
            "results": [{"status": "matched"}],
        }
        results = _write_result(tmp_path, result)
        summary = audit_cybergym(manifest, results)
        assert summary["incomplete_gt_matching"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_clean_git_checkout_at_recorded_head_is_valid(self, tmp_path):
        import subprocess

        repo = tmp_path / "gitsrc"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, capture_output=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, capture_output=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repo, capture_output=True)
        (repo / "main.go").write_text("package main\n")
        subprocess.run(["git", "add", "."], cwd=repo, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True)
        from eval.provenance import git_head

        entry = _manifest_entry(
            str(repo), ground_truth_validation="independent", source_head=git_head(str(repo)),
        )
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(tmp_path, _result(entry["vuln_id"], _clean_provenance(entry)))
        summary = audit_cybergym(manifest, results)
        assert summary["source_digest_mismatch"] == 0
        assert summary["valid_for_headline_accuracy"] is True

    def test_moved_head_with_identical_content_falls_back_to_digest(self, tmp_path):
        import subprocess

        repo = tmp_path / "gitsrc"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, capture_output=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, capture_output=True)
        subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repo, capture_output=True)
        (repo / "main.go").write_text("package main\n")
        subprocess.run(["git", "add", "."], cwd=repo, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True)
        from eval.provenance import git_head

        recorded_head = git_head(str(repo))
        # Empty commit moves HEAD without changing any file content.
        subprocess.run(
            ["git", "commit", "--allow-empty", "-m", "noop"], cwd=repo, capture_output=True,
        )
        assert git_head(str(repo)) != recorded_head

        entry = _manifest_entry(
            str(repo), ground_truth_validation="independent", source_head=recorded_head,
        )
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(tmp_path, _result(entry["vuln_id"], _clean_provenance(entry)))
        summary = audit_cybergym(manifest, results)
        assert summary["source_digest_mismatch"] == 0
        assert summary["valid_for_headline_accuracy"] is True

    def test_missing_provenance_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(
            tmp_path, _result(entry["vuln_id"], provenance={})
        )
        summary = audit_cybergym(manifest, results)
        assert summary["missing_provenance"] >= 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_digest_mismatch_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        # Tamper with the source after the manifest digest was recorded.
        (tmp_path / "src" / "main.go").write_text("package main\nfunc evil() {}\n")
        results = _write_result(tmp_path, _result(entry["vuln_id"], _clean_provenance(entry)))
        summary = audit_cybergym(manifest, results)
        assert summary["source_digest_mismatch"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_legacy_gt_comparison_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        result = _result(entry["vuln_id"], _clean_provenance(entry))
        result["gt_comparison"] = {"matched": 1, "results": []}
        results = _write_result(tmp_path, result)
        summary = audit_cybergym(manifest, results)
        assert summary["legacy_gt_comparison"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_incomplete_gt_counts_block_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        result = _result(entry["vuln_id"], _clean_provenance(entry))
        result["gt_comparison"] = {
            "matched": 1, "unmatched_predictions": 0, "unmatched_ground_truth": 0,
            "results": [],
        }
        results = _write_result(tmp_path, result)
        summary = audit_cybergym(manifest, results)
        assert summary["incomplete_gt_matching"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_malformed_claim_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        result = _result(entry["vuln_id"], _clean_provenance(entry))
        result["ccv"]["claims"] = [{"claim_type": "FUNCTION_EXISTS", "parameters": {}}]
        results = _write_result(tmp_path, result)
        summary = audit_cybergym(manifest, results)
        assert summary["malformed_claims"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_non_independent_ground_truth_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="heuristic")
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(tmp_path, _result(entry["vuln_id"], _clean_provenance(entry)))
        summary = audit_cybergym(manifest, results)
        assert summary["invalid_ground_truth"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_missing_extraction_metadata_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, ground_truth_validation="independent")
        manifest = _write_manifest(tmp_path, [entry])
        provenance = _clean_provenance(entry)
        del provenance["extraction"]["extraction_version"]
        results = _write_result(tmp_path, _result(entry["vuln_id"], provenance))
        summary = audit_cybergym(manifest, results)
        assert summary["missing_provenance"] >= 1
        assert summary["valid_for_headline_accuracy"] is False


class TestAuditMultiswe:
    def _provenance(self, entry):
        provenance = _clean_provenance(entry)
        provenance["base_sha"] = entry["base_sha"]
        # multiswe records model configuration at the provenance top level.
        provenance.update({
            "provider": _EXTRACTION_PROVENANCE["provider"],
            "resolved_model": _EXTRACTION_PROVENANCE["resolved_model"],
            "max_tokens": _EXTRACTION_PROVENANCE["max_tokens"],
            "temperature": _EXTRACTION_PROVENANCE["temperature"],
            "config_version": _EXTRACTION_PROVENANCE["config_version"],
        })
        return provenance

    def test_clean_run_is_valid_for_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, base_sha=_REVISION)
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(
            tmp_path, _result(entry["vuln_id"], self._provenance(entry))
        )
        summary = audit_multiswe(manifest, results)
        assert summary["valid_result_files"] == 1
        # Non-git source root: the checkout cannot be shown to match base_sha.
        assert summary["current_checkout_matches"] == 0
        assert summary["valid_for_headline_accuracy"] is False

    def test_empty_results_dir_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, base_sha=_REVISION)
        manifest = _write_manifest(tmp_path, [entry])
        empty_results = tmp_path / "results"
        empty_results.mkdir()
        summary = audit_multiswe(manifest, str(empty_results))
        assert summary["result_files"] == 0
        assert summary["valid_for_headline_accuracy"] is False

    def test_shared_root_with_multiple_base_shas_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "shared")
        entries = [
            _manifest_entry(source, base_sha=_REVISION),
            _manifest_entry(
                source, vuln_id="GHSA-0000-0000-0001",
                base_sha="ffffffffffffffffffffffffffffffffffffffff",
            ),
        ]
        manifest = _write_manifest(tmp_path, entries)
        results = _write_result(
            tmp_path, _result(entries[0]["vuln_id"], self._provenance(entries[0]))
        )
        summary = audit_multiswe(manifest, results)
        assert summary["shared_roots_with_multiple_base_shas"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_include_patch_files_flag_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, base_sha=_REVISION)
        manifest = _write_manifest(tmp_path, [entry])
        provenance = self._provenance(entry)
        provenance["include_patch_files"] = True
        results = _write_result(tmp_path, _result(entry["vuln_id"], provenance))
        summary = audit_multiswe(manifest, results)
        assert summary["provenance_mismatch"] == 1
        assert summary["valid_result_files"] == 0

    def test_corrupt_result_file_is_skipped_not_crashed(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, base_sha=_REVISION)
        manifest = _write_manifest(tmp_path, [entry])
        results_dir = tmp_path / "results" / "test-model" / "informed"
        results_dir.mkdir(parents=True)
        (results_dir / "broken.json").write_text("{oops")
        summary = audit_multiswe(manifest, str(tmp_path / "results"))
        assert summary["result_files"] == 0
        assert summary["valid_for_headline_accuracy"] is False

    def test_provenance_mismatch_flags_file(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, base_sha=_REVISION)
        manifest = _write_manifest(tmp_path, [entry])
        provenance = _clean_provenance(entry)
        provenance["dataset_revision"] = "ffffffffffffffffffffffffffffffffffffffff"
        results = _write_result(tmp_path, _result(entry["vuln_id"], provenance))
        summary = audit_multiswe(manifest, results)
        assert summary["provenance_mismatch"] == 1
        assert summary["valid_result_files"] == 0


class TestAuditMultilang:
    def test_clean_run_is_valid_for_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(
            source, verification_method="ccv-build-verify", vuln_verified=True,
        )
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(tmp_path, _result(entry["vuln_id"], _clean_provenance(entry)))
        summary = audit_multilang(manifest, results)
        assert summary["result_files"] == 1
        assert summary["valid_result_files"] == 1
        assert summary["valid_for_headline_accuracy"] is True

    def test_missing_gt_verification_evidence_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(source, verification_method="", vuln_verified=False)
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(tmp_path, _result(entry["vuln_id"], _clean_provenance(entry)))
        summary = audit_multilang(manifest, results)
        assert summary["invalid_ground_truth"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_legacy_result_is_counted_but_blocked(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(
            source, verification_method="ccv-build-verify", vuln_verified=True,
        )
        manifest = _write_manifest(tmp_path, [entry])
        result = _result(entry["vuln_id"], provenance={})
        result["gt_comparison"] = {"matched": 1, "results": []}
        results = _write_result(tmp_path, result)
        summary = audit_multilang(manifest, results)
        assert summary["result_files"] == 1
        assert summary["valid_result_files"] == 0
        assert summary["legacy_gt_comparison"] == 1
        assert summary["missing_provenance"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_unenriched_manifest_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(
            source, verification_method="ccv-build-verify", vuln_verified=True,
        )
        for field in ("manifest_schema", "dataset_revision", "source_digest", "source_head"):
            entry.pop(field)
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(tmp_path, _result(entry["vuln_id"], provenance={}))
        summary = audit_multilang(manifest, results)
        assert summary["invalid_manifest_schema"] == 1
        assert summary["invalid_dataset_revision"] == 1
        assert summary["missing_provenance"] >= 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_empty_results_dir_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(
            source, verification_method="ccv-build-verify", vuln_verified=True,
        )
        manifest = _write_manifest(tmp_path, [entry])
        empty_results = tmp_path / "results"
        empty_results.mkdir()
        summary = audit_multilang(manifest, str(empty_results))
        assert summary["result_files"] == 0
        assert summary["valid_for_headline_accuracy"] is False

    def test_corrupt_result_file_is_skipped_not_crashed(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(
            source, verification_method="ccv-build-verify", vuln_verified=True,
        )
        manifest = _write_manifest(tmp_path, [entry])
        results_dir = tmp_path / "results" / "test-model" / "informed"
        results_dir.mkdir(parents=True)
        (results_dir / "broken.json").write_text("not json at all")
        summary = audit_multilang(manifest, str(tmp_path / "results"))
        assert summary["result_files"] == 0
        assert summary["valid_for_headline_accuracy"] is False

    def test_non_dict_claim_record_counts_as_malformed(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(
            source, verification_method="ccv-build-verify", vuln_verified=True,
        )
        manifest = _write_manifest(tmp_path, [entry])
        result = _result(entry["vuln_id"], _clean_provenance(entry))
        result["ccv"]["claims"] = [None, "string claim"]
        results = _write_result(tmp_path, result)
        summary = audit_multilang(manifest, results)
        assert summary["malformed_claims"] == 2
        assert summary["valid_for_headline_accuracy"] is False

    def test_result_for_unknown_vuln_id_counts_missing_manifest(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(
            source, verification_method="ccv-build-verify", vuln_verified=True,
        )
        manifest = _write_manifest(tmp_path, [entry])
        results = _write_result(
            tmp_path, _result("GHSA-does-not-exist", _clean_provenance(entry))
        )
        summary = audit_multilang(manifest, results)
        assert summary["missing_manifest"] == 1
        assert summary["valid_for_headline_accuracy"] is False

    def test_tampered_source_blocks_headline(self, tmp_path):
        source = _make_source_root(tmp_path, "src")
        entry = _manifest_entry(
            source, verification_method="ccv-build-verify", vuln_verified=True,
        )
        manifest = _write_manifest(tmp_path, [entry])
        (tmp_path / "src" / "extra.go").write_text("package main\n")
        results = _write_result(tmp_path, _result(entry["vuln_id"], _clean_provenance(entry)))
        summary = audit_multilang(manifest, results)
        assert summary["source_digest_mismatch"] == 1
        assert summary["valid_for_headline_accuracy"] is False
