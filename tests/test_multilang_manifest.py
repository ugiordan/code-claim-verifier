from __future__ import annotations

from eval.multilang.build_manifest import _select_top_cases, _validate_manifest_entry
from eval.multilang.constants import CandidateStatus


def _make_candidate(osv_id: str, ecosystem: str, status: str,
                    test_success: bool = True, gt_claims: list | None = None):
    return {
        "osv_id": osv_id,
        "cve_id": "CVE-2023-0001",
        "ecosystem": ecosystem,
        "package": "example/pkg",
        "repo_url": "https://github.com/example/pkg",
        "fix_commit": "abc123",
        "source_root": f"repos/go/{osv_id}",
        "language": "go",
        "description": "A" * 60,
        "severity": "HIGH",
        "published_date": "2023-06-15",
        "source_files": ["main.go"] * 5,
        "source_functions": ["func1", "func2"],
        "gt_claims": gt_claims or [
            {"claim_type": "FILE_EXISTS", "parameters": {"path": "main.go"},
             "expected_verdict": "VERIFIED", "gt_tier": "source"},
        ] * 6 + [
            {"claim_type": "FILE_EXISTS", "parameters": {"path": "fake.go"},
             "expected_verdict": "REFUTED", "gt_tier": "tier1"},
        ] * 4,
        "build_verified": True,
        "vuln_verified": True,
        "verification_method": "ccv",
        "test_success": test_success,
        "status": status,
    }


class TestSelectTopCases:
    def test_selects_up_to_n_per_language(self):
        candidates = [
            _make_candidate(f"GHSA-{i:04d}", "Go", CandidateStatus.READY)
            for i in range(10)
        ]
        selected = _select_top_cases(candidates, per_language=5)
        assert len(selected) == 5

    def test_prioritizes_test_success(self):
        candidates = [
            _make_candidate("GHSA-0001", "Go", CandidateStatus.READY, test_success=False),
            _make_candidate("GHSA-0002", "Go", CandidateStatus.READY, test_success=True),
        ]
        selected = _select_top_cases(candidates, per_language=1)
        assert selected[0]["osv_id"] == "GHSA-0002"

    def test_skips_non_ready(self):
        candidates = [
            _make_candidate("GHSA-0001", "Go", CandidateStatus.FAILED),
            _make_candidate("GHSA-0002", "Go", CandidateStatus.READY),
        ]
        selected = _select_top_cases(candidates, per_language=5)
        assert len(selected) == 1
        assert selected[0]["osv_id"] == "GHSA-0002"


class TestValidateManifestEntry:
    def test_valid_entry_passes(self):
        c = _make_candidate("GHSA-0001", "Go", CandidateStatus.READY)
        assert _validate_manifest_entry(c) is True

    def test_missing_description_fails(self):
        c = _make_candidate("GHSA-0001", "Go", CandidateStatus.READY)
        c["description"] = "short"
        assert _validate_manifest_entry(c) is False
