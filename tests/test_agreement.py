"""Tests for the cross-source agreement harness."""
from __future__ import annotations

from eval.agreement.harness import classify, extract_triples

SAMPLE_REPORT = {
    "manifest_hash": "sha256:abc",
    "packages": {
        "34": {"name": "gpgv", "version": "2.2.40-1.1", "kind": "binary"},
        "6": {"name": "base-files", "version": "12.4", "kind": "binary"},
    },
    "distributions": {"1": {"did": "debian", "version_id": "12"}},
    "environments": {
        "34": [{"distribution_id": "1"}],
        "6": [{"distribution_id": "1"}],
    },
    "vulnerabilities": {
        "9": {"name": "CVE-2025-1111", "package": {"name": "gnupg2", "kind": "source"}},
        "10": {"name": "CVE-2025-2222", "package": {"name": "base-files", "kind": "source"}},
    },
    "package_vulnerabilities": {
        "34": ["9", "10"],
        "6": ["10"],
    },
}


class TestExtractTriples:
    def test_extracts_edges_with_source_package(self):
        triples = extract_triples(SAMPLE_REPORT, "sample.json")
        # CVE-2025-2222 reaches both binaries but its source package is
        # base-files either way: one deduped triple per (cve, source, distro).
        assert len(triples) == 2
        by_key = {(t["cve"], t["source_package"]) for t in triples}
        assert ("CVE-2025-1111", "gnupg2") in by_key
        assert ("CVE-2025-2222", "base-files") in by_key
        for triple in triples:
            assert triple["distro"] == "debian:12"
            assert triple["clair_affected"] is True

    def test_dedup_within_report(self):
        triples = extract_triples(SAMPLE_REPORT, "sample.json")
        keys = [(t["cve"], t["source_package"], t["distro"]) for t in triples]
        assert len(keys) == len(set(keys))

    def test_missing_names_skipped(self):
        report = {
            "packages": {"1": {"name": "x", "version": "1", "kind": "binary"}},
            "vulnerabilities": {"2": {"name": "", "package": {}}},
            "package_vulnerabilities": {"1": ["2"]},
        }
        assert extract_triples(report, "empty.json") == []


class TestClassify:
    def _result(self, osv_match=None, osv_gap=None, vex_status=None, vex_gap=None):
        return {
            "osv": {"matching_cve": osv_match, "gap_reason": osv_gap},
            "vex": {"status": vex_status, "gap_reason": vex_gap},
        }

    def test_agree_affected(self):
        out = classify(self._result(osv_match=True, vex_status="known_affected"))
        assert out["clair_vs_osv"] == "agree_affected"
        assert out["vex_view"] == "status:known_affected"

    def test_disagree(self):
        out = classify(self._result(osv_match=False))
        assert out["clair_vs_osv"] == "disagree_affectedness"

    def test_osv_gap(self):
        out = classify(self._result(osv_gap="osv_query_failed"))
        assert out["clair_vs_osv"] == "osv_gap:osv_query_failed"

    def test_vex_gap_taxonomy(self):
        out = classify(self._result(vex_gap="component_under_different_product_prefix"))
        assert out["vex_view"] == "vex_gap:component_under_different_product_prefix"

    def test_indeterminate(self):
        out = classify(self._result(osv_match=None, vex_gap=None))
        assert out["clair_vs_osv"] == "osv_indeterminate"
        assert out["vex_view"] == "vex_indeterminate"
