"""Tests for Clair report ingestion and the CVE_AFFECTS_VERSION clair path."""
from __future__ import annotations

import urllib.request
from pathlib import Path

import pytest

from code_claim_verifier import (
    ClairAssessment,
    ClairReport,
    fetch_clair_assessment,
    load_clair_report,
    parse_clair_report,
)
from code_claim_verifier.types import TypedClaim
from code_claim_verifier.verifiers.import_claims import verify_cve_affects

FIXTURE = Path(__file__).parent / "fixtures" / "clair" / "debian12-slim.json"
MANIFEST = "sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018"
GPGV_VERSION = "2.2.40-1.1+deb12u2"
TAR_VERSION = "1.34+dfsg-1.2+deb12u1"


def _claim(parameters: dict) -> TypedClaim:
    return TypedClaim(
        claim_type="CVE_AFFECTS_VERSION",
        parameters=parameters,
        source_sentence="",
    )


class TestParseClairReport:
    def test_fixture_parses_with_expected_shape(self):
        report = load_clair_report(str(FIXTURE))
        assert isinstance(report, ClairReport)
        assert report.manifest_hash == MANIFEST
        assert report.distro == "debian/12"
        assert {pkg.name for pkg in report.packages.values()} == {
            "base-files", "gpgv", "tar",
        }
        assert all(pkg.kind == "binary" for pkg in report.packages.values())
        assert len(report.vulnerabilities) == 10
        assert sum(len(v) for v in report.package_vulnerabilities.values()) == 10
        assert "base-files" not in {
            report.packages[pid].name
            for pid in report.package_vulnerabilities
            if report.package_vulnerabilities[pid]
        }

    def test_cve_names_and_updater_survive_parse(self):
        report = load_clair_report(str(FIXTURE))
        names = {vuln.name for vuln in report.vulnerabilities.values()}
        assert "CVE-2025-30258" in names
        assert "TEMP-0290435-0B57B5" in names
        assert all(
            vuln.updater == "debian/updater"
            for vuln in report.vulnerabilities.values()
        )

    def test_non_object_raises(self):
        with pytest.raises(ValueError):
            parse_clair_report([1, 2, 3])

    def test_malformed_entries_are_skipped(self):
        report = parse_clair_report({
            "manifest_hash": "sha256:abc",
            "packages": {"1": {"name": "ok", "version": "1.0", "kind": "binary"},
                         "2": {"version": "2.0"},
                         "3": "not-a-dict"},
            "vulnerabilities": {"9": {"name": "CVE-2026-0001"}},
            "package_vulnerabilities": {"1": ["9"], "2": "not-a-list"},
            "environments": {"1": [{"distribution_id": "7"}]},
            "distributions": {"7": {"did": "debian", "version_id": "12"}},
        })
        assert set(report.packages) == {"1"}
        assert set(report.vulnerabilities) == {"9"}
        assert report.package_vulnerabilities == {"1": ("9",)}
        assert report.distro == "debian/12"

    def test_empty_report_is_valid(self):
        report = parse_clair_report({})
        assert report.manifest_hash is None
        assert report.distro is None
        assert report.packages == {}
        assert report.vulnerabilities == {}


class TestFetchClairAssessment:
    def test_affected_package(self):
        report = load_clair_report(str(FIXTURE))
        assessment = fetch_clair_assessment(report, "CVE-2025-30258", "gpgv")
        assert isinstance(assessment, ClairAssessment)
        assert assessment.affected is True
        assert assessment.installed_version == GPGV_VERSION
        assert assessment.gap_reason is None
        assert assessment.distro == "debian/12"
        assert assessment.manifest_hash == MANIFEST
        assert assessment.updater == "debian/updater"
        assert assessment.severity is not None

    def test_cve_known_but_not_linked_to_package(self):
        report = load_clair_report(str(FIXTURE))
        assessment = fetch_clair_assessment(report, "CVE-2005-2541", "gpgv")
        assert assessment.affected is None
        assert assessment.gap_reason == "cve_not_linked_to_package"
        assert assessment.installed_version == GPGV_VERSION
        assert assessment.severity is not None

    def test_clean_package_is_not_affected(self):
        report = load_clair_report(str(FIXTURE))
        assessment = fetch_clair_assessment(report, "CVE-2025-30258", "base-files")
        assert assessment.affected is None
        assert assessment.gap_reason == "cve_not_linked_to_package"
        assert assessment.installed_version == "12.4+deb12u15"

    def test_cve_not_in_report(self):
        report = load_clair_report(str(FIXTURE))
        assessment = fetch_clair_assessment(report, "CVE-1999-0001", "gpgv")
        assert assessment.affected is None
        assert assessment.gap_reason == "cve_not_in_report"
        assert assessment.installed_version == GPGV_VERSION

    def test_package_not_in_report(self):
        report = load_clair_report(str(FIXTURE))
        assessment = fetch_clair_assessment(report, "CVE-2025-30258", "openssl")
        assert assessment.affected is None
        assert assessment.gap_reason == "package_not_in_report"
        assert assessment.installed_version is None
        assert assessment.severity is not None

    def test_case_insensitive_cve(self):
        report = load_clair_report(str(FIXTURE))
        assessment = fetch_clair_assessment(report, "cve-2025-30258", "gpgv")
        assert assessment.affected is True


class TestCveAffectsViaClair:
    def test_affected_verifies_with_source(self):
        result = verify_cve_affects(
            _claim({
                "cve": "CVE-2025-30258", "package": "gpgv",
                "version": GPGV_VERSION, "clair_report": str(FIXTURE),
            }),
            "/tmp", "python",
        )
        assert result.verdict == "VERIFIED"
        assert result.method == "clair_report"
        assert result.verification_source == "clair_report"
        assert MANIFEST in result.evidence
        assert GPGV_VERSION in result.evidence

    def test_version_mismatch_is_unverifiable(self):
        result = verify_cve_affects(
            _claim({
                "cve": "CVE-2025-30258", "package": "gpgv",
                "version": "9.9.9", "clair_report": str(FIXTURE),
            }),
            "/tmp", "python",
        )
        assert result.verdict == "UNVERIFIABLE"
        assert "did not assess" in result.evidence
        assert GPGV_VERSION in result.evidence

    def test_not_linked_is_unverifiable(self):
        result = verify_cve_affects(
            _claim({
                "cve": "CVE-2005-2541", "package": "gpgv",
                "version": GPGV_VERSION, "clair_report": str(FIXTURE),
            }),
            "/tmp", "python",
        )
        assert result.verdict == "UNVERIFIABLE"
        assert "does not link" in result.evidence
        assert "not proof of safety" in result.evidence

    def test_missing_report_unverifiable(self):
        result = verify_cve_affects(
            _claim({
                "cve": "CVE-2025-30258", "package": "gpgv",
                "version": GPGV_VERSION, "clair_report": "/no/such/report.json",
            }),
            "/tmp", "python",
        )
        assert result.verdict == "UNVERIFIABLE"
        assert "not found" in result.evidence

    def test_unreadable_report_unverifiable(self, tmp_path):
        bad = tmp_path / "report.json"
        bad.write_text("not json at all")
        result = verify_cve_affects(
            _claim({
                "cve": "CVE-2025-30258", "package": "gpgv",
                "version": GPGV_VERSION, "clair_report": str(bad),
            }),
            "/tmp", "python",
        )
        assert result.verdict == "UNVERIFIABLE"
        assert "unreadable" in result.evidence

    def test_missing_cve_parameter_unverifiable(self):
        result = verify_cve_affects(
            _claim({
                "package": "gpgv", "version": GPGV_VERSION,
                "clair_report": str(FIXTURE),
            }),
            "/tmp", "python",
        )
        assert result.verdict == "UNVERIFIABLE"
        assert "requires the cve parameter" in result.evidence

    def test_repo_relative_path_resolution(self, tmp_path):
        (tmp_path / "scan.json").write_text(FIXTURE.read_text())
        result = verify_cve_affects(
            _claim({
                "cve": "CVE-2025-30258", "package": "gpgv",
                "version": GPGV_VERSION, "clair_report": "scan.json",
            }),
            str(tmp_path), "python",
        )
        assert result.verdict == "VERIFIED"

    def test_traversal_outside_repo_rejected(self, tmp_path):
        result = verify_cve_affects(
            _claim({
                "cve": "CVE-2025-30258", "package": "gpgv",
                "version": GPGV_VERSION,
                "clair_report": "../../../etc/passwd",
            }),
            str(tmp_path), "python",
        )
        assert result.verdict == "UNVERIFIABLE"
        assert "not found" in result.evidence

    def test_osv_not_called_when_clair_report_present(self, monkeypatch):
        def no_network(*args, **kwargs):
            raise AssertionError("OSV API must not be called when a clair_report is supplied")

        monkeypatch.setattr(urllib.request, "urlopen", no_network)
        result = verify_cve_affects(
            _claim({
                "cve": "CVE-2025-30258", "package": "gpgv",
                "version": GPGV_VERSION, "clair_report": str(FIXTURE),
            }),
            "/tmp", "python",
        )
        assert result.verdict == "VERIFIED"


class TestReviewFixes:
    def test_malformed_collections_raise(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text('{"packages": [], "vulnerabilities": {}, "package_vulnerabilities": {}}')
        result = verify_cve_affects(
            _claim({
                "cve": "CVE-2025-30258", "package": "gpgv",
                "version": GPGV_VERSION, "clair_report": str(bad),
            }),
            "/tmp", "python",
        )
        assert result.verdict == "UNVERIFIABLE"
        assert "unreadable" in result.evidence

    def test_duplicate_package_names_use_matched_edge_version(self):
        report = parse_clair_report({
            "manifest_hash": "sha256:dup",
            "packages": {
                "1": {"name": "dup", "version": "2.0", "kind": "binary"},
                "2": {"name": "dup", "version": "1.0", "kind": "binary"},
            },
            "vulnerabilities": {"9": {"name": "CVE-2026-0001"}},
            "package_vulnerabilities": {"2": ["9"]},
            "environments": {"1": [{"distribution_id": "7"}], "2": [{"distribution_id": "7"}]},
            "distributions": {"7": {"did": "debian", "version_id": "12"}},
        })
        assessment = fetch_clair_assessment(report, "CVE-2026-0001", "dup")
        assert assessment.affected is True
        assert assessment.installed_version == "1.0"

    def test_duplicate_package_names_unlinked_ambiguous_version(self):
        report = parse_clair_report({
            "manifest_hash": "sha256:dup2",
            "packages": {
                "1": {"name": "dup", "version": "2.0", "kind": "binary"},
                "2": {"name": "dup", "version": "1.0", "kind": "binary"},
            },
            "vulnerabilities": {"9": {"name": "CVE-2026-0001"}},
            "package_vulnerabilities": {},
        })
        assessment = fetch_clair_assessment(report, "CVE-2026-0001", "dup")
        assert assessment.affected is None
        assert assessment.gap_reason == "cve_not_linked_to_package"
        assert assessment.installed_version is None
