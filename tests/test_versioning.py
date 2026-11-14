"""Tests for offline version comparison and the range/upgrade claim types."""
from __future__ import annotations

import io
import json
import urllib.request

import pytest

from code_claim_verifier import OsvAssessment, fetch_osv_assessment
from code_claim_verifier.types import TypedClaim
from code_claim_verifier.verifiers.import_claims import (
    verify_cve_affects,
    verify_upgrade_fixes,
    verify_version_in_range,
)
from code_claim_verifier.versioning import compare, fixes, in_range


def _claim(claim_type: str, parameters: dict) -> TypedClaim:
    return TypedClaim(claim_type=claim_type, parameters=parameters, source_sentence="")


class TestSemVer:
    def test_basic_ordering(self):
        assert compare("1.2.3", "1.2.4") < 0
        assert compare("1.10.0", "1.9.0") > 0
        assert compare("1.2.3", "1.2.3") == 0

    def test_prerelease_sorts_before_release(self):
        assert compare("1.2.3-alpha", "1.2.3") < 0
        assert compare("1.2.3-alpha.1", "1.2.3-alpha.2") < 0
        assert compare("1.2.3-alpha", "1.2.3-beta") < 0

    def test_numeric_prerelease_before_alphanumeric(self):
        assert compare("1.0.0-1", "1.0.0-alpha") < 0

    def test_v_prefix_ignored(self):
        assert compare("v1.2.3", "1.2.3") == 0

    def test_unparsable_raises(self):
        with pytest.raises(ValueError):
            compare("not-a-version", "1.2.3")


class TestPEP440:
    def test_pre_release_ordering(self):
        assert compare("1.0.dev1", "1.0a1", "python") < 0
        assert compare("1.0a1", "1.0b2", "python") < 0
        assert compare("1.0b2", "1.0rc1", "python") < 0
        assert compare("1.0rc1", "1.0", "python") < 0
        assert compare("1.0", "1.0.post1", "python") < 0

    def test_release_padding_equality(self):
        assert compare("1.0", "1.0.0", "python") == 0

    def test_epoch_dominates(self):
        assert compare("1!0.5", "2.0", "python") > 0

    def test_pep440_not_semver(self):
        # PEP 440 pre-release spellings are not SemVer; the semver
        # comparator rejects them rather than guessing.
        with pytest.raises(ValueError):
            compare("1.0rc1", "1.0", "semver")


class TestGo:
    def test_pseudo_versions_order_by_timestamp(self):
        assert compare("v0.0.0-20260101120000-abc", "v0.0.0-20260201120000-def") < 0

    def test_pseudo_version_below_patch_release(self):
        assert compare("v0.0.0-20260101120000-abc", "v0.0.1") < 0

    def test_incompatible_suffix_ignored(self):
        assert compare("v1.2.3+incompatible", "v1.2.3") == 0


class TestRPM:
    def test_release_comparison(self):
        assert compare("3.0.7-18.el9", "3.0.7-19.el9_1", "rpm") < 0

    def test_epoch_dominates(self):
        assert compare("1:1.0", "2:2.0", "rpm") < 0

    def test_numeric_segments_dominate_alphabetic(self):
        assert compare("1.10", "1.5a", "rpm") > 0
        assert compare("2.0", "2.0.1", "rpm") < 0

    def test_tilde_pre_release_sorts_first(self):
        assert compare("1.0~rc1", "1.0", "rpm") < 0

    def test_full_nevra(self):
        assert compare("openssl-3.0.7-18.el9", "3.0.7-19.el9_1", "rpm") < 0


class TestInRange:
    def test_less_than(self):
        assert in_range("1.2.3", "< 1.2.0") is False
        assert in_range("1.1.9", "< 1.2.0") is True

    def test_conjunction(self):
        assert in_range("1.5.0", ">= 1.0, < 2.0") is True
        assert in_range("2.5.0", ">= 1.0, < 2.0") is False

    def test_not_equal(self):
        assert in_range("1.2.5", "!= 1.2.5") is False

    def test_wildcard(self):
        assert in_range("1.2.9", "1.2.*") is True
        assert in_range("1.3.0", "1.2.*") is False

    def test_bare_version_is_exact(self):
        assert in_range("1.2.3", "1.2.3") is True
        assert in_range("1.2.4", "1.2.3") is False

    def test_empty_range_raises(self):
        with pytest.raises(ValueError):
            in_range("1.0.0", "  ")

    def test_ecosystem_routing(self):
        assert in_range("1.0rc1", "< 1.0", "python") is True
        assert in_range("3.0.7-18.el9", "< 3.0.7-19.el9_1", "rpm") is True


class TestFixes:
    def test_upgrade_reaches_fix(self):
        assert fixes("1.2.5", "1.2.4") is True

    def test_upgrade_below_fix(self):
        assert fixes("1.2.3", "1.2.4") is False


class TestVersionInRangeClaim:
    def test_prompt_case_refutes(self):
        # From the improvements prompt: range < 1.2.0, version 1.2.3.
        result = verify_version_in_range(
            _claim("VERSION_IN_RANGE", {"version": "1.2.3", "range": "< 1.2.0"}),
            "/tmp", "semver",
        )
        assert result.verdict == "REFUTED"
        assert result.verification_source == "version_compare"

    def test_in_range_verifies(self):
        result = verify_version_in_range(
            _claim("VERSION_IN_RANGE", {"version": "1.1.0", "range": "< 1.2.0"}),
            "/tmp", "semver",
        )
        assert result.verdict == "VERIFIED"

    def test_negated_claim(self):
        result = verify_version_in_range(
            _claim("VERSION_IN_RANGE", {
                "version": "1.2.3", "range": "< 1.2.0", "expected": False,
            }),
            "/tmp", "semver",
        )
        assert result.verdict == "VERIFIED"

    def test_missing_parameters_unverifiable(self):
        result = verify_version_in_range(
            _claim("VERSION_IN_RANGE", {"version": "1.2.3"}), "/tmp", "semver",
        )
        assert result.verdict == "UNVERIFIABLE"

    def test_unparsable_range_unverifiable(self):
        result = verify_version_in_range(
            _claim("VERSION_IN_RANGE", {"version": "1.2.3", "range": "garbage<<"}),
            "/tmp", "semver",
        )
        assert result.verdict == "UNVERIFIABLE"

    def test_ecosystem_from_params(self):
        result = verify_version_in_range(
            _claim("VERSION_IN_RANGE", {
                "version": "1.0rc1", "range": "< 1.0", "ecosystem": "pypi",
            }),
            "/tmp", "python",
        )
        assert result.verdict == "VERIFIED"


class TestUpgradeFixesClaim:
    def test_prompt_case_verifies(self):
        # From the improvements prompt: fixed 1.2.4, upgrade to 1.2.5.
        result = verify_upgrade_fixes(
            _claim("UPGRADE_FIXES", {"upgrade": "1.2.5", "fixed_in": "1.2.4"}),
            "/tmp", "semver",
        )
        assert result.verdict == "VERIFIED"
        assert result.verification_source == "version_compare"

    def test_rpm_backport_case_refutes(self):
        # From the improvements prompt: openssl-3.0.7-18.el9 vs fixed-in
        # 3.0.7-19.el9_1. The -18 release predates the fix.
        result = verify_upgrade_fixes(
            _claim("UPGRADE_FIXES", {
                "upgrade": "3.0.7-18.el9", "fixed_in": "3.0.7-19.el9_1",
                "ecosystem": "rpm",
            }),
            "/tmp", "c",
        )
        assert result.verdict == "REFUTED"

    def test_installed_context_in_evidence(self):
        result = verify_upgrade_fixes(
            _claim("UPGRADE_FIXES", {
                "upgrade": "1.2.5", "fixed_in": "1.2.4", "installed": "1.2.3",
            }),
            "/tmp", "semver",
        )
        assert result.verdict == "VERIFIED"
        assert "installed 1.2.3 is below the fix" in result.evidence

    def test_missing_fixed_in_unverifiable(self):
        result = verify_upgrade_fixes(
            _claim("UPGRADE_FIXES", {"upgrade": "1.2.5"}), "/tmp", "semver",
        )
        assert result.verdict == "UNVERIFIABLE"


class TestCveAffectsOffline:
    def test_range_present_uses_offline_comparison(self, monkeypatch):
        def no_network(*args, **kwargs):
            raise AssertionError("OSV API must not be called when a range is supplied")

        import urllib.request
        monkeypatch.setattr(urllib.request, "urlopen", no_network)
        result = verify_cve_affects(
            _claim("CVE_AFFECTS_VERSION", {
                "package": "requests", "version": "1.2.3",
                "cve": "CVE-2026-0001", "affected_range": "< 1.2.0",
                "ecosystem": "pypi",
            }),
            "/tmp", "python",
        )
        assert result.verdict == "REFUTED"
        assert result.method == "version_compare"
        assert result.verification_source == "version_compare"

    def test_no_range_uses_public_osv_assessment(self, monkeypatch):
        assessment = OsvAssessment(
            package="x",
            version="1.0",
            cve_id=None,
            vulnerability_count=0,
            vulnerability_ids=(),
            matching_cve=None,
            source_url="https://api.osv.dev/v1/query",
        )
        monkeypatch.setattr(
            "code_claim_verifier.verifiers.import_claims.fetch_osv_assessment",
            lambda package, version, cve_id=None, ecosystem=None: assessment,
        )
        result = verify_cve_affects(
            _claim("CVE_AFFECTS_VERSION", {"package": "x", "version": "1.0"}),
            "/tmp", "python",
        )
        assert result.method == "osv_api"


class TestOsvAssessment:
    def test_public_query_matches_cve_alias(self, monkeypatch):
        requests = []

        def fake_urlopen(request, timeout=None):
            requests.append(request)
            return io.BytesIO(json.dumps({
                "vulns": [{
                    "id": "GHSA-test-0001",
                    "aliases": ["CVE-2026-0001"],
                }],
            }).encode())

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        assessment = fetch_osv_assessment(
            "requests", "2.0.0", "CVE-2026-0001",
        )

        assert assessment.package == "requests"
        assert assessment.version == "2.0.0"
        assert assessment.cve_id == "CVE-2026-0001"
        assert assessment.vulnerability_count == 1
        assert assessment.vulnerability_ids == ("GHSA-test-0001",)
        assert assessment.matching_cve is True
        assert assessment.gap_reason is None
        assert requests[0].full_url == "https://api.osv.dev/v1/query"
        assert json.loads(requests[0].data) == {
            "package": {"name": "requests"}, "version": "2.0.0",
        }

    def test_empty_result_is_no_osv_match_not_unaffected(self, monkeypatch):
        monkeypatch.setattr(
            urllib.request,
            "urlopen",
            lambda request, timeout=None: io.BytesIO(b'{"vulns": []}'),
        )

        assessment = fetch_osv_assessment("requests", "2.0.0", "CVE-2026-0001")

        assert assessment.vulnerability_count == 0
        assert assessment.matching_cve is False
        assert assessment.gap_reason is None

    def test_query_error_returns_gap(self, monkeypatch):
        def fail(*args, **kwargs):
            raise OSError("offline")

        monkeypatch.setattr(urllib.request, "urlopen", fail)
        assessment = fetch_osv_assessment("requests", "2.0.0")

        assert assessment.matching_cve is None
        assert assessment.gap_reason == "osv_query_failed"
        assert assessment.error == "offline"

    def test_missing_parameters_do_not_query(self, monkeypatch):
        def fail(*args, **kwargs):
            raise AssertionError("OSV must not be queried without package and version")

        monkeypatch.setattr(urllib.request, "urlopen", fail)
        assessment = fetch_osv_assessment("", "2.0.0")

        assert assessment.matching_cve is None
        assert assessment.gap_reason == "missing_parameters"


class TestOsvEcosystemAndPagination:
    def test_ecosystem_forwarded_to_payload(self, monkeypatch):
        import io as _io
        import urllib.request

        requests = []

        def fake_urlopen(request, timeout=None):
            requests.append(request)
            return _io.BytesIO(b'{"vulns": []}')

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        import json as _json
        assessment = fetch_osv_assessment("pkg", "1.0", ecosystem="PyPI")
        assert assessment.gap_reason is None
        body = _json.loads(requests[0].data)
        assert body["package"] == {"name": "pkg", "ecosystem": "PyPI"}

    def test_pagination_followed(self, monkeypatch):
        import io as _io
        import urllib.request
        import json as _json

        pages = [
            {"vulns": [{"id": "GHSA-1"}], "next_page_token": "tok2"},
            {"vulns": [{"id": "GHSA-2", "aliases": ["CVE-2026-0001"]}]},
        ]
        calls = []

        def fake_urlopen(request, timeout=None):
            calls.append(_json.loads(request.data))
            return _io.BytesIO(_json.dumps(pages[len(calls) - 1]).encode())

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        assessment = fetch_osv_assessment("pkg", "1.0", cve_id="CVE-2026-0001")
        assert assessment.matching_cve is True
        assert assessment.vulnerability_ids == ("GHSA-1", "GHSA-2")
        assert calls[1].get("page_token") == "tok2"

    def test_verifier_forwards_claim_ecosystem(self, monkeypatch):
        captured = {}

        def fake_fetch(package, version, cve_id=None, ecosystem=None):
            captured["ecosystem"] = ecosystem
            return OsvAssessment(
                package=package, version=version, cve_id=cve_id,
                vulnerability_count=0, vulnerability_ids=(),
                matching_cve=None, source_url="x",
            )

        monkeypatch.setattr(
            "code_claim_verifier.verifiers.import_claims.fetch_osv_assessment",
            fake_fetch,
        )
        result = verify_cve_affects(
            _claim("CVE_AFFECTS_VERSION", {
                "package": "x", "version": "1.0", "ecosystem": "pypi",
            }),
            "/tmp", "python",
        )
        assert result.method == "osv_api"
        assert captured["ecosystem"] == "PyPI"
