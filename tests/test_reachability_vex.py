"""Tests for presence-vs-reachability and the VEX claim type."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier import VexAssessment, fetch_redhat_vex_assessment
from code_claim_verifier.types import TypedClaim
from code_claim_verifier.verifiers import safe_verify
from code_claim_verifier.verifiers.vex_claims import VEX_BASE_URL, clear_vex_cache


def _claim(claim_type: str, parameters: dict) -> TypedClaim:
    return TypedClaim(claim_type=claim_type, parameters=parameters, source_sentence="")


class TestReachabilityDetailField:
    def test_function_called_populates_symbol_called(self, tmp_path):
        (tmp_path / "main.py").write_text(
            "def handler():\n    pass\n\ndef caller():\n    handler()\n"
        )
        result = safe_verify(
            _claim("FUNCTION_CALLED", {"name": "handler", "expected": True}),
            str(tmp_path), "python",
        )
        assert result.verdict == "VERIFIED"
        assert result.reachability_detail == "symbol_called"

    def test_function_called_populates_no_call_sites(self, tmp_path):
        (tmp_path / "main.py").write_text(
            "def handler():\n    pass\n"
        )
        result = safe_verify(
            _claim("FUNCTION_CALLED", {"name": "handler", "expected": False}),
            str(tmp_path), "python",
        )
        assert result.verdict == "VERIFIED"
        assert result.reachability_detail == "no_call_sites"

    def test_has_callers_populates_detail(self, tmp_path):
        (tmp_path / "app.js").write_text(
            "function handler() {}\nconst x = handler();\n"
        )
        result = safe_verify(
            _claim("HAS_CALLERS", {"name": "handler"}), str(tmp_path), "javascript",
        )
        assert result.verdict == "VERIFIED"
        assert result.reachability_detail == "symbol_called"

    def test_function_exists_leaves_detail_none(self, tmp_path):
        (tmp_path / "main.py").write_text("def handler():\n    pass\n")
        result = safe_verify(
            _claim("FUNCTION_EXISTS", {"name": "handler"}), str(tmp_path), "python",
        )
        assert result.verdict == "VERIFIED"
        assert result.reachability_detail is None

    def test_to_dict_includes_reachability_detail(self, tmp_path):
        (tmp_path / "main.py").write_text(
            "def handler():\n    pass\n\ndef caller():\n    handler()\n"
        )
        engine = VerificationEngine()
        results = engine.verify_claims(
            [_claim("FUNCTION_CALLED", {"name": "handler"})], str(tmp_path), "python",
        )
        from code_claim_verifier.calibrator import calibrate
        data = calibrate(results).to_dict()
        assert data["claims"][0]["reachability_detail"] == "symbol_called"


class TestVulnerableSymbolCalled:
    def test_symbol_called_verifies(self, tmp_path):
        repo = tmp_path
        (repo / "requirements.txt").write_text("vulnpkg==1.2.3\n")
        (repo / "main.py").write_text(
            "import vulnpkg\nvulnpkg.vulnerable_symbol(x)\n"
        )
        result = safe_verify(
            _claim("VULNERABLE_SYMBOL_CALLED", {
                "function": "vulnerable_symbol", "package": "vulnpkg",
            }),
            str(repo), "python",
        )
        assert result.verdict == "VERIFIED"
        assert result.reachability_detail == "symbol_called"
        assert "vulnpkg" in result.evidence

    def test_package_imported_but_symbol_not_called(self, tmp_path):
        repo = tmp_path
        (repo / "requirements.txt").write_text("vulnpkg==1.2.3\n")
        (repo / "main.py").write_text("import vulnpkg\n")
        result = safe_verify(
            _claim("VULNERABLE_SYMBOL_CALLED", {
                "function": "vulnerable_symbol", "package": "vulnpkg",
            }),
            str(repo), "python",
        )
        assert result.verdict == "REFUTED"
        assert result.reachability_detail == "package_imported"
        assert "presence, not reachability" in result.evidence

    def test_no_imports_and_no_call_sites(self, tmp_path):
        repo = tmp_path
        (repo / "requirements.txt").write_text("vulnpkg==1.2.3\n")
        (repo / "main.py").write_text("def unrelated():\n    pass\n")
        result = safe_verify(
            _claim("VULNERABLE_SYMBOL_CALLED", {
                "function": "vulnerable_symbol", "package": "vulnpkg",
            }),
            str(repo), "python",
        )
        assert result.verdict == "REFUTED"
        assert result.reachability_detail == "no_call_sites"

    def test_package_absent_from_lockfiles_refutes(self, tmp_path):
        repo = tmp_path
        (repo / "requirements.txt").write_text("otherpkg==1.0.0\n")
        (repo / "main.py").write_text("import otherpkg\n")
        result = safe_verify(
            _claim("VULNERABLE_SYMBOL_CALLED", {
                "function": "vulnerable_symbol", "package": "vulnpkg",
            }),
            str(repo), "python",
        )
        assert result.verdict == "REFUTED"
        assert "does not ship" in result.evidence

    def test_no_lockfiles_is_inconclusive_not_refutation(self, tmp_path):
        repo = tmp_path
        (repo / "main.py").write_text("import vulnpkg\n")
        result = safe_verify(
            _claim("VULNERABLE_SYMBOL_CALLED", {
                "function": "vulnerable_symbol", "package": "vulnpkg",
            }),
            str(repo), "python",
        )
        # No lockfiles: the lockfile gate is inconclusive, analysis
        # continues on imports and call sites.
        assert "inconclusive" in result.evidence
        assert result.reachability_detail == "package_imported"

    def test_negated_claim(self, tmp_path):
        repo = tmp_path
        (repo / "requirements.txt").write_text("vulnpkg==1.2.3\n")
        (repo / "main.py").write_text("import vulnpkg\n")
        result = safe_verify(
            _claim("VULNERABLE_SYMBOL_CALLED", {
                "function": "vulnerable_symbol", "package": "vulnpkg",
                "expected": False,
            }),
            str(repo), "python",
        )
        assert result.verdict == "VERIFIED"  # correctly claims NOT called
        assert result.reachability_detail == "package_imported"

    def test_missing_parameters_unverifiable(self, tmp_path):
        result = safe_verify(
            _claim("VULNERABLE_SYMBOL_CALLED", {"function": "x"}),
            str(tmp_path), "python",
        )
        assert result.verdict == "UNVERIFIABLE"


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _csaf(statuses: dict, flags: list | None = None) -> bytes:
    return json.dumps({
        "document": {"title": "t"},
        "vulnerabilities": [{
            "cve": "CVE-2026-1234",
            "product_status": statuses,
            "flags": flags or [],
        }],
    }).encode()


_PREFIX = "red_hat_enterprise_linux_9"
_ARGS = {
    "cve_id": "CVE-2026-1234",
    "expected_status": "known_not_affected",
    "product_prefix": _PREFIX,
    "component": "ncurses-libs",
}


class TestRedhatVexStatus:
    def setup_method(self):
        clear_vex_cache()

    def _install(self, monkeypatch, response):
        def fake_urlopen(request, timeout=None):
            if isinstance(response, Exception):
                raise response
            return _FakeResponse(response)
        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    def test_public_assessment_returns_structured_match(self, monkeypatch):
        document = _csaf(
            {"known_not_affected": [f"{_PREFIX}:ncurses-libs"]},
            flags=[{"label": "component_not_present",
                    "product_ids": [f"{_PREFIX}:ncurses-libs"]}],
        )
        self._install(monkeypatch, document)

        assessment = fetch_redhat_vex_assessment(
            "CVE-2026-1234", _PREFIX, "ncurses-libs",
        )

        assert isinstance(assessment, VexAssessment)
        assert assessment.cve_id == "CVE-2026-1234"
        assert assessment.requested_product_id == f"{_PREFIX}:ncurses-libs"
        assert assessment.status == "known_not_affected"
        assert assessment.justification == "component_not_present"
        assert assessment.product_id == f"{_PREFIX}:ncurses-libs"
        assert assessment.match_quality == "exact"
        assert assessment.gap_reason is None
        assert assessment.source_url == (
            f"{VEX_BASE_URL}/2026/cve-2026-1234.json"
        )

    def test_public_assessment_reports_ambiguous_product(self, monkeypatch):
        self._install(
            monkeypatch,
            _csaf({"known_not_affected": ["red_hat_enterprise_linux_8:ncurses-libs"]}),
        )

        assessment = fetch_redhat_vex_assessment(
            "CVE-2026-1234", _PREFIX, "ncurses-libs",
        )

        assert assessment.status is None
        assert assessment.product_id is None
        assert assessment.match_quality == "ambiguous"
        assert assessment.gap_reason == "component_under_different_product_prefix"
        assert assessment.other_product_prefixes == ("red_hat_enterprise_linux_8",)

    def test_public_assessment_reports_missing_document(self, monkeypatch):
        self._install(
            monkeypatch,
            urllib.error.HTTPError("u", 404, "Not Found", None, None),
        )

        assessment = fetch_redhat_vex_assessment(
            "CVE-2026-1234", _PREFIX, "ncurses-libs",
        )

        assert assessment.match_quality == "unavailable"
        assert assessment.gap_reason == "no_vex_document"
        assert assessment.source_url is not None

    def test_exact_match_with_justification_verifies(self, monkeypatch, tmp_path):
        document = _csaf(
            {"known_not_affected": [f"{_PREFIX}:ncurses-libs",
                                    "red_hat_enterprise_linux_8:curl"]},
            flags=[{"label": "component_not_present",
                    "product_ids": [f"{_PREFIX}:ncurses-libs"]}],
        )
        self._install(monkeypatch, document)
        result = safe_verify(_claim("REDHAT_VEX_STATUS", _ARGS), str(tmp_path), "go")
        assert result.verdict == "VERIFIED"
        assert "component_not_present" in result.evidence
        # Cross-component entries are noted, not fatal.
        assert "2 products" in result.evidence

    def test_wrong_status_refutes(self, monkeypatch, tmp_path):
        document = _csaf({"known_affected": [f"{_PREFIX}:ncurses-libs"]})
        self._install(monkeypatch, document)
        result = safe_verify(_claim("REDHAT_VEX_STATUS", _ARGS), str(tmp_path), "go")
        assert result.verdict == "REFUTED"
        assert "known_affected, not known_not_affected" in result.evidence

    def test_known_not_affected_without_justification_refutes(self, monkeypatch, tmp_path):
        document = _csaf({"known_not_affected": [f"{_PREFIX}:ncurses-libs"]})
        self._install(monkeypatch, document)
        result = safe_verify(_claim("REDHAT_VEX_STATUS", _ARGS), str(tmp_path), "go")
        assert result.verdict == "REFUTED"
        assert "without a justification" in result.evidence

    def test_component_only_under_other_prefix_is_ambiguous(self, monkeypatch, tmp_path):
        document = _csaf(
            {"known_not_affected": ["red_hat_enterprise_linux_8:ncurses-libs"]},
        )
        self._install(monkeypatch, document)
        result = safe_verify(_claim("REDHAT_VEX_STATUS", _ARGS), str(tmp_path), "go")
        assert result.verdict == "UNVERIFIABLE"
        assert "AMBIGUOUS_VEX_PRODUCT" in result.evidence
        assert "red_hat_enterprise_linux_8" in result.evidence

    def test_no_entry_for_component_refutes(self, monkeypatch, tmp_path):
        document = _csaf({"known_affected": [f"{_PREFIX}:curl"]})
        self._install(monkeypatch, document)
        result = safe_verify(_claim("REDHAT_VEX_STATUS", _ARGS), str(tmp_path), "go")
        assert result.verdict == "REFUTED"
        assert "no VEX entry" in result.evidence

    def test_network_unreachable_is_unverifiable(self, monkeypatch, tmp_path):
        self._install(monkeypatch, urllib.error.URLError("no route"))
        result = safe_verify(_claim("REDHAT_VEX_STATUS", _ARGS), str(tmp_path), "go")
        assert result.verdict == "UNVERIFIABLE"
        assert "unreachable" in result.evidence

    def test_missing_document_refutes(self, monkeypatch, tmp_path):
        self._install(
            monkeypatch, urllib.error.HTTPError("u", 404, "Not Found", None, None),
        )
        result = safe_verify(_claim("REDHAT_VEX_STATUS", _ARGS), str(tmp_path), "go")
        assert result.verdict == "UNVERIFIABLE"
        assert "no VEX document" in result.evidence

    def test_document_cache_avoids_refetch(self, monkeypatch, tmp_path):
        calls = []

        def fake_urlopen(request, timeout=None):
            calls.append(request.full_url)
            return _FakeResponse(_csaf(
                {"known_affected": [f"{_PREFIX}:ncurses-libs"]},
            ))

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        args = dict(_ARGS, expected_status="known_affected")
        first = safe_verify(_claim("REDHAT_VEX_STATUS", args), str(tmp_path), "go")
        second = safe_verify(_claim("REDHAT_VEX_STATUS", args), str(tmp_path), "go")
        assert len(calls) == 1
        assert first.verdict == "VERIFIED"
        assert second.verdict == "VERIFIED"

    def test_missing_parameters_unverifiable(self, tmp_path):
        result = safe_verify(
            _claim("REDHAT_VEX_STATUS", {"cve_id": "CVE-2026-1234"}),
            str(tmp_path), "go",
        )
        assert result.verdict == "UNVERIFIABLE"

    def test_verification_source_is_vex_api(self, monkeypatch, tmp_path):
        document = _csaf({"known_affected": [f"{_PREFIX}:ncurses-libs"]})
        self._install(monkeypatch, document)
        result = safe_verify(
            _claim("REDHAT_VEX_STATUS", dict(_ARGS, expected_status="known_affected")),
            str(tmp_path), "go",
        )
        assert result.verification_source == "vex_api"
