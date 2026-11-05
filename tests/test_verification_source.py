"""Tests for VerifiedClaim.verification_source and its derivation."""
from __future__ import annotations

from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.verifiers import (
    VERIFICATION_SOURCES,
    derive_verification_source,
    safe_verify,
)


def _claim(claim_type: str, parameters: dict) -> TypedClaim:
    return TypedClaim(claim_type=claim_type, parameters=parameters, source_sentence="")


class TestDeriveVerificationSource:
    def test_lockfile_and_manifest_methods(self):
        assert derive_verification_source("lockfile_parse") == "lockfile"
        assert derive_verification_source("manifest_parse") == "manifest"

    def test_cpg_and_cymbal_prefixes(self):
        assert derive_verification_source("cpg_function") == "cpg"
        assert derive_verification_source("cpg_call_chain") == "cpg"
        assert derive_verification_source("cymbal_callers") == "cymbal"

    def test_grep_and_file_methods_are_source_code(self):
        for method in ("grep_import", "grep_call", "file_read", "file_scope",
                      "path_check", "schema", "config_flag", "default_value"):
            assert derive_verification_source(method) == "source_code", method

    def test_call_chain_maps_to_call_graph(self):
        assert derive_verification_source("call_chain") == "call_graph"

    def test_api_and_version_methods(self):
        assert derive_verification_source("osv_api") == "osv_api"
        assert derive_verification_source("version_compare") == "version_compare"

    def test_unknown_method(self):
        assert derive_verification_source("something_new") == "unknown"

    def test_vocabulary_is_closed(self):
        assert derive_verification_source("lockfile_parse") in VERIFICATION_SOURCES
        assert derive_verification_source("something_new") in VERIFICATION_SOURCES


class TestSafeVerifyDerivation:
    def test_lockfile_claim_gets_lockfile_source(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        result = safe_verify(
            _claim("PACKAGE_VERSION", {"package": "requests", "version": "2.31.0"}),
            str(tmp_path), "python",
        )
        assert result.verification_source == "lockfile"

    def test_file_claim_gets_source_code(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hi')\n")
        result = safe_verify(
            _claim("FILE_EXISTS", {"path": "main.py"}), str(tmp_path), "python",
        )
        assert result.verification_source == "source_code"

    def test_explicit_source_is_not_overridden(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hi')\n")
        claim = _claim("FILE_EXISTS", {"path": "main.py"})
        # Simulate a verifier that sets its own source.
        from code_claim_verifier.verifiers import VERIFIER_REGISTRY
        real = VERIFIER_REGISTRY["FILE_EXISTS"]

        def explicit(claim, repo_path, language):
            out = real(claim, repo_path, language)
            out.verification_source = "cpg"
            return out

        VERIFIER_REGISTRY["FILE_EXISTS"] = explicit
        try:
            result = safe_verify(claim, str(tmp_path), "python")
        finally:
            VERIFIER_REGISTRY["FILE_EXISTS"] = real
        assert result.verification_source == "cpg"


class TestEngineDerivation:
    def test_engine_verifies_with_source(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hi')\n")
        engine = VerificationEngine()
        results = engine.verify_claims(
            [_claim("FILE_EXISTS", {"path": "main.py"})], str(tmp_path), "python",
        )
        assert results[0].verification_source == "source_code"

    def test_unknown_type_still_gets_a_source(self, tmp_path):
        engine = VerificationEngine()
        results = engine.verify_claims(
            [_claim("NOT_A_TYPE", {})], str(tmp_path), "python",
        )
        assert results[0].verification_source in VERIFICATION_SOURCES


class TestReportSerialization:
    def test_to_dict_includes_sources(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        (tmp_path / "main.py").write_text("print('hi')\n")
        engine = VerificationEngine()
        results = engine.verify_claims(
            [
                _claim("FILE_EXISTS", {"path": "main.py"}),
                _claim("PACKAGE_VERSION", {"package": "requests", "version": "2.31.0"}),
            ],
            str(tmp_path), "python",
        )
        from code_claim_verifier.calibrator import calibrate

        report = calibrate(results)
        data = report.to_dict()
        assert data["verification_sources"] == {"source_code": 1, "lockfile": 1}
        sources = [c["verification_source"] for c in data["claims"]]
        assert sources == ["source_code", "lockfile"]

    def test_unset_source_serializes_as_none_per_claim(self):
        vc = VerifiedClaim(
            claim=_claim("FILE_EXISTS", {"path": "x"}),
            verdict="VERIFIED", method_confidence=0.9,
            evidence="", method="file_read",
        )
        assert vc.verification_source is None
