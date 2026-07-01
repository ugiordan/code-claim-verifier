"""Tests for code_claim_verifier.engine module."""
from __future__ import annotations

import os

import pytest

from code_claim_verifier.engine import VerificationEngine, _freeze
from code_claim_verifier.types import TypedClaim, VerifiedClaim

FIXTURE_REPO = os.path.join(os.path.dirname(__file__), "fixtures", "python_repo")


# ------------------------------------------------------------------
# _freeze helper
# ------------------------------------------------------------------

class TestFreeze:
    def test_flat_dict(self):
        result = _freeze({"a": 1})
        assert isinstance(result, frozenset)
        assert result == frozenset([("a", 1)])

    def test_nested_dict(self):
        result = _freeze({"a": {"b": 1}})
        assert isinstance(result, frozenset)
        inner = frozenset([("b", 1)])
        assert result == frozenset([("a", inner)])

    def test_list(self):
        result = _freeze([1, 2, 3])
        assert result == (1, 2, 3)

    def test_set(self):
        result = _freeze({1, 2})
        assert isinstance(result, frozenset)
        assert result == frozenset([1, 2])

    def test_depth_cap(self):
        """Deeply nested structure (25 levels) does not crash."""
        nested: object = 42
        for _ in range(25):
            nested = {"x": nested}
        result = _freeze(nested)
        # Just verify it returns without error and is hashable
        hash(result)


# ------------------------------------------------------------------
# Engine registry
# ------------------------------------------------------------------

class TestEngineRegistry:
    def test_default_registry_has_all_builtins(self):
        engine = VerificationEngine()
        expected = {
            "FILE_EXISTS", "LINE_CONTENT", "FILE_CLASSIFICATION",
            "GENERATED_OR_VENDORED", "FUNCTION_EXISTS", "FUNCTION_CALLED",
            "HAS_CALLERS", "IMPORT_EXISTS", "PACKAGE_VERSION",
            "DEPENDENCY_TYPE", "CVE_AFFECTS_VERSION", "ABSENCE",
            "MITIGATION_EXISTS", "ENTRY_POINT",
            "CALL_CHAIN", "DEFAULT_VALUE", "CONFIG_FLAG",
        }
        assert expected.issubset(set(engine.registry.keys()))

    def test_register_custom_type(self):
        engine = VerificationEngine()

        def custom_verifier(claim, repo_path, language):
            return VerifiedClaim(
                claim=claim, verdict="VERIFIED", method_confidence=1.0,
                evidence="custom", method="custom",
            )

        engine.register("CUSTOM_CHECK", custom_verifier)
        assert "CUSTOM_CHECK" in engine.registry

    def test_register_duplicate_raises(self):
        engine = VerificationEngine()

        def dummy(claim, repo_path, language):
            return VerifiedClaim(
                claim=claim, verdict="VERIFIED", method_confidence=1.0,
                evidence="", method="dummy",
            )

        with pytest.raises(ValueError, match="already registered"):
            engine.register("FILE_EXISTS", dummy)


# ------------------------------------------------------------------
# Engine verification (flat, with caching)
# ------------------------------------------------------------------

class TestEngineVerification:
    def test_verify_single_claim(self):
        engine = VerificationEngine()
        claim = TypedClaim(
            claim_type="FILE_EXISTS",
            parameters={"path": "main.py"},
            source_sentence="main.py exists",
        )
        results = engine.verify_claims([claim], FIXTURE_REPO, "python")
        assert len(results) == 1
        assert results[0].verdict == "VERIFIED"

    def test_verify_uses_cache(self):
        engine = VerificationEngine()
        claim_a = TypedClaim(
            claim_type="FILE_EXISTS",
            parameters={"path": "main.py"},
            source_sentence="main.py exists (first)",
        )
        claim_b = TypedClaim(
            claim_type="FILE_EXISTS",
            parameters={"path": "main.py"},
            source_sentence="main.py exists (second)",
        )
        results = engine.verify_claims([claim_a, claim_b], FIXTURE_REPO, "python")
        assert len(results) == 2
        # Both should have the same verdict
        assert results[0].verdict == results[1].verdict == "VERIFIED"

    def test_cached_result_is_independent_copy(self):
        engine = VerificationEngine()
        claim_a = TypedClaim(
            claim_type="FILE_EXISTS",
            parameters={"path": "main.py"},
            source_sentence="first",
        )
        claim_b = TypedClaim(
            claim_type="FILE_EXISTS",
            parameters={"path": "main.py"},
            source_sentence="second",
        )
        results = engine.verify_claims([claim_a, claim_b], FIXTURE_REPO, "python")
        # Mutate first result
        results[0].evidence = "MUTATED"
        # Second must be unaffected
        assert results[1].evidence != "MUTATED"


# ------------------------------------------------------------------
# Dependency resolution and SUSPECT propagation
# ------------------------------------------------------------------

class TestDependencyResolution:
    def test_synthesizes_missing_file_exists(self):
        engine = VerificationEngine()
        claim = TypedClaim(
            claim_type="LINE_CONTENT",
            parameters={"path": "main.py", "line": 1, "expected": "import os"},
            source_sentence="line 1 has import os",
        )
        results = engine.verify_claims_with_chaining([claim], FIXTURE_REPO, "python")
        # Should have synthesized a FILE_EXISTS claim
        synth = [r for r in results if r.synthesized]
        assert len(synth) == 1
        assert synth[0].claim.claim_type == "FILE_EXISTS"
        assert synth[0].synthesized is True

    def test_refuted_dep_marks_dependent_suspect(self):
        engine = VerificationEngine()
        claim = TypedClaim(
            claim_type="LINE_CONTENT",
            parameters={"path": "nonexistent.py", "line": 1, "expected": "x"},
            source_sentence="line 1 of nonexistent.py",
        )
        results = engine.verify_claims_with_chaining([claim], FIXTURE_REPO, "python")
        line_content = [r for r in results if r.claim.claim_type == "LINE_CONTENT"][0]
        assert line_content.suspect_reason is not None
        assert "REFUTED" in line_content.suspect_reason

    def test_verified_dep_no_suspect(self):
        engine = VerificationEngine()
        file_claim = TypedClaim(
            claim_type="FILE_EXISTS",
            parameters={"path": "main.py"},
            source_sentence="main.py exists",
        )
        line_claim = TypedClaim(
            claim_type="LINE_CONTENT",
            parameters={"path": "main.py", "line": 1, "expected": "import os"},
            source_sentence="line 1 has import os",
        )
        results = engine.verify_claims_with_chaining(
            [file_claim, line_claim], FIXTURE_REPO, "python"
        )
        line_result = [r for r in results if r.claim.claim_type == "LINE_CONTENT"][0]
        assert line_result.suspect_reason is None

    def test_no_duplicate_synthesized(self):
        engine = VerificationEngine()
        claim_lc = TypedClaim(
            claim_type="LINE_CONTENT",
            parameters={"path": "main.py", "line": 1, "expected": "import os"},
            source_sentence="line 1",
        )
        claim_gov = TypedClaim(
            claim_type="GENERATED_OR_VENDORED",
            parameters={"path": "main.py"},
            source_sentence="is it generated?",
        )
        results = engine.verify_claims_with_chaining(
            [claim_lc, claim_gov], FIXTURE_REPO, "python"
        )
        synth = [r for r in results if r.synthesized]
        # Both LINE_CONTENT and GENERATED_OR_VENDORED depend on FILE_EXISTS
        # for the same path, so only one should be synthesized
        assert len(synth) == 1
        assert synth[0].claim.claim_type == "FILE_EXISTS"

    def test_any_match_semantics(self):
        """FUNCTION_CALLED is not suspect when at least one FUNCTION_EXISTS
        prereq is VERIFIED (even if others are REFUTED)."""
        engine = VerificationEngine()

        # Explicitly provide two FUNCTION_EXISTS claims for the same name
        # "load_model": one in main.py (will be VERIFIED), one in
        # nonexistent.py (will be REFUTED)
        fe_good = TypedClaim(
            claim_type="FUNCTION_EXISTS",
            parameters={"name": "load_model", "file": "main.py"},
            source_sentence="load_model in main.py",
        )
        fe_bad = TypedClaim(
            claim_type="FUNCTION_EXISTS",
            parameters={"name": "load_model", "file": "nonexistent.py"},
            source_sentence="load_model in nonexistent.py",
        )
        fc = TypedClaim(
            claim_type="FUNCTION_CALLED",
            parameters={"name": "load_model"},
            source_sentence="load_model is called",
        )

        # Manually wire edges so both FUNCTION_EXISTS are prereqs of FUNCTION_CALLED
        results = engine.verify_claims_with_chaining(
            [fe_good, fe_bad, fc], FIXTURE_REPO, "python"
        )

        fc_result = [r for r in results if r.claim.claim_type == "FUNCTION_CALLED"][0]
        # ANY-match: fe_good is VERIFIED, so fc should NOT be suspect
        assert fc_result.suspect_reason is None

    def test_cycle_detection_custom_deps(self):
        engine = VerificationEngine()
        # A -> B already exists (FUNCTION_CALLED -> FUNCTION_EXISTS)
        # Try adding B -> A, which should create a cycle
        with pytest.raises(ValueError, match="cycle"):
            engine.register_dependency(
                "FUNCTION_EXISTS", "FUNCTION_CALLED", "name", "name"
            )
