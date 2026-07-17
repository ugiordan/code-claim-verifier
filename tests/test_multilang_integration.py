from __future__ import annotations

import os

from eval.multilang.generate_gt import generate_verified_gt, generate_refuted_gt, validate_negatives

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "multilang_repo")


class TestGoGT:
    def test_verified_claims(self):
        src = os.path.join(FIXTURES, "go_project")
        claims = generate_verified_gt(src, "go")
        types = {c["claim_type"] for c in claims}
        assert "FILE_EXISTS" in types
        assert "FUNCTION_EXISTS" in types
        func_names = {c["parameters"]["name"] for c in claims if c["claim_type"] == "FUNCTION_EXISTS"}
        assert "handleRequest" in func_names or "processData" in func_names


class TestPythonGT:
    def test_verified_claims(self):
        src = os.path.join(FIXTURES, "python_project")
        claims = generate_verified_gt(src, "python")
        types = {c["claim_type"] for c in claims}
        assert "FILE_EXISTS" in types
        assert "FUNCTION_EXISTS" in types
        assert "IMPORT_EXISTS" in types
        modules = {c["parameters"]["module"] for c in claims if c["claim_type"] == "IMPORT_EXISTS"}
        assert "os" in modules
        assert "json" in modules


class TestJavaScriptGT:
    def test_verified_claims(self):
        src = os.path.join(FIXTURES, "js_project")
        claims = generate_verified_gt(src, "javascript")
        types = {c["claim_type"] for c in claims}
        assert "FILE_EXISTS" in types
        assert "FUNCTION_EXISTS" in types
        func_names = {c["parameters"]["name"] for c in claims if c["claim_type"] == "FUNCTION_EXISTS"}
        assert "handleAuth" in func_names or "parseToken" in func_names


class TestJavaGT:
    def test_verified_claims(self):
        src = os.path.join(FIXTURES, "java_project")
        claims = generate_verified_gt(src, "java")
        types = {c["claim_type"] for c in claims}
        assert "FILE_EXISTS" in types
        assert "FUNCTION_EXISTS" in types


class TestRustGT:
    def test_verified_claims(self):
        src = os.path.join(FIXTURES, "rust_project")
        claims = generate_verified_gt(src, "rust")
        types = {c["claim_type"] for c in claims}
        assert "FILE_EXISTS" in types
        assert "FUNCTION_EXISTS" in types
        func_names = {c["parameters"]["name"] for c in claims if c["claim_type"] == "FUNCTION_EXISTS"}
        assert "parse_request" in func_names or "validate_input" in func_names


class TestRefutedAndValidation:
    def test_refuted_across_languages(self):
        for lang, project in [("go", "go_project"), ("python", "python_project"),
                              ("javascript", "js_project"), ("rust", "rust_project")]:
            src = os.path.join(FIXTURES, project)
            verified = generate_verified_gt(src, lang)
            func_names = [c["parameters"]["name"] for c in verified if c["claim_type"] == "FUNCTION_EXISTS"]
            import_names = [c["parameters"]["module"] for c in verified if c["claim_type"] == "IMPORT_EXISTS"]
            files = [c["parameters"]["path"] for c in verified if c["claim_type"] == "FILE_EXISTS"]

            refuted = generate_refuted_gt(files, func_names, import_names, lang)
            assert len(refuted) > 0, f"No refuted claims for {lang}"
            assert all(c["expected_verdict"] == "REFUTED" for c in refuted)

            validated = validate_negatives(refuted, src, lang)
            assert len(validated) > 0, f"All refuted claims collided for {lang}"
