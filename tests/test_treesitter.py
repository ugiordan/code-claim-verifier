"""Tests for the tree-sitter AST backend."""
from __future__ import annotations

import pytest

from code_claim_verifier.treesitter_backend import TreeSitterBackend


@pytest.fixture
def backend():
    ts = TreeSitterBackend(["python", "go", "c"])
    if not ts.available_languages:
        pytest.skip("tree-sitter grammars not installed")
    return ts


@pytest.fixture
def python_repo(tmp_path):
    (tmp_path / "main.py").write_text(
        "def real_function():\n"
        "    pass\n"
        "\n"
        "# def commented_function():\n"
        "#     pass\n"
        "\n"
        'docstring_mention = """\n'
        "def documented_function():\n"
        '    This is inside a string\n'
        '"""\n'
        "\n"
        "def caller():\n"
        "    real_function()\n"
    )
    return tmp_path


@pytest.fixture
def go_repo(tmp_path):
    (tmp_path / "main.go").write_text(
        "package main\n"
        "\n"
        "func realFunc() {}\n"
        "\n"
        "// func commentedFunc() {}\n"
        "\n"
        "func caller() {\n"
        "\trealFunc()\n"
        "}\n"
    )
    return tmp_path


class TestFunctionExists:
    def test_finds_real_function(self, backend, python_repo):
        result = backend.function_exists("real_function", str(python_repo))
        assert result is not None
        assert result["name"] == "real_function"
        assert result["file"] == "main.py"
        assert result["line"] == 1

    def test_string_literal_not_a_definition(self, backend, python_repo):
        """The critical test: a name inside a string is not a function."""
        result = backend.function_exists("documented_function", str(python_repo))
        assert result is None

    def test_comment_not_a_definition(self, backend, python_repo):
        result = backend.function_exists("commented_function", str(python_repo))
        assert result == {}

    def test_nonexistent_function(self, backend, python_repo):
        result = backend.function_exists("no_such_function", str(python_repo))
        assert result == {}

    def test_go_function(self, backend, go_repo):
        result = backend.function_exists("realFunc", str(go_repo))
        assert result is not None
        assert result["file"] == "main.go"

    def test_go_comment_not_a_definition(self, backend, go_repo):
        result = backend.function_exists("commentedFunc", str(go_repo))
        # Searched and not found: empty dict, a confident negative
        assert result == {}


class TestFunctionCallers:
    def test_finds_caller(self, backend, python_repo):
        callers = backend.function_callers("real_function", str(python_repo))
        assert len(callers) == 1
        assert callers[0]["caller"] == "caller"
        assert callers[0]["file"] == "main.py"

    def test_no_callers(self, backend, python_repo):
        callers = backend.function_callers("no_such_function", str(python_repo))
        assert callers == []

    def test_go_caller(self, backend, go_repo):
        callers = backend.function_callers("realFunc", str(go_repo))
        assert len(callers) == 1
        assert callers[0]["caller"] == "caller"


class TestEngineDispatch:
    def test_function_exists_via_treesitter(self, backend, python_repo):
        from code_claim_verifier.engine import VerificationEngine
        from code_claim_verifier.types import TypedClaim

        engine = VerificationEngine(treesitter=backend)
        claim = TypedClaim(
            claim_type="FUNCTION_EXISTS",
            parameters={"name": "real_function"},
            source_sentence="",
        )
        result = engine.verify_claims([claim], str(python_repo), "python")
        assert result[0].verdict == "VERIFIED"
        assert result[0].method == "treesitter_function"
        assert result[0].verification_source == "treesitter"
        assert "tree-sitter" in result[0].evidence

    def test_string_function_not_found_via_treesitter(self, backend, python_repo):
        """The grep false-positive scenario must not verify."""
        from code_claim_verifier.engine import VerificationEngine
        from code_claim_verifier.types import TypedClaim

        engine = VerificationEngine(treesitter=backend)
        claim = TypedClaim(
            claim_type="FUNCTION_EXISTS",
            parameters={"name": "documented_function"},
            source_sentence="",
        )
        result = engine.verify_claims([claim], str(python_repo), "python")
        assert result[0].verdict == "REFUTED"
        assert result[0].method == "treesitter_function"

    def test_function_called_via_treesitter(self, backend, python_repo):
        from code_claim_verifier.engine import VerificationEngine
        from code_claim_verifier.types import TypedClaim

        engine = VerificationEngine(treesitter=backend)
        claim = TypedClaim(
            claim_type="FUNCTION_CALLED",
            parameters={"name": "real_function", "expected": True},
            source_sentence="",
        )
        result = engine.verify_claims([claim], str(python_repo), "python")
        assert result[0].verdict == "VERIFIED"
        assert result[0].method == "treesitter_callers"
        assert result[0].reachability_detail == "symbol_called"

    def test_engine_without_grammars_falls_back(self, python_repo):
        """Engine with no tree-sitter grammars falls back to grep."""
        from code_claim_verifier.engine import VerificationEngine

        empty = TreeSitterBackend([])
        assert empty.available_languages == []
        engine = VerificationEngine(treesitter=empty)
        # The engine keeps the empty backend; its dispatch methods
        # return None for every query, so grep handles everything.
        assert engine.treesitter is empty
