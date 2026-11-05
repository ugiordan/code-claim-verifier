from __future__ import annotations

from code_claim_verifier.types import TypedClaim
from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.verifiers.auth_claims import (
    verify_call_chain,
    verify_config_flag,
    verify_default_value,
)
from code_claim_verifier.verifiers.file_claims import (
    verify_file_classification,
    verify_file_exists,
    verify_generated_or_vendored,
    verify_line_content,
)
from code_claim_verifier.verifiers.import_claims import (
    _parse_go_mod,
    verify_import_exists,
    verify_package_version,
)
from code_claim_verifier.verifiers.security_claims import (
    verify_absence,
    verify_entry_point,
    verify_mitigation_exists,
)
from code_claim_verifier.verifiers.symbol_claims import verify_function_exists


def _claim(claim_type: str, parameters: dict) -> TypedClaim:
    return TypedClaim(claim_type=claim_type, parameters=parameters, source_sentence="")


def test_javascript_function_exists_ignores_calls_and_keeps_assignments(tmp_path):
    source = tmp_path / "app.js"
    source.write_text(
        'app.get("/", handler);\n'
        "function handler() {}\n"
        "const arrowHandler = (request) => request;\n"
        "let functionHandler = function (request) { return request; };\n"
        "var asyncHandler = async request => request;\n"
    )

    ordinary_call = verify_function_exists(
        _claim("FUNCTION_EXISTS", {"name": "get", "file": "app.js"}),
        str(tmp_path), "javascript",
    )
    assert ordinary_call.verdict == "REFUTED"

    for name in ("handler", "arrowHandler", "functionHandler", "asyncHandler"):
        result = verify_function_exists(
            _claim("FUNCTION_EXISTS", {"name": name, "file": "app.js"}),
            str(tmp_path), "javascript",
        )
        assert result.verdict == "VERIFIED", name


def test_javascript_named_function_expressions_and_methods(tmp_path):
    source = tmp_path / "app.js"
    source.write_text(
        "const assigned = function namedImplementation() {};\n"
        "class Service { run() { return true; } }\n"
        "const routes = { handle(request) { return request; } };\n"
    )
    for name in ("assigned", "run", "handle"):
        result = verify_function_exists(
            _claim("FUNCTION_EXISTS", {"name": name, "file": "app.js"}),
            str(tmp_path), "javascript",
        )
        assert result.verdict == "VERIFIED", name


def test_scoped_function_and_import_do_not_search_the_repository(tmp_path):
    (tmp_path / "present.py").write_text("import os\ndef target(): pass\n")

    function_result = verify_function_exists(
        _claim("FUNCTION_EXISTS", {"name": "target", "file": "missing.py"}),
        str(tmp_path), "python",
    )
    import_result = verify_import_exists(
        _claim("IMPORT_EXISTS", {"module": "os", "file": "missing.py"}),
        str(tmp_path), "python",
    )

    assert function_result.verdict == "REFUTED"
    assert "missing.py" in function_result.evidence
    assert import_result.verdict == "REFUTED"
    assert "missing.py" in import_result.evidence


def test_missing_required_symbol_parameters_are_unverifiable(tmp_path):
    function_result = verify_function_exists(
        _claim("FUNCTION_EXISTS", {"file": "present.py"}), str(tmp_path), "python",
    )
    import_result = verify_import_exists(
        _claim("IMPORT_EXISTS", {"file": "present.py"}), str(tmp_path), "python",
    )
    assert function_result.verdict == "UNVERIFIABLE"
    assert import_result.verdict == "UNVERIFIABLE"


def test_line_zero_is_not_a_false_refutation(tmp_path):
    (tmp_path / "main.py").write_text("def validate_token():\n    return True\n")
    result = verify_line_content(
        _claim("LINE_CONTENT", {
            "path": "main.py", "line": 0, "content": "def validate_token",
        }), str(tmp_path), "python",
    )
    assert result.verdict == "UNVERIFIABLE"


def test_descriptive_function_names_are_not_refuted(tmp_path):
    (tmp_path / "main.py").write_text("def validate_token():\n    return True\n")
    result = verify_function_exists(
        _claim("FUNCTION_EXISTS", {"name": "the function that validates tokens"}),
        str(tmp_path), "python",
    )
    assert result.verdict == "UNVERIFIABLE"
    single_word = verify_function_exists(
        _claim("FUNCTION_EXISTS", {"name": "function"}), str(tmp_path), "python",
    )
    assert single_word.verdict == "UNVERIFIABLE"


def test_file_fuzzy_lookup_is_bare_name_only_and_path_safe(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "target.py").write_text("# AUTO-GENERATED\nexpected = True\n")

    assert verify_file_exists(
        _claim("FILE_EXISTS", {"path": "target.py"}), str(tmp_path), "python",
    ).verdict == "VERIFIED"
    assert verify_line_content(
        _claim("LINE_CONTENT", {"path": "target.py", "line": 2, "expected": "expected"}),
        str(tmp_path), "python",
    ).verdict == "VERIFIED"
    assert verify_generated_or_vendored(
        _claim("GENERATED_OR_VENDORED", {"path": "target.py", "expected": True}),
        str(tmp_path), "python",
    ).verdict == "VERIFIED"

    scoped_miss = verify_file_exists(
        _claim("FILE_EXISTS", {"path": "other/target.py"}), str(tmp_path), "python",
    )
    traversal = verify_file_exists(
        _claim("FILE_EXISTS", {"path": "../target.py"}), str(tmp_path), "python",
    )
    assert scoped_miss.verdict == "REFUTED"
    assert traversal.verdict == "REFUTED"


def test_normalized_parent_path_cannot_enable_basename_fallback(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "target.py").write_text("value = True\n")
    result = verify_file_exists(
        _claim("FILE_EXISTS", {"path": "missing/../target.py"}),
        str(tmp_path), "python",
    )
    assert result.verdict == "REFUTED"


def test_fuzzy_lookup_rejects_external_symlink_candidates(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("# AUTO-GENERATED\nsecret = True\n")
    (repo / "outside.py").symlink_to(outside)

    claims = [
        verify_file_exists(_claim("FILE_EXISTS", {"path": "outside.py"}), str(repo), "python"),
        verify_line_content(
            _claim("LINE_CONTENT", {"path": "outside.py", "line": 2, "expected": "secret"}),
            str(repo), "python",
        ),
        verify_generated_or_vendored(
            _claim("GENERATED_OR_VENDORED", {"path": "outside.py", "expected": True}),
            str(repo), "python",
        ),
    ]
    assert all(result.verdict == "REFUTED" for result in claims)


def test_file_classification_requires_an_existing_file(tmp_path):
    result = verify_file_classification(
        _claim("FILE_CLASSIFICATION", {"path": "missing.py", "category": "production"}),
        str(tmp_path), "python",
    )
    invalid = verify_file_classification(
        _claim("FILE_CLASSIFICATION", {"path": "../missing.py", "category": "production"}),
        str(tmp_path), "python",
    )
    assert result.verdict == "UNVERIFIABLE"
    assert invalid.verdict == "UNVERIFIABLE"


def test_absence_scope_never_widens_to_repository(tmp_path):
    (tmp_path / "present.py").write_text("dangerous_call()\n")
    missing_file = verify_absence(
        _claim("ABSENCE", {"pattern": "dangerous_call", "scope": "file", "file": "missing.py"}),
        str(tmp_path), "python",
    )
    missing_directory = verify_absence(
        _claim("ABSENCE", {"pattern": "dangerous_call", "scope": "directory", "directory": "missing"}),
        str(tmp_path), "python",
    )
    assert missing_file.verdict == "UNVERIFIABLE"
    assert missing_directory.verdict == "UNVERIFIABLE"


def test_descriptive_absence_patterns_are_not_treated_as_literal_evidence(tmp_path):
    (tmp_path / "present.py").write_text("def validate(value):\n    return value\n")
    result = verify_absence(
        _claim("ABSENCE", {"pattern": "there is no input validation", "scope": "repo"}),
        str(tmp_path), "python",
    )
    assert result.verdict == "UNVERIFIABLE"
    single_word = verify_absence(
        _claim("ABSENCE", {"pattern": "authentication", "scope": "repo"}),
        str(tmp_path), "python",
    )
    assert single_word.verdict == "UNVERIFIABLE"


def test_call_chain_checks_the_caller_body_only(tmp_path):
    (tmp_path / "chain.go").write_text(
        "package chain\n"
        "func Caller() bool { return true }\n"
        "func Other() bool { return Target() }\n"
        "func Target() bool { return true }\n"
    )
    result = verify_call_chain(
        _claim("CALL_CHAIN", {"chain": ["Caller", "Target"]}), str(tmp_path), "go",
    )
    assert result.verdict == "REFUTED"
    assert "Caller does not call Target" in result.evidence


def test_call_chain_accepts_opening_brace_on_next_line(tmp_path):
    (tmp_path / "chain.c").write_text(
        "int caller(void)\n"
        "{\n"
        "    return callee();\n"
        "}\n"
        "int callee(void) { return 1; }\n"
    )
    result = verify_call_chain(
        _claim("CALL_CHAIN", {"chain": ["caller", "callee"]}), str(tmp_path), "c",
    )
    assert result.verdict == "VERIFIED"


def test_descriptive_call_chain_names_are_not_refuted(tmp_path):
    result = verify_call_chain(
        _claim("CALL_CHAIN", {
            "chain": ["the function that validates tokens", "Authorize"],
        }), str(tmp_path), "go",
    )
    assert result.verdict == "UNVERIFIABLE"


def test_cpg_negative_call_chain_falls_back_to_source_body(tmp_path):
    (tmp_path / "chain.go").write_text(
        "package chain\n"
        "func Caller() bool { return Callee() }\n"
        "func Callee() bool { return true }\n"
    )

    class EmptyCpg:
        def call_chain_exists(self, _chain):
            return False, []

    result = VerificationEngine(cpg=EmptyCpg()).verify_claims(
        [_claim("CALL_CHAIN", {"chain": ["Caller", "Callee"]})],
        str(tmp_path), "go",
    )[0]
    assert result.verdict == "VERIFIED"


def test_non_object_parameters_are_unverifiable(tmp_path):
    result = VerificationEngine().verify_claims(
        [TypedClaim(
            claim_type="FILE_EXISTS", parameters="main.py", source_sentence="",
        )],
        str(tmp_path), "python",
    )[0]
    assert result.verdict == "UNVERIFIABLE"


def test_mitigation_requires_a_concrete_pattern(tmp_path):
    (tmp_path / "handler.go").write_text("package handler\nfunc check() { return false }\n")
    no_pattern = verify_mitigation_exists(
        _claim("MITIGATION_EXISTS", {"file": "handler.go", "line": 2}),
        str(tmp_path), "go",
    )
    with_pattern = verify_mitigation_exists(
        _claim("MITIGATION_EXISTS", {"file": "handler.go", "line": 2, "pattern": "return false"}),
        str(tmp_path), "go",
    )
    assert no_pattern.verdict == "UNVERIFIABLE"
    assert with_pattern.verdict == "VERIFIED"


def test_entry_point_respects_explicit_file_and_location(tmp_path):
    (tmp_path / "other.go").write_text('package main\nfunc init() { http.HandleFunc("/", handler) }\n')
    (tmp_path / "target.go").write_text("package main\nfunc handler() {}\n")

    scoped = verify_entry_point(
        _claim("ENTRY_POINT", {"location": "target.go", "type": "http"}),
        str(tmp_path), "go",
    )
    missing = verify_entry_point(
        _claim("ENTRY_POINT", {"location": "missing.go", "type": "http"}),
        str(tmp_path), "go",
    )
    assert scoped.verdict == "REFUTED"
    assert missing.verdict == "UNVERIFIABLE"
    assert "missing.go" in missing.evidence


def test_default_value_needs_behavior_evidence_and_honors_file_scope(tmp_path):
    (tmp_path / "behavior.go").write_text(
        "package config\n"
        "func check(values []string) bool {\n"
        "    if len(values) == 0 { return false }\n"
        "    return true\n"
        "}\n"
    )
    (tmp_path / "declaration.go").write_text("package config\nvar values []string\n")

    behavior = verify_default_value(
        _claim("DEFAULT_VALUE", {"variable": "values", "file": "behavior.go", "default_behavior": "deny"}),
        str(tmp_path), "go",
    )
    declaration_only = verify_default_value(
        _claim("DEFAULT_VALUE", {"variable": "values", "file": "declaration.go", "default_behavior": "deny"}),
        str(tmp_path), "go",
    )
    assert behavior.verdict == "VERIFIED"
    assert declaration_only.verdict == "UNVERIFIABLE"


def test_default_value_does_not_use_a_neighboring_function_return(tmp_path):
    (tmp_path / "neighbors.go").write_text(
        "package config\n"
        "func check(values []string) bool {\n"
        "    if len(values) == 0 {\n"
        "        log(values)\n"
        "    }\n"
        "    return allow(values)\n"
        "}\n"
        "func unrelated() bool {\n"
        "    return false\n"
        "}\n"
    )
    result = verify_default_value(
        _claim("DEFAULT_VALUE", {
            "variable": "values", "file": "neighbors.go", "default_behavior": "deny",
        }), str(tmp_path), "go",
    )
    assert result.verdict == "UNVERIFIABLE"


def test_config_flag_honors_scope_and_explicit_file(tmp_path):
    (tmp_path / "settings.yaml").write_text("enable_feature: true\n")
    (tmp_path / "code.go").write_text("package settings\n")

    manifest = verify_config_flag(
        _claim("CONFIG_FLAG", {"flag": "enable_feature", "value": "true", "scope": "manifests"}),
        str(tmp_path), "go",
    )
    code = verify_config_flag(
        _claim("CONFIG_FLAG", {"flag": "enable_feature", "value": "true", "scope": "code"}),
        str(tmp_path), "go",
    )
    invalid_file = verify_config_flag(
        _claim("CONFIG_FLAG", {"flag": "enable_feature", "file": "missing.yaml"}),
        str(tmp_path), "go",
    )
    wrong_file_scope = verify_config_flag(
        _claim("CONFIG_FLAG", {
            "flag": "enable_feature", "file": "settings.yaml", "scope": "code",
        }), str(tmp_path), "go",
    )
    assert manifest.verdict == "VERIFIED"
    assert code.verdict == "REFUTED"
    assert invalid_file.verdict == "UNVERIFIABLE"
    assert wrong_file_scope.verdict == "REFUTED"


def test_go_mod_parser_ignores_inline_comments_and_compares_versions_exactly(tmp_path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        "module example\n"
        "require github.com/example/tool v1.2.3 // indirect\n"
    )
    assert _parse_go_mod(str(go_mod), "github.com/example/tool") == "1.2.3"

    verified = verify_package_version(
        _claim("PACKAGE_VERSION", {"package": "github.com/example/tool", "version": "1.2.3"}),
        str(tmp_path), "go",
    )
    partial = verify_package_version(
        _claim("PACKAGE_VERSION", {"package": "github.com/example/tool", "version": "1.2"}),
        str(tmp_path), "go",
    )
    assert verified.verdict == "VERIFIED"
    assert partial.verdict == "REFUTED"
