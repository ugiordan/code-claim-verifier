from __future__ import annotations

import json
import os
import tempfile

from code_claim_verifier.cpg_backend import CpgBackend, load_cpg
from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.types import TypedClaim


def _make_cpg(nodes, edges, arch=None):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "code-graph.json")
    with open(path, "w") as f:
        json.dump({"nodes": nodes, "edges": edges, "schema_version": 3}, f)
    arch_path = None
    if arch:
        arch_path = os.path.join(d, "component-architecture.json")
        with open(arch_path, "w") as f:
            json.dump(arch, f)
    return path, arch_path


SAMPLE_NODES = [
    {"id": "fn_1", "kind": "Function", "name": "authenticate", "file": "auth.go", "line": 10, "language": "go"},
    {"id": "fn_2", "kind": "Function", "name": "authorize", "file": "auth.go", "line": 50, "language": "go"},
    {"id": "fn_3", "kind": "Function", "name": "handleRequest", "file": "handler.go", "line": 5, "language": "go"},
    {"id": "cs_1", "kind": "CallSite", "name": "authorize", "file": "auth.go", "line": 15, "call_target": "authorize"},
    {"id": "cs_2", "kind": "CallSite", "name": "authenticate", "file": "handler.go", "line": 8, "call_target": "authenticate"},
    {"id": "ep_1", "kind": "HTTPEndpoint", "name": "/api/login", "file": "handler.go", "line": 5, "route": "/api/login", "http_method": "POST"},
]

SAMPLE_EDGES = [
    {"from": "fn_1", "to": "cs_1", "kind": "CONTAINS"},
    {"from": "cs_1", "to": "fn_2", "kind": "CALLS", "confidence": "CERTAIN"},
    {"from": "fn_3", "to": "cs_2", "kind": "CONTAINS"},
    {"from": "cs_2", "to": "fn_1", "kind": "CALLS", "confidence": "INFERRED"},
]


class TestCpgBackend:
    def test_function_exists(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        assert cpg.function_exists("authenticate") is not None
        assert cpg.function_exists("nonexistent") is None

    def test_function_exists_with_file(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        assert cpg.function_exists("authenticate", "auth.go") is not None
        assert cpg.function_exists("authenticate", "wrong.go") is None

    def test_function_callers(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        callers = cpg.function_callers("authenticate")
        assert len(callers) == 1
        assert callers[0]["kind"] == "CALLS"

    def test_function_callers_none(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        callers = cpg.function_callers("handleRequest")
        assert len(callers) == 0

    def test_function_callees(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        callees = cpg.function_callees("authenticate")
        assert len(callees) == 1
        assert callees[0]["target"]["name"] == "authorize"

    def test_call_chain(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        success, evidence = cpg.call_chain_exists(["authenticate", "authorize"])
        assert success is True

    def test_call_chain_broken(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        success, evidence = cpg.call_chain_exists(["authorize", "authenticate"])
        assert success is False

    def test_http_endpoints(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        eps = cpg.http_endpoints()
        assert len(eps) == 1
        assert eps[0]["route"] == "/api/login"

    def test_confidence_mapping(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        assert cpg.get_confidence_for_edge({"confidence": "CERTAIN"}) == 0.95
        assert cpg.get_confidence_for_edge({"confidence": "INFERRED"}) == 0.80
        assert cpg.get_confidence_for_edge({"confidence": "UNCERTAIN"}) == 0.65


class TestEngineWithCpg:
    def test_cpg_function_exists_verified(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="FUNCTION_EXISTS",
                           parameters={"name": "authenticate"}, source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_function"

    def test_cpg_function_exists_refuted(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="FUNCTION_EXISTS",
                           parameters={"name": "nonexistent"}, source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "REFUTED"
        assert results[0].method in ("cpg_function", "grep_function_def")

    def test_cpg_has_callers(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="HAS_CALLERS",
                           parameters={"name": "authenticate", "expected": True},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_callers"

    def test_cpg_call_chain(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="CALL_CHAIN",
                           parameters={"chain": ["authenticate", "authorize"]},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_call_chain"

    def test_falls_back_to_grep_for_file_exists(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="FILE_EXISTS",
                           parameters={"path": "nonexistent.go"}, source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].method != "cpg_function"


class TestLoadCpg:
    def test_loads_from_repo_root(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "code-graph.json")
        with open(path, "w") as f:
            json.dump({"nodes": [], "edges": [], "schema_version": 3}, f)
        cpg = load_cpg(d)
        assert cpg is not None

    def test_returns_none_when_missing(self):
        d = tempfile.mkdtemp()
        cpg = load_cpg(d)
        assert cpg is None


NODES_WITH_TESTS = SAMPLE_NODES + [
    {"id": "fn_test1", "kind": "Function", "name": "TestAuth", "file": "auth_test.go", "line": 5,
     "language": "go", "is_test": True, "annotations": {"test:is_test_func": True}},
    {"id": "fn_test2", "kind": "Function", "name": "TestLogin", "file": "auth_test.go", "line": 20,
     "language": "go", "is_test": True, "annotations": {"test:is_test_func": True}},
    {"id": "cs_mux", "kind": "CallSite", "name": "mux.NewRouter", "file": "handler.go", "line": 10,
     "call_target": "mux.NewRouter"},
]

EXTENDED_NODES = SAMPLE_NODES + [
    {"id": "var_1", "kind": "Variable", "name": "allowedGroups", "file": "provider.go", "line": 20, "language": "go"},
    {"id": "struct_1", "kind": "StructLiteral", "name": "Config", "file": "config.go", "line": 10,
     "struct_type": "ServerConfig", "field_names": ["EnableAuth", "Port"],
     "properties": {"string_values": "true,8080"}},
]

SAMPLE_ARCH = {
    "dependencies": {
        "go_modules": [
            {"module": "github.com/gorilla/mux", "version": "v1.8.1"},
            {"module": "golang.org/x/crypto", "version": "v0.21.0"},
        ]
    },
    "external_connections": [{"type": "http", "service": "auth-service", "target": "https://auth.internal"}],
    "runtime_dependencies": [{"name": "Redis", "type": "cache"}],
    "rbac": {"kubebuilder_markers": [{"verb": "get", "resource": "pods"}]},
}


class TestCpgFileClassification:
    def test_test_file_verified(self):
        cpg = CpgBackend(_make_cpg(NODES_WITH_TESTS, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="FILE_CLASSIFICATION",
                           parameters={"path": "auth_test.go", "category": "test"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_classification"

    def test_production_file_verified(self):
        cpg = CpgBackend(_make_cpg(NODES_WITH_TESTS, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="FILE_CLASSIFICATION",
                           parameters={"path": "auth.go", "category": "production"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_classification"

    def test_wrong_classification_refuted(self):
        cpg = CpgBackend(_make_cpg(NODES_WITH_TESTS, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="FILE_CLASSIFICATION",
                           parameters={"path": "auth_test.go", "category": "production"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "REFUTED"


class TestCpgImportExists:
    def test_import_found_via_callsite(self):
        cpg = CpgBackend(_make_cpg(NODES_WITH_TESTS, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="IMPORT_EXISTS",
                           parameters={"module": "mux"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_import"

    def test_import_found_via_arch_deps(self):
        path, arch_path = _make_cpg(SAMPLE_NODES, SAMPLE_EDGES, SAMPLE_ARCH)
        cpg = CpgBackend(path, arch_path)
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="IMPORT_EXISTS",
                           parameters={"module": "gorilla/mux"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_import"


class TestCpgMitigation:
    def test_mitigation_function_exists(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="MITIGATION_EXISTS",
                           parameters={"description": "auth check", "pattern": "authenticate",
                                       "file": "auth.go", "line": 10},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_mitigation"


class TestCpgAbsence:
    def test_symbol_exists(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        assert cpg.symbol_exists("authenticate") is True
        assert cpg.symbol_exists("nonexistent_xyz") is False

    def test_engine_absence_verified(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="ABSENCE",
                           parameters={"pattern": "nonexistent_xyz", "scope": "repo"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_absence"

    def test_engine_absence_refuted(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="ABSENCE",
                           parameters={"pattern": "authenticate", "scope": "repo"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "REFUTED"
        assert results[0].method == "cpg_absence"


class TestCpgPackageVersion:
    def test_version_match(self):
        path, arch_path = _make_cpg(SAMPLE_NODES, SAMPLE_EDGES, SAMPLE_ARCH)
        cpg = CpgBackend(path, arch_path)
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="PACKAGE_VERSION",
                           parameters={"package": "github.com/gorilla/mux", "version": "1.8.1"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_dependency"

    def test_version_mismatch(self):
        path, arch_path = _make_cpg(SAMPLE_NODES, SAMPLE_EDGES, SAMPLE_ARCH)
        cpg = CpgBackend(path, arch_path)
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="PACKAGE_VERSION",
                           parameters={"package": "github.com/gorilla/mux", "version": "2.0.0"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "REFUTED"
        assert results[0].method == "cpg_dependency"


class TestCpgVariable:
    def test_variable_found(self):
        cpg = CpgBackend(_make_cpg(EXTENDED_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="DEFAULT_VALUE",
                           parameters={"variable": "allowedGroups"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_variable"


class TestCpgConfigFlag:
    def test_flag_found(self):
        cpg = CpgBackend(_make_cpg(EXTENDED_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="CONFIG_FLAG",
                           parameters={"flag": "EnableAuth", "value": "true"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_config"

    def test_flag_wrong_value(self):
        cpg = CpgBackend(_make_cpg(EXTENDED_NODES, SAMPLE_EDGES)[0])
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="CONFIG_FLAG",
                           parameters={"flag": "EnableAuth", "value": "false"},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "REFUTED"
        assert results[0].method == "cpg_config"
