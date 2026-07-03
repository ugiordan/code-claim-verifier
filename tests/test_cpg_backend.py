from __future__ import annotations

import json
import os
import tempfile

from code_claim_verifier.cpg_backend import CpgBackend, load_cpg
from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.types import TypedClaim


def _make_cpg(nodes, edges):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "code-graph.json")
    with open(path, "w") as f:
        json.dump({"nodes": nodes, "edges": edges, "schema_version": 3}, f)
    return path


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
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        assert cpg.function_exists("authenticate") is not None
        assert cpg.function_exists("nonexistent") is None

    def test_function_exists_with_file(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        assert cpg.function_exists("authenticate", "auth.go") is not None
        assert cpg.function_exists("authenticate", "wrong.go") is None

    def test_function_callers(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        callers = cpg.function_callers("authenticate")
        assert len(callers) == 1
        assert callers[0]["kind"] == "CALLS"

    def test_function_callers_none(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        callers = cpg.function_callers("handleRequest")
        assert len(callers) == 0

    def test_function_callees(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        callees = cpg.function_callees("authenticate")
        assert len(callees) == 1
        assert callees[0]["target"]["name"] == "authorize"

    def test_call_chain(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        success, evidence = cpg.call_chain_exists(["authenticate", "authorize"])
        assert success is True

    def test_call_chain_broken(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        success, evidence = cpg.call_chain_exists(["authorize", "authenticate"])
        assert success is False

    def test_http_endpoints(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        eps = cpg.http_endpoints()
        assert len(eps) == 1
        assert eps[0]["route"] == "/api/login"

    def test_confidence_mapping(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        assert cpg.get_confidence_for_edge({"confidence": "CERTAIN"}) == 0.95
        assert cpg.get_confidence_for_edge({"confidence": "INFERRED"}) == 0.80
        assert cpg.get_confidence_for_edge({"confidence": "UNCERTAIN"}) == 0.65


class TestEngineWithCpg:
    def test_cpg_function_exists_verified(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="FUNCTION_EXISTS",
                           parameters={"name": "authenticate"}, source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_function"

    def test_cpg_function_exists_refuted(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="FUNCTION_EXISTS",
                           parameters={"name": "nonexistent"}, source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "REFUTED"
        assert results[0].method == "cpg_function"

    def test_cpg_has_callers(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="HAS_CALLERS",
                           parameters={"name": "authenticate", "expected": True},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_callers"

    def test_cpg_call_chain(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
        engine = VerificationEngine(cpg=cpg)
        claim = TypedClaim(claim_type="CALL_CHAIN",
                           parameters={"chain": ["authenticate", "authorize"]},
                           source_sentence="")
        results = engine.verify_claims([claim], "/tmp", "go")
        assert results[0].verdict == "VERIFIED"
        assert results[0].method == "cpg_call_chain"

    def test_falls_back_to_grep_for_file_exists(self):
        cpg = CpgBackend(_make_cpg(SAMPLE_NODES, SAMPLE_EDGES))
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
