"""Optional CPG backend using architecture-analyzer's code-graph.json.

When a code-graph.json is available, CCV uses exact AST-level queries
instead of grep for function/call verification. Falls back gracefully
when the CPG is not available.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class CpgBackend:
    """Query interface over an architecture-analyzer code property graph."""

    def __init__(self, cpg_path: str):
        with open(cpg_path) as f:
            data = json.load(f)

        self._nodes: dict[str, dict] = {}
        self._by_kind: dict[str, list[dict]] = {}
        self._by_name: dict[str, list[dict]] = {}
        self._out_edges: dict[str, list[dict]] = {}
        self._in_edges: dict[str, list[dict]] = {}

        for node in data.get("nodes", []):
            nid = node["id"]
            self._nodes[nid] = node
            kind = node.get("kind", "")
            self._by_kind.setdefault(kind, []).append(node)
            name = node.get("name", "")
            if name:
                self._by_name.setdefault(name, []).append(node)

        for edge in data.get("edges", []):
            self._out_edges.setdefault(edge["from"], []).append(edge)
            self._in_edges.setdefault(edge["to"], []).append(edge)

        func_count = len(self._by_kind.get("Function", []))
        call_count = len([e for edges in self._out_edges.values()
                         for e in edges if e.get("kind") == "CALLS"])
        logger.info("CPG loaded: %d nodes, %d functions, %d call edges",
                    len(self._nodes), func_count, call_count)

    def function_exists(self, name: str, file: str | None = None) -> dict | None:
        """Check if a function with the given name exists. Returns node or None."""
        candidates = self._by_name.get(name, [])
        for node in candidates:
            if node.get("kind") != "Function":
                continue
            if file and not node.get("file", "").endswith(file):
                continue
            return node
        return None

    def function_callers(self, name: str) -> list[dict]:
        """Find all call edges targeting a function with the given name."""
        func = self.function_exists(name)
        if not func:
            return []
        return [e for e in self._in_edges.get(func["id"], [])
                if e.get("kind") == "CALLS"]

    def function_callees(self, name: str) -> list[dict]:
        """Find all functions called by the given function."""
        func = self.function_exists(name)
        if not func:
            return []
        callsites = [e["to"] for e in self._out_edges.get(func["id"], [])
                     if e.get("kind") == "CONTAINS"]
        results = []
        for cs_id in callsites:
            for e in self._out_edges.get(cs_id, []):
                if e.get("kind") == "CALLS":
                    target = self._nodes.get(e["to"])
                    if target:
                        results.append({
                            "edge": e,
                            "target": target,
                        })
        return results

    def call_chain_exists(self, chain: list[str]) -> tuple[bool, list[str]]:
        """Check if a multi-hop call chain A->B->C exists.
        Returns (success, evidence_list)."""
        if len(chain) < 2:
            return False, ["Chain too short"]

        evidence = []
        for i in range(len(chain) - 1):
            caller, callee = chain[i], chain[i + 1]
            callees = self.function_callees(caller)
            found = any(c["target"].get("name") == callee for c in callees)
            if found:
                match = next(c for c in callees if c["target"].get("name") == callee)
                conf = match["edge"].get("confidence", "UNCERTAIN")
                evidence.append(f"{caller}->{callee}: {conf}")
            else:
                evidence.append(f"{caller}->{callee}: NOT FOUND")
                return False, evidence

        return True, evidence

    def http_endpoints(self) -> list[dict]:
        """List all HTTP endpoint nodes."""
        return self._by_kind.get("HTTPEndpoint", [])

    def get_confidence_for_edge(self, edge: dict) -> float:
        """Map CPG edge confidence to CCV method_confidence."""
        conf = edge.get("confidence", "UNCERTAIN")
        return {"CERTAIN": 0.95, "INFERRED": 0.80, "UNCERTAIN": 0.65}.get(conf, 0.65)


def load_cpg(repo_path: str) -> CpgBackend | None:
    """Try to load a CPG from common locations relative to repo_path."""
    candidates = [
        os.path.join(repo_path, "code-graph.json"),
        os.path.join(repo_path, "output", "code-graph.json"),
        os.path.join(repo_path, ".arch-analyzer", "code-graph.json"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                return CpgBackend(path)
            except Exception as e:
                logger.warning("Failed to load CPG from %s: %s", path, e)
    return None
