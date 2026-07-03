"""Optional CPG backend using architecture-analyzer's code-graph.json.

When a code-graph.json (and optionally component-architecture.json) is
available, CCV uses exact AST-level queries instead of grep. Falls back
gracefully when the CPG is not available.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class CpgBackend:
    """Query interface over architecture-analyzer's code property graph
    and optional architecture JSON."""

    def __init__(self, cpg_path: str, arch_path: str | None = None):
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

        self._arch: dict = {}
        if arch_path and os.path.isfile(arch_path):
            try:
                with open(arch_path) as f:
                    self._arch = json.load(f)
            except Exception as e:
                logger.warning("Failed to load architecture JSON from %s: %s", arch_path, e)

        func_count = len(self._by_kind.get("Function", []))
        call_count = sum(1 for edges in self._out_edges.values()
                         for e in edges if e.get("kind") == "CALLS")
        logger.info("CPG loaded: %d nodes, %d functions, %d call edges, arch=%s",
                    len(self._nodes), func_count, call_count, bool(self._arch))

    # ------------------------------------------------------------------
    # Function queries (existing)
    # ------------------------------------------------------------------

    def function_exists(self, name: str, file: str | None = None) -> dict | None:
        candidates = self._by_name.get(name, [])
        for node in candidates:
            if node.get("kind") != "Function":
                continue
            if file and not node.get("file", "").endswith(file):
                continue
            return node
        return None

    def function_callers(self, name: str) -> list[dict]:
        func = self.function_exists(name)
        if not func:
            return []
        return [e for e in self._in_edges.get(func["id"], [])
                if e.get("kind") == "CALLS"]

    def function_callees(self, name: str) -> list[dict]:
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
                        results.append({"edge": e, "target": target})
        return results

    def call_chain_exists(self, chain: list[str]) -> tuple[bool, list[str]]:
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
        return self._by_kind.get("HTTPEndpoint", [])

    # ------------------------------------------------------------------
    # Variable / config queries (new)
    # ------------------------------------------------------------------

    def variable_exists(self, name: str, file: str | None = None) -> dict | None:
        candidates = self._by_name.get(name, [])
        for node in candidates:
            if node.get("kind") != "Variable":
                continue
            if file and not node.get("file", "").endswith(file):
                continue
            return node
        return None

    def struct_literal_with_field(self, struct_type: str | None = None,
                                  field_name: str | None = None,
                                  field_value: str | None = None) -> list[dict]:
        results = []
        for node in self._by_kind.get("StructLiteral", []):
            if struct_type and struct_type not in node.get("struct_type", ""):
                continue
            fields = node.get("field_names", [])
            if field_name and field_name not in fields:
                continue
            if field_value:
                props = node.get("properties", {})
                string_values = props.get("string_values", "")
                if field_value not in string_values:
                    continue
            results.append(node)
        return results

    # ------------------------------------------------------------------
    # Absence / symbol search (new)
    # ------------------------------------------------------------------

    def symbol_exists(self, name: str) -> bool:
        return name in self._by_name

    def all_function_names(self) -> set[str]:
        return {n["name"] for n in self._by_kind.get("Function", [])}

    def file_is_test(self, file_path: str) -> bool | None:
        """Check if a file contains only test functions. Returns None if no data."""
        funcs = [n for n in self._by_kind.get("Function", [])
                 if n.get("file", "").endswith(file_path)]
        if not funcs:
            return None
        return all(n.get("is_test", False) or
                   n.get("annotations", {}).get("test:is_test_func", False)
                   for n in funcs)

    def module_is_used(self, module: str) -> list[dict]:
        """Find CallSite nodes that reference a module (by call_target prefix)."""
        results = []
        for node in self._by_kind.get("CallSite", []):
            target = node.get("call_target", "") or node.get("name", "")
            if module in target:
                results.append(node)
        if not results:
            modules = self._arch.get("dependencies", {}).get("go_modules", [])
            for m in modules:
                if module in m.get("module", ""):
                    return [{"id": "arch", "kind": "dependency", "name": m["module"],
                             "file": "go.mod", "line": 0}]
        return results

    # ------------------------------------------------------------------
    # Data flow queries (new)
    # ------------------------------------------------------------------

    def data_flow_reaches(self, source_name: str, target_name: str,
                          max_hops: int = 10) -> tuple[bool, list[str]]:
        source = self.function_exists(source_name) or self.variable_exists(source_name)
        target = self.function_exists(target_name) or self.variable_exists(target_name)
        if not source or not target:
            return False, [f"{'source' if not source else 'target'} not found"]

        visited: set[str] = set()
        queue: list[tuple[str, list[str]]] = [(source["id"], [source_name])]
        while queue:
            current_id, path = queue.pop(0)
            if current_id == target["id"]:
                return True, path
            if current_id in visited or len(path) > max_hops:
                continue
            visited.add(current_id)
            for edge in self._out_edges.get(current_id, []):
                if edge["kind"] in ("DATA_FLOW", "CALLS", "CONTAINS"):
                    next_node = self._nodes.get(edge["to"])
                    if next_node:
                        next_name = next_node.get("name", next_node["id"][:8])
                        queue.append((edge["to"], path + [next_name]))
        return False, [f"No data flow path from {source_name} to {target_name}"]

    # ------------------------------------------------------------------
    # Architecture JSON queries (new)
    # ------------------------------------------------------------------

    def get_dependency_version(self, package: str) -> str | None:
        modules = self._arch.get("dependencies", {}).get("go_modules", [])
        for m in modules:
            mod_name = m.get("module", "")
            if mod_name == package or mod_name.endswith("/" + package):
                return m.get("version", "").lstrip("v")
        return None

    def get_external_connections(self) -> list[dict]:
        return self._arch.get("external_connections", [])

    def get_runtime_dependencies(self) -> list[dict]:
        return self._arch.get("runtime_dependencies", [])

    def get_rbac_markers(self) -> list[dict]:
        return self._arch.get("rbac", {}).get("kubebuilder_markers", [])

    # ------------------------------------------------------------------
    # Confidence mapping
    # ------------------------------------------------------------------

    def get_confidence_for_edge(self, edge: dict) -> float:
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
            arch_path = os.path.join(os.path.dirname(path), "component-architecture.json")
            try:
                return CpgBackend(path, arch_path if os.path.isfile(arch_path) else None)
            except Exception as e:
                logger.warning("Failed to load CPG from %s: %s", path, e)
    return None
