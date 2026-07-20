from __future__ import annotations

import dataclasses
from collections import defaultdict, deque
from typing import Callable

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.verifiers import VERIFIER_REGISTRY
from code_claim_verifier import grep as grep_module
from code_claim_verifier.cpg_backend import CpgBackend, load_cpg
from code_claim_verifier.cymbal_backend import CymbalBackend

VerifierFunction = Callable[[TypedClaim, str, str], VerifiedClaim]

_FREEZE_DEPTH_CAP = 20


def _freeze(value: object, _depth: int = 0) -> object:
    """Recursively freeze nested structures into hashable equivalents.

    dict -> frozenset of sorted (key, frozen_value) pairs
    set  -> frozenset
    list/tuple -> tuple of frozen elements
    Depth is capped at 20 to guard against pathological nesting.
    """
    if _depth >= _FREEZE_DEPTH_CAP:
        return str(value)
    if isinstance(value, dict):
        return frozenset(
            sorted((k, _freeze(v, _depth + 1)) for k, v in value.items())
        )
    if isinstance(value, set):
        return frozenset(_freeze(v, _depth + 1) for v in value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v, _depth + 1) for v in value)
    return value


# Each rule: (dependent_type, prereq_type, source_param, target_param)
# source_param is the key in the dependent's parameters that maps to
# target_param in the synthesized prerequisite's parameters.
BUILTIN_RULES: list[tuple[str, str, str, str]] = [
    ("LINE_CONTENT", "FILE_EXISTS", "path", "path"),
    ("GENERATED_OR_VENDORED", "FILE_EXISTS", "path", "path"),
    ("FUNCTION_EXISTS", "FILE_EXISTS", "file", "path"),
    ("FUNCTION_CALLED", "FUNCTION_EXISTS", "name", "name"),
    ("HAS_CALLERS", "FUNCTION_EXISTS", "name", "name"),
    ("IMPORT_EXISTS", "FILE_EXISTS", "file", "path"),
    ("MITIGATION_EXISTS", "FILE_EXISTS", "file", "path"),
    ("DEFAULT_VALUE", "FILE_EXISTS", "file", "path"),
    ("CONFIG_FLAG", "FILE_EXISTS", "file", "path"),
]


class VerificationEngine:
    """Owns the verifier registry, result caching, and dependency graph.

    Two entry points:
    * verify_claims        - simple flat verification with caching
    * verify_claims_with_chaining - full dependency synthesis + SUSPECT propagation
    """

    def __init__(self, cpg: CpgBackend | None = None,
                 cymbal: CymbalBackend | None = None) -> None:
        self.registry: dict[str, VerifierFunction] = dict(VERIFIER_REGISTRY)
        self.dependency_rules: list[tuple[str, str, str, str]] = list(BUILTIN_RULES)
        self.cpg = cpg
        self.cymbal = cymbal

    # ------------------------------------------------------------------
    # Registry management
    # ------------------------------------------------------------------

    def register(
        self,
        claim_type: str,
        verifier_fn: VerifierFunction,
        depends_on: list[tuple[str, str, str]] | None = None,
    ) -> None:
        """Register a verifier for *claim_type*.

        Raises ValueError if the type is already registered.
        *depends_on* is an optional list of (prereq_type, source_param, target_param).
        """
        if claim_type in self.registry:
            raise ValueError(
                f"Claim type {claim_type!r} is already registered"
            )
        self.registry[claim_type] = verifier_fn
        if depends_on:
            for prereq_type, source_param, target_param in depends_on:
                self.register_dependency(
                    claim_type, prereq_type, source_param, target_param
                )

    def register_dependency(
        self,
        claim_type: str,
        depends_on: str,
        source_param: str,
        target_param: str,
    ) -> None:
        """Add a dependency rule, raising ValueError on cycle."""
        new_rule = (claim_type, depends_on, source_param, target_param)
        if self._would_create_cycle(new_rule):
            raise ValueError(
                f"Adding rule {new_rule!r} would create a dependency cycle"
            )
        self.dependency_rules.append(new_rule)

    def _would_create_cycle(
        self, new_rule: tuple[str, str, str, str]
    ) -> bool:
        """DFS from prereq_type back through existing rules to check
        whether we'd reach dependent_type, which would form a cycle."""
        dep_type, prereq_type, _, _ = new_rule

        # Build an adjacency map: prereq -> {dependents}
        # We want to walk *backwards*: from prereq_type, follow edges
        # where prereq_type is a dependent that itself has prerequisites.
        # Actually we need: from prereq_type, can we reach dep_type by
        # following prerequisite edges (prereq -> its prereq -> ...).
        adj: dict[str, set[str]] = defaultdict(set)
        for d, p, _, _ in self.dependency_rules:
            adj[d].add(p)
        # Also add the candidate rule
        adj[dep_type].add(prereq_type)

        # DFS from prereq_type through adj
        visited: set[str] = set()
        stack = [prereq_type]
        while stack:
            node = stack.pop()
            if node == dep_type:
                return True
            if node in visited:
                continue
            visited.add(node)
            stack.extend(adj.get(node, set()))
        return False

    # ------------------------------------------------------------------
    # Simple (flat) verification
    # ------------------------------------------------------------------

    def verify_claims(
        self,
        claims: list[TypedClaim],
        repo_path: str,
        language: str,
    ) -> list[VerifiedClaim]:
        """Verify claims with per-call caches (grep + verifier result).

        Returns independent copies so callers can mutate freely.
        """
        token = grep_module.cache_context()
        try:
            cache: dict[tuple, VerifiedClaim] = {}
            results: list[VerifiedClaim] = []
            for claim in claims:
                key = self._cache_key(claim, repo_path, language)
                if key not in cache:
                    cache[key] = self._verify_one(claim, repo_path, language)
                # Return independent copy with the requesting claim's identity
                results.append(
                    dataclasses.replace(
                        cache[key],
                        claim=claim,
                        synthesized=claim is not cache[key].claim and cache[key].synthesized,
                        suspect_reason=None,
                    )
                )
            return results
        finally:
            grep_module.reset_cache(token)

    # ------------------------------------------------------------------
    # Chained verification with dependency synthesis
    # ------------------------------------------------------------------

    def verify_claims_with_chaining(
        self,
        claims: list[TypedClaim],
        repo_path: str,
        language: str,
    ) -> list[VerifiedClaim]:
        """Full chaining pipeline:

        1. Build dependency graph (synthesize missing prerequisites)
        2. Topological sort
        3. Verify in order with caching
        4. Propagate SUSPECT flags (ANY-match semantics)
        """
        all_claims, edges, synthesized_ids = self._build_dependency_graph(claims)
        ordered = self._topological_sort(all_claims, edges)

        token = grep_module.cache_context()
        try:
            cache: dict[tuple, VerifiedClaim] = {}
            verified_map: dict[str, VerifiedClaim] = {}

            for claim in ordered:
                key = self._cache_key(claim, repo_path, language)
                if key not in cache:
                    cache[key] = self._verify_one(claim, repo_path, language)

                result = dataclasses.replace(
                    cache[key],
                    claim=claim,
                    synthesized=claim.id in synthesized_ids,
                    suspect_reason=None,
                )
                verified_map[claim.id] = result

            self._propagate_suspect(verified_map, edges)

            # Return results in the original order of *all_claims*
            # (original claims first, then synthesized)
            return [verified_map[c.id] for c in all_claims]
        finally:
            grep_module.reset_cache(token)

    # ------------------------------------------------------------------
    # Dependency graph construction
    # ------------------------------------------------------------------

    def _build_dependency_graph(
        self, claims: list[TypedClaim]
    ) -> tuple[list[TypedClaim], dict[str, list[str]], set[str]]:
        """Synthesize missing prerequisites and build edge map.

        Returns (all_claims, edges, synthesized_ids).
        edges maps dependent_id -> [prereq_ids].
        """
        claim_list = list(claims)
        edges: dict[str, list[str]] = defaultdict(list)
        synthesized_ids: set[str] = set()
        # Track synthesized claims by (claim_type, frozen_params) to dedup
        seen_synth: dict[tuple, TypedClaim] = {}

        # Iterate up to 3 rounds to handle transitive synthesis
        for _ in range(3):
            new_claims: list[TypedClaim] = []
            for rule_dep, rule_prereq, src_param, tgt_param in self.dependency_rules:
                for claim in claim_list:
                    if claim.claim_type != rule_dep:
                        continue
                    param_value = claim.parameters.get(src_param)
                    if param_value is None:
                        continue

                    existing = self._find_matching_prereq(
                        claim_list, rule_prereq, tgt_param, param_value
                    )
                    if existing is not None:
                        if existing.id not in edges[claim.id]:
                            edges[claim.id].append(existing.id)
                        continue

                    # Also check already-synthesized new_claims
                    existing_new = self._find_matching_prereq(
                        new_claims, rule_prereq, tgt_param, param_value
                    )
                    if existing_new is not None:
                        if existing_new.id not in edges[claim.id]:
                            edges[claim.id].append(existing_new.id)
                        continue

                    # Dedup by (type, params)
                    synth_params = {tgt_param: param_value}
                    synth_key = (rule_prereq, _freeze(synth_params))
                    if synth_key in seen_synth:
                        prereq = seen_synth[synth_key]
                        if prereq.id not in edges[claim.id]:
                            edges[claim.id].append(prereq.id)
                        continue

                    prereq = TypedClaim(
                        claim_type=rule_prereq,
                        parameters=synth_params,
                        source_sentence="[synthesized prerequisite]",
                    )
                    seen_synth[synth_key] = prereq
                    new_claims.append(prereq)
                    synthesized_ids.add(prereq.id)
                    edges[claim.id].append(prereq.id)

            if not new_claims:
                break
            claim_list.extend(new_claims)

        return claim_list, dict(edges), synthesized_ids

    @staticmethod
    def _find_matching_prereq(
        claims: list[TypedClaim],
        prereq_type: str,
        param_name: str,
        param_value: object,
    ) -> TypedClaim | None:
        """Linear search for a claim matching the prerequisite criteria."""
        for c in claims:
            if c.claim_type == prereq_type and c.parameters.get(param_name) == param_value:
                return c
        return None

    # ------------------------------------------------------------------
    # Topological sort (Kahn's algorithm)
    # ------------------------------------------------------------------

    @staticmethod
    def _topological_sort(
        claims: list[TypedClaim],
        edges: dict[str, list[str]],
    ) -> list[TypedClaim]:
        """Kahn's BFS topological sort. Appends remaining nodes on cycle."""
        claim_by_id = {c.id: c for c in claims}

        # in-degree: how many prereqs does this claim depend on
        in_degree: dict[str, int] = {c.id: 0 for c in claims}
        # reverse edges: prereq_id -> [dependent_ids]
        reverse: dict[str, list[str]] = defaultdict(list)

        for dep_id, prereq_ids in edges.items():
            in_degree[dep_id] = len(prereq_ids)
            for prereq_id in prereq_ids:
                reverse[prereq_id].append(dep_id)

        queue: deque[str] = deque()
        for cid, deg in in_degree.items():
            if deg == 0:
                queue.append(cid)

        ordered: list[TypedClaim] = []
        while queue:
            cid = queue.popleft()
            ordered.append(claim_by_id[cid])
            for dep_id in reverse.get(cid, []):
                in_degree[dep_id] -= 1
                if in_degree[dep_id] == 0:
                    queue.append(dep_id)

        # Append any remaining (cycle participants) in original order
        ordered_ids = {c.id for c in ordered}
        for c in claims:
            if c.id not in ordered_ids:
                ordered.append(c)

        return ordered

    # ------------------------------------------------------------------
    # SUSPECT propagation (ANY-match semantics)
    # ------------------------------------------------------------------

    @staticmethod
    def _propagate_suspect(
        verified_map: dict[str, VerifiedClaim],
        edges: dict[str, list[str]],
    ) -> None:
        """For each dependent, group prereqs by type. A dependent is marked
        SUSPECT only when ALL prereqs of at least one type are REFUTED
        (ANY-match: if at least one prereq of a type is VERIFIED, the
        dependent is not suspect for that type).
        """
        for dep_id, prereq_ids in edges.items():
            if dep_id not in verified_map:
                continue

            # Group prereqs by claim_type
            by_type: dict[str, list[VerifiedClaim]] = defaultdict(list)
            for pid in prereq_ids:
                if pid in verified_map:
                    vc = verified_map[pid]
                    by_type[vc.claim.claim_type].append(vc)

            # Check each type group: if ALL are REFUTED, flag as suspect
            suspect_reasons: list[str] = []
            for ptype, prereqs in by_type.items():
                if all(p.verdict == "REFUTED" for p in prereqs):
                    suspect_reasons.append(
                        f"all {ptype} prerequisites REFUTED"
                    )

            if suspect_reasons:
                dep_vc = verified_map[dep_id]
                verified_map[dep_id] = dataclasses.replace(
                    dep_vc,
                    suspect_reason="; ".join(suspect_reasons),
                )

    # ------------------------------------------------------------------
    # Core verification dispatch
    # ------------------------------------------------------------------

    def _verify_one(
        self, claim: TypedClaim, repo_path: str, language: str
    ) -> VerifiedClaim:
        """Dispatch to CPG backend if available, else registry with error handling."""
        if self.cpg:
            cpg_result = self._try_cpg_verify(claim)
            if cpg_result:
                return cpg_result

        if self.cymbal:
            cymbal_result = self._try_cymbal_verify(claim)
            if cymbal_result:
                return cymbal_result

        verifier = self.registry.get(claim.claim_type)
        if not verifier:
            return VerifiedClaim(
                claim=claim,
                verdict="UNVERIFIABLE",
                method_confidence=0.0,
                evidence=f"Unknown claim type: {claim.claim_type}",
                method="error",
                error="unknown_type",
            )
        try:
            return verifier(claim, repo_path, language)
        except Exception as e:
            return VerifiedClaim(
                claim=claim,
                verdict="UNVERIFIABLE",
                method_confidence=0.0,
                evidence="",
                method="error",
                error=f"{type(e).__name__}: {str(e)[:200]}",
            )

    def _try_cpg_verify(self, claim: TypedClaim) -> VerifiedClaim | None:
        """Try to verify a claim using the CPG. Returns None to fall back to grep."""
        cpg = self.cpg
        ct = claim.claim_type
        params = claim.parameters

        if ct == "FUNCTION_EXISTS":
            name = params.get("name", "")
            file = params.get("file", params.get("path", ""))
            node = cpg.function_exists(name, file or None)
            if node:
                return VerifiedClaim(
                    claim=claim, verdict="VERIFIED", method_confidence=0.95,
                    evidence=f"CPG: {node['name']} at {node['file']}:{node['line']}",
                    method="cpg_function",
                )
            return None

        if ct in ("FUNCTION_CALLED", "HAS_CALLERS"):
            name = params.get("name", "")
            expected = params.get("expected", True)
            callers = cpg.function_callers(name)
            if callers:
                conf = max(cpg.get_confidence_for_edge(c) for c in callers)
                return VerifiedClaim(
                    claim=claim,
                    verdict="VERIFIED" if expected else "REFUTED",
                    method_confidence=conf,
                    evidence=f"CPG: {len(callers)} callers",
                    method="cpg_callers",
                )
            return None

        if ct == "CALL_CHAIN":
            chain = params.get("chain", [])
            caller = params.get("caller", "")
            callee = params.get("callee", "")
            if not chain and caller and callee:
                chain = [caller, callee]
            if len(chain) < 2:
                return None
            success, evidence = cpg.call_chain_exists(chain)
            return VerifiedClaim(
                claim=claim,
                verdict="VERIFIED" if success else "REFUTED",
                method_confidence=0.85,
                evidence=f"CPG chain: {'; '.join(evidence)}",
                method="cpg_call_chain",
            )

        if ct == "ENTRY_POINT":
            endpoints = cpg.http_endpoints()
            location = params.get("location", "")
            for ep in endpoints:
                if location and location in ep.get("file", ""):
                    return VerifiedClaim(
                        claim=claim, verdict="VERIFIED", method_confidence=0.90,
                        evidence=f"CPG: endpoint {ep['name']} at {ep['file']}:{ep['line']}",
                        method="cpg_endpoint",
                    )
            return None

        if ct == "ABSENCE":
            pattern = params.get("pattern", "")
            if pattern and not cpg.symbol_exists(pattern):
                return VerifiedClaim(
                    claim=claim, verdict="VERIFIED", method_confidence=0.90,
                    evidence=f"CPG: no symbol '{pattern}' in graph",
                    method="cpg_absence",
                )
            if pattern and cpg.symbol_exists(pattern):
                return VerifiedClaim(
                    claim=claim, verdict="REFUTED", method_confidence=0.90,
                    evidence=f"CPG: symbol '{pattern}' found in graph",
                    method="cpg_absence",
                )
            return None

        if ct == "PACKAGE_VERSION":
            package = params.get("package", "")
            expected = params.get("version", "")
            actual = cpg.get_dependency_version(package)
            if actual is not None:
                match = actual == expected or expected in actual
                return VerifiedClaim(
                    claim=claim,
                    verdict="VERIFIED" if match else "REFUTED",
                    method_confidence=0.92,
                    evidence=f"CPG arch: {package}=={actual} (expected {expected})",
                    method="cpg_dependency",
                )
            return None

        if ct == "DEFAULT_VALUE":
            variable = params.get("variable", "")
            file_param = params.get("file", "")
            node = cpg.variable_exists(variable, file_param or None)
            if node:
                return VerifiedClaim(
                    claim=claim, verdict="VERIFIED", method_confidence=0.70,
                    evidence=f"CPG: variable '{variable}' at {node['file']}:{node['line']}",
                    method="cpg_variable",
                )
            return None

        if ct == "FILE_CLASSIFICATION":
            path = params.get("file", params.get("path", ""))
            category = params.get("category", "").lower()
            if category in ("test", "production") and path:
                is_test = cpg.file_is_test(path)
                if is_test is not None:
                    if category == "test":
                        return VerifiedClaim(
                            claim=claim,
                            verdict="VERIFIED" if is_test else "REFUTED",
                            method_confidence=0.90,
                            evidence=f"CPG: file {'is' if is_test else 'is not'} a test file (function annotations)",
                            method="cpg_classification",
                        )
                    else:
                        return VerifiedClaim(
                            claim=claim,
                            verdict="VERIFIED" if not is_test else "REFUTED",
                            method_confidence=0.90,
                            evidence=f"CPG: file {'is not' if not is_test else 'is'} a test file",
                            method="cpg_classification",
                        )
            return None

        if ct == "IMPORT_EXISTS":
            module = params.get("module", "")
            if module:
                refs = cpg.module_is_used(module)
                if refs:
                    ref = refs[0]
                    return VerifiedClaim(
                        claim=claim, verdict="VERIFIED", method_confidence=0.88,
                        evidence=f"CPG: module '{module}' referenced via {ref.get('name', '')} at {ref.get('file', '')}:{ref.get('line', '')}",
                        method="cpg_import",
                    )
            return None

        if ct == "MITIGATION_EXISTS":
            pattern = params.get("pattern", "")
            if pattern and cpg.function_exists(pattern):
                node = cpg.function_exists(pattern)
                callers = cpg.function_callers(pattern)
                return VerifiedClaim(
                    claim=claim, verdict="VERIFIED", method_confidence=0.75,
                    evidence=f"CPG: mitigation function '{pattern}' exists at {node['file']}:{node['line']}, {len(callers)} callers",
                    method="cpg_mitigation",
                )
            return None

        if ct == "CONFIG_FLAG":
            flag = params.get("flag", "")
            value = params.get("value", "")
            matches = cpg.struct_literal_with_field(field_name=flag, field_value=value or None)
            if matches:
                m = matches[0]
                return VerifiedClaim(
                    claim=claim, verdict="VERIFIED", method_confidence=0.85,
                    evidence=f"CPG: flag '{flag}' in {m['struct_type']} at {m['file']}:{m['line']}",
                    method="cpg_config",
                )
            if not value:
                return None
            no_value = cpg.struct_literal_with_field(field_name=flag)
            if no_value:
                m = no_value[0]
                return VerifiedClaim(
                    claim=claim, verdict="REFUTED", method_confidence=0.80,
                    evidence=f"CPG: flag '{flag}' found but not with value '{value}' at {m['file']}:{m['line']}",
                    method="cpg_config",
                )
            return None

        return None

    def _try_cymbal_verify(self, claim: TypedClaim) -> VerifiedClaim | None:
        """Try to verify using cymbal tree-sitter backend. Returns None to fall back."""
        cymbal = self.cymbal
        ct = claim.claim_type
        params = claim.parameters

        if ct == "FUNCTION_EXISTS":
            name = params.get("name", "")
            file = params.get("file", params.get("path", ""))
            if not name:
                return None
            node = cymbal.function_exists(name, file or None)
            if node:
                return VerifiedClaim(
                    claim=claim, verdict="VERIFIED", method_confidence=0.95,
                    evidence=f"cymbal: {node['name']} at {node.get('rel_path', '')}:{node.get('start_line', '')}",
                    method="cymbal_function",
                )
            return None

        if ct in ("FUNCTION_CALLED", "HAS_CALLERS"):
            name = (params.get("name", "") or params.get("callee", "")
                    or params.get("function", ""))
            expected = params.get("expected", True)
            if not name:
                return None
            callers = cymbal.function_callers(name)
            if callers:
                caller_names = ", ".join(c.get("caller", "?") for c in callers[:3])
                return VerifiedClaim(
                    claim=claim,
                    verdict="VERIFIED" if expected else "REFUTED",
                    method_confidence=0.90,
                    evidence=f"cymbal: {len(callers)} callers ({caller_names})",
                    method="cymbal_callers",
                )
            return None

        if ct == "CALL_CHAIN":
            chain = params.get("chain", [])
            caller = params.get("caller", "")
            callee = params.get("callee", "")
            if not chain and caller and callee:
                chain = [caller, callee]
            if len(chain) < 2:
                return None
            evidence_parts = []
            for i in range(len(chain) - 1):
                src, dst = chain[i], chain[i + 1]
                callees = cymbal.function_callees(src)
                found = any(c.get("name", c.get("symbol", "")) == dst
                            for c in callees)
                if found:
                    evidence_parts.append(f"{src}->{dst}: found")
                else:
                    evidence_parts.append(f"{src}->{dst}: NOT FOUND")
                    return VerifiedClaim(
                        claim=claim, verdict="REFUTED", method_confidence=0.85,
                        evidence=f"cymbal chain broken: {'; '.join(evidence_parts)}",
                        method="cymbal_call_chain",
                    )
            return VerifiedClaim(
                claim=claim, verdict="VERIFIED", method_confidence=0.85,
                evidence=f"cymbal chain: {'; '.join(evidence_parts)}",
                method="cymbal_call_chain",
            )

        return None

    @staticmethod
    def _cache_key(
        claim: TypedClaim, repo_path: str, language: str
    ) -> tuple:
        """Deterministic, hashable cache key for a claim."""
        return (
            claim.claim_type,
            _freeze(claim.parameters),
            repo_path,
            language,
        )
