# Round 2 Adversarial Review: Architecture and Design

**Spec**: `docs/superpowers/specs/2026-06-15-ccv-improvements-design.md`
**Focus**: Architecture, lifecycle, coupling, signature adequacy
**Round 1 fixes**: 15 issues already addressed, not re-flagged here

---

## [SEVERITY: major] VerificationEngine lifecycle is ambiguous across single vs batch verify

**Section**: 1 (VerificationEngine) + 5 (Batch)

The spec says `CodeClaimVerifier` "holds LLM function, repo path, and engine instance" and that the engine owns the registry, caches, and dependency graph. But the lifecycle of the engine across calls is never specified.

Two scenarios with different implications:

1. **Engine created once in `__init__`, reused across calls**: The verifier-level cache (`VerifierCache`) on the engine instance accumulates results across all `verify()` and `verify_batch()` calls for the lifetime of the `CodeClaimVerifier`. This means stale results if the repo changes between calls (e.g., git checkout, file edits). The spec says "No persistence across runs. No staleness risk" in the cache lifecycle section, but if the engine is a long-lived instance attribute, "run" is ambiguous. Is it per-`verify()` call or per-engine lifetime?

2. **Engine created per call**: No cache reuse between `verify()` calls, which defeats the purpose of the verifier cache for batch mode where the spec explicitly says "catches exact duplicate claims across findings in a batch."

The spec needs to define: (a) the engine is created once in `__init__` and lives with the `CodeClaimVerifier`, (b) the verifier cache is scoped per `verify()` or `verify_batch()` invocation (cleared at the start of each call), not per engine lifetime, and (c) the grep cache context is per-call (already specified via contextvars token). Without this, implementers will either leak cache across calls or fail to share cache within a batch.

---

## [SEVERITY: major] Grep cache shared across per-finding dependency graph isolation creates semantic inconsistency

**Section**: 5 (Batch, Verification Phase) + 3 (Caching)

The spec says dependency graphs are "per-finding, not shared across findings" to prevent cross-finding dependency leakage, but grep cache is shared because "grep results are repo-level facts." This creates a subtle inconsistency.

Consider: Finding #0 has a synthesized FILE_EXISTS for `model.py`. The verifier calls `os.path.isfile()` (not grep), so the file check itself is not cached. But when Finding #0's FUNCTION_EXISTS for `torch.load` in `model.py` runs, it greps for the function definition. Finding #3 also has a FUNCTION_EXISTS for `torch.load` in `model.py`, but its FILE_EXISTS dependency was REFUTED. Under the per-finding isolation rule, Finding #3's FUNCTION_EXISTS should be marked SUSPECT. However, the verifier cache (keyed by claim_type + params) will return the cached VERIFIED result from Finding #0's identical FUNCTION_EXISTS claim, bypassing the chaining logic entirely.

The problem is that the verifier cache operates at the claim level and is shared across findings, but chaining (SUSPECT marking) is per-finding. A cache hit returns a `VerifiedClaim` that was produced in a different finding's dependency context. The cached result does not carry the SUSPECT flag that the current finding's chaining rules would require.

Fix options: (a) Scope verifier cache per-finding (loses the "catches exact duplicate claims across findings" benefit), (b) Apply SUSPECT marking as a post-cache decoration (verify with shared cache, then apply per-finding chaining as a separate pass over the results), or (c) Exclude from verifier cache any claim that has dependencies in the chaining graph.

---

## [SEVERITY: major] calibrate() signature and responsibility split with engine is unclear

**Section**: 2 (Calibration Impact) + 1 (VerificationEngine)

The spec shows the asymmetric SUSPECT weighting code inline in what appears to be `calibrate()`:

```python
for c in verifiable:
    weighted_total += c.method_confidence
    if c.verdict == "VERIFIED":
        factor = 0.5 if c.suspect_reason else 1.0
        weighted_verified += c.method_confidence * factor
```

But `calibrate()` currently lives in `calibrator.py` as a standalone function that takes `list[VerifiedClaim]` and returns a `VerificationReport`. The engine calls `calibrate()` after verification. The spec also says synthesized claims should be "excluded from report metrics" but doesn't say who is responsible for that filtering.

Two design questions are unresolved:

1. Does `calibrate()` gain responsibility for filtering `synthesized=True` claims, or does the engine filter before passing to `calibrate()`? If the engine filters, `calibrate()` never sees synthesized claims and `per_claim` won't include them (contradicting "they appear in `per_claim` for debugging transparency"). If `calibrate()` filters, it needs to know about `synthesized`, creating coupling to the chaining feature.

2. `VerificationReport` counts (`verified`, `refuted`, `verifiable_claims`) need to exclude synthesized claims, but `per_claim` needs to include them. The current `calibrate()` computes counts from its input list and sets `per_claim=verified_claims` (line 52 of calibrator.py). This means either `calibrate()` needs two lists (all claims for `per_claim`, filtered claims for metrics), or the engine passes the full list and `calibrate()` partitions internally.

The spec should specify: `calibrate()` receives all claims (including synthesized), partitions internally by `synthesized` flag, computes metrics from non-synthesized only, and includes all claims in `per_claim`.

---

## [SEVERITY: major] Verifier function signature (claim, repo_path, language) cannot support chaining context

**Section**: 2 (Chaining) + 4 (Custom Types, Verifier Function Contract)

The spec preserves the existing `(claim, repo_path, language) -> VerifiedClaim` signature for all verifiers and declares "No changes to their internals." But chaining creates a scenario where a verifier might benefit from knowing the result of its prerequisite.

Today this is not a problem because chaining only does post-hoc SUSPECT flagging. But the spec also says custom types can declare dependencies. A custom verifier for `DATABASE_QUERY` that depends on `FILE_EXISTS` might want to know whether the file actually exists before running an expensive check (e.g., parsing SQL from the file). Without access to prerequisite results, the custom verifier must redundantly check file existence itself.

More concretely: the built-in `verify_function_exists` already checks `os.path.isfile(resolved)` internally (line 33 of symbol_claims.py) even though R3 declares FILE_EXISTS as its prerequisite. With chaining, this check is redundant. If the prerequisite was REFUTED, the engine marks FUNCTION_EXISTS as SUSPECT anyway. But the verifier still runs, potentially returning REFUTED for a different reason (function not found in non-existent file), and the evidence string will say "No definition found for X" rather than "File does not exist."

This is not a blocker for v1 since the signature stays stable and SUSPECT flagging works post-hoc. But the spec should acknowledge this as a known limitation and note that a future v2 could add an optional `context: dict` parameter (or use contextvars) to pass prerequisite results to verifiers that want them.

---

## [SEVERITY: minor] safe_path rejects repo root itself as a valid path

**Section**: implicit, affects synthesized FILE_EXISTS claims

`safe_path` in security.py (line 9) checks `resolved.startswith(abs_repo + os.sep)`. If `claim_path` is `""` or `"."`, then `resolved == abs_repo` (no trailing sep), and `safe_path` returns `None`. This means a synthesized FILE_EXISTS with an empty `path` parameter (from a dependent claim that has `file: ""`) will be REFUTED with "Path traversal detected" rather than a more accurate "empty path" error.

This is pre-existing behavior, but the chaining system amplifies it: every dependent claim with a missing/empty file parameter will trigger a synthesized FILE_EXISTS that gets REFUTED for "path traversal," and every downstream claim gets SUSPECT. The evidence string is misleading because there is no actual traversal attempt.

Fix: Before synthesizing, check if the source parameter is empty/missing and skip synthesis (or mark the dependent as UNVERIFIABLE directly). Alternatively, have `safe_path` distinguish between "empty path" and "path traversal" in its return value.

---

## [SEVERITY: minor] _freeze() with frozenset loses dict key ordering, creates non-deterministic cache keys

**Section**: 3 (Caching, VerifierCache)

The `_freeze()` function converts dicts to `frozenset((k, _freeze(v)) for k, v in sorted(value.items()))`. The `sorted()` makes it deterministic for string keys. However, if parameter values are themselves dicts with mixed-type keys (e.g., int and str), `sorted()` will raise `TypeError` in Python 3.11+. While this is unlikely in practice (claim parameters are typically `str -> str|int|bool`), the spec shows `_freeze` as a general recursive function with no type constraints documented.

Also, `frozenset` of tuples is not ordered. Two frozensets with the same elements are equal regardless of insertion order, so this is actually correct for cache key equality. But `frozenset` comparison is O(n) per lookup rather than O(1) for tuples. For claim parameters that are consistently structured, a `tuple(sorted(...))` would be both deterministic and faster for cache lookups.

Fix: Use `tuple(sorted(value.items()))` instead of `frozenset(...)` in `_freeze()`. This is faster for dict-key use (tuples hash in O(n) once, frozensets hash in O(n) once, but tuple comparison is O(n) sequential vs frozenset's O(n) set operations). Minor performance difference, but since this is on the hot path for every claim verification, it is worth getting right.

---

## [SEVERITY: minor] register_dependency() allows adding dependencies to built-in types, potentially breaking invariants

**Section**: 4 (Custom Claim Types, Optional Dependency Registration)

The spec shows `register_dependency("DATABASE_QUERY", depends_on="FILE_EXISTS", ...)` and says "Registering a dependency that creates a cycle raises ValueError." But there is no mention of restricting which types can be made dependent. A user could call:

```python
verifier.register_dependency("FILE_EXISTS", depends_on="DATABASE_QUERY", source_param="path", target_param="file")
```

This makes FILE_EXISTS depend on a custom type, which means every synthesized FILE_EXISTS prerequisite now also needs a synthesized DATABASE_QUERY prerequisite. This could create surprising behavior where registering a custom type changes the verification behavior of built-in claims that were previously working correctly.

Fix: Either (a) disallow adding new dependencies to built-in types via `register_dependency()`, or (b) document that built-in dependency rules are immutable and `register_dependency()` only accepts custom types as the dependent, or (c) at minimum warn when a dependency is added to a built-in type.

---

## [SEVERITY: minor] Batch extraction substring matching for finding_index inference is fragile

**Section**: 5 (Batch, Fallback and Partial Recovery)

When `finding_index` is missing from a claim, the spec says to "attempt to infer from `source_sentence` matching against the original findings text (substring match)." This has two problems:

1. If two findings contain similar reasoning text, a `source_sentence` could match multiple findings. The spec doesn't say which one wins (first match? shortest match? ambiguous = discard?).

2. The `source_sentence` is extracted by the LLM and truncated to 500 chars (line 105 of extractor.py). The original reasoning text could be up to 4000 chars (line 63 of extractor.py). A 500-char substring match against 4000-char texts from multiple findings could produce false positives, especially for common phrasings like "the function is called at..."

Fix: Define the ambiguity resolution: if `source_sentence` matches multiple findings, discard (treat as unassignable). Also note that substring matching should be case-sensitive and require a minimum match length to avoid trivial matches.

---

## [SEVERITY: nit] as_tools() and default_tools() create two code paths for schema generation

**Section**: 6 (CLI and Tool Schemas)

The spec defines `as_tools()` as an instance method that includes custom types, and `default_tools()` as a classmethod for built-in-only schema. This means two separate code paths for generating tool schemas. If a new built-in claim type is added, both paths need updating. If `as_tools()` internally calls the same generation logic with `self.engine.registry` and `default_tools()` calls it with `VERIFIER_REGISTRY`, the duplication is manageable. But the spec doesn't specify this shared implementation, so an implementer might write two independent schema generators.

Fix: Specify that both methods use a shared `_generate_tools(registry)` internal function, differing only in which registry they pass.

---

## [SEVERITY: nit] Engine's verify_all returns list[VerifiedClaim] but calibrate() is called separately

**Section**: 1 (VerificationEngine)

The spec shows the engine architecture as:

```
engine.verify_all(claims, repo_path, language)
    -> return list[VerifiedClaim]
```

Then `CodeClaimVerifier.verify()` must call `calibrate()` on the result. But for batch mode, section 5 says "Each group gets its own `calibrate()` call for per-item reports." This means `CodeClaimVerifier` is responsible for grouping claims by finding index and calling `calibrate()` per group. The engine just verifies.

This is fine architecturally, but it means `CodeClaimVerifier.verify_batch()` needs to do significant orchestration: batch extraction, finding-index assignment, fallback handling, per-finding dependency graph construction (calling the engine per-finding for chaining isolation), and per-finding calibration. The engine's `verify_all()` as specified doesn't support per-finding isolation. it takes a flat list of claims.

Either the engine needs a `verify_finding(claims_for_one_finding)` method that handles chaining for a single finding's claims (called per-finding by `verify_batch`), or `verify_all` needs a `groups: dict[int, list[TypedClaim]]` parameter to handle per-finding isolation internally. The current spec implies a flat `verify_all` but requires per-finding chaining isolation, which is contradictory.
