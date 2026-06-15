# Round 2 Correctness and Edge Case Review: CCV Improvements Design Spec

Reviewed: `docs/superpowers/specs/2026-06-15-ccv-improvements-design.md`
Against: existing codebase in `code_claim_verifier/`
Focus: NEW issues not covered by round 1 fixes.

---

## [SEVERITY: major] SUSPECT asymmetric weighting interacts incorrectly with calibrator action thresholds at boundary values

**Location**: Section 2 (Calibration Impact) interacting with existing `calibrator.py` lines 33-38

**Finding**: The updated spec correctly fixes the symmetric cancellation bug by making SUSPECT-VERIFIED claims contribute full confidence to the denominator but only half to the numerator. However, this fix creates a new problem at the action threshold boundaries.

The existing calibrator thresholds are:
```python
if rate >= 0.8:
    action = "BOOST"
elif rate >= 0.5:
    action = "FLAG"
else:
    action = "OVERRIDE"
```

Consider a finding with 5 claims, all VERIFIED. 4 are normal, 1 is SUSPECT. All have method_confidence 0.85.

Without SUSPECT: rate = (0.85*5) / (0.85*5) = 1.0, action = BOOST.
With the asymmetric fix: weighted_verified = 0.85*4 + 0.85*0.5 = 3.825, weighted_total = 0.85*5 = 4.25. Rate = 3.825/4.25 = 0.9, action = BOOST.

Now consider 2 claims, both VERIFIED, one is SUSPECT. Both at 0.85.
Rate = (0.85 + 0.425) / (0.85 + 0.85) = 1.275/1.70 = 0.75. Action = FLAG (not BOOST).

And the critical edge case: 1 claim, VERIFIED, SUSPECT. At 0.85.
Rate = 0.425/0.85 = 0.50. Action = FLAG (barely).

1 claim, VERIFIED, SUSPECT. At 0.60 (ABSENCE type).
Rate = 0.30/0.60 = 0.50. Action = FLAG (exactly at boundary).

The problem is that a single SUSPECT-VERIFIED claim always produces rate = 0.5, regardless of the claim type's method_confidence. This is because the 0.5 factor cancels the confidence in the ratio (confidence * 0.5 / confidence = 0.5). For a finding with only one verifiable claim that happens to be SUSPECT-VERIFIED, the action is always FLAG, which seems too harsh. The SUSPECT mechanism is supposed to signal "the foundation is shaky," not "this is as bad as a coin flip." A single SUSPECT-VERIFIED claim with FILE_EXISTS confidence (0.99) should arguably be treated differently from one with ABSENCE confidence (0.60), but both land at exactly 0.50.

Furthermore, the 0.5 hardcoded factor is not configurable. There is no way for the caller to adjust the SUSPECT penalty strength without forking the calibrator.

**Suggestion**: Make the SUSPECT penalty factor configurable on the engine or calibrator (e.g., `suspect_discount=0.5`). Consider using a factor higher than 0.5 (like 0.7 or 0.75) so that a single SUSPECT-VERIFIED claim at high confidence still lands in BOOST territory. The current 0.5 is too aggressive for high-confidence verifiers like FILE_EXISTS. Alternatively, document that the 0.5 factor was chosen deliberately and explain the rationale for always producing rate=0.5 in the single-claim case.

---

## [SEVERITY: major] Partial recovery threshold of >50% has an off-by-one at exactly 50%

**Location**: Section 5 (Fallback and Partial Recovery), bullet points after validation

**Finding**: The spec defines three ranges:
- **all** claims assignable: proceed normally
- **>50%** assignable: proceed with valid subset
- **<50%** assignable: fall back to per-item extraction

The condition `>50%` (strictly greater than) and `<50%` (strictly less than) does not cover `exactly 50%`. For a batch with 2 claims where 1 is valid and 1 is invalid, that is 50% exactly. Neither `>50%` nor `<50%` applies.

This is a specification gap. Depending on implementation, it would either fall through to no defined behavior (bug), or one of the conditions would be implemented with `>=` or `<=`, creating implicit behavior the spec didn't document.

More concretely, with 4 claims where 2 are valid: 50% exactly. With 6 claims where 3 are valid: 50% exactly. The spec says nothing about what happens here.

**Suggestion**: Change to `>=50%` proceeds with valid subset, `<50%` falls back. Or change to `>50%` proceeds, `<=50%` falls back. Either is fine, but the spec must pick one explicitly. For the 2-claim case (1 valid, 1 invalid), the more conservative choice is to fall back, since 1 claim is too few to justify skipping re-extraction.

---

## [SEVERITY: major] _freeze() does not handle set values in parameters

**Location**: Section 3 (Caching), `_freeze()` function

**Finding**: The `_freeze()` function handles `dict`, `list`, `tuple`, and falls through to `return value` for everything else. This covers the common cases, but Python claim parameters could contain `set` values. For example, `parameters = {"scopes": {"read", "write"}}`.

A `set` is not hashable (cannot be a dict key), and `_freeze()` would return it unchanged via the fallback `return value`. When this frozen value is used as part of a dict key in the verifier cache, it raises `TypeError: unhashable type: 'set'`.

The `_freeze()` function handles `list` and `tuple` but not `set`, even though sets are a standard Python collection type that could appear in parameters. Similarly, `frozenset` is already hashable and would pass through correctly, but raw `set` would fail.

Additionally, `None`, `bool`, `int`, `float`, and `str` all pass through the fallback branch correctly (they are all hashable). So those types are fine. But `bytes`, `bytearray`, and other exotic types would also pass through. `bytearray` is unhashable and would fail at cache key time.

**Suggestion**: Add `set` handling to `_freeze()`:

```python
def _freeze(value):
    if isinstance(value, dict):
        return frozenset((k, _freeze(v)) for k, v in sorted(value.items()))
    if isinstance(value, set):
        return frozenset(_freeze(v) for v in value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value
```

Consider also adding a general fallback for unhashable types (e.g., `try: hash(value); return value; except TypeError: return str(value)`) to prevent cache key construction from crashing the entire verification pipeline.

---

## [SEVERITY: major] Topological sort edge update after deduplication of synthesized claims is unspecified

**Location**: Section 2 (Resolution Algorithm), steps 5-6

**Finding**: Step 5 says "Deduplicate synthesized claims by `(claim_type, frozen_parameters)`." Step 6 says "Topological sort the complete graph."

The dependency graph built in step 2-4 has edges pointing from dependent claims to their prerequisite claims. When synthesized claims are deduplicated, the edges must be updated to point to the surviving deduplicated claim, not the removed duplicate. The spec does not address how edge re-targeting works.

Concrete scenario: Finding has `LINE_CONTENT(path="a.py")` and `GENERATED_OR_VENDORED(path="a.py")`. Both depend on `FILE_EXISTS(path="a.py")`. During synthesis (step 3-4), two separate `FILE_EXISTS(path="a.py")` claims are created, one for each dependent. Step 5 deduplicates them into one. But the edges from `LINE_CONTENT` and `GENERATED_OR_VENDORED` originally pointed to two distinct synthesized claim objects. After deduplication, both edges must point to the single surviving claim.

If deduplication happens by replacing the graph's claim nodes with canonical representatives (e.g., using a dict keyed by `(claim_type, frozen_params)` to track the canonical instance), this works. But if deduplication just removes duplicates from a list without updating the adjacency structure, the graph has dangling edges.

The spec says "Topological sort the complete graph" in step 6, but if the graph has dangling references to removed duplicates, the sort will either fail (node not found) or produce incorrect ordering (missing edges means independent ordering where dependency ordering was needed).

**Suggestion**: Specify that deduplication works via canonicalization: maintain a mapping of `(claim_type, frozen_params) -> canonical_claim`. When building edges during synthesis, always look up the canonical instance. If a synthesized claim already exists in the map, reuse it and add the edge to the existing node. This makes step 5 and step 2-4 interleaved rather than sequential.

---

## [SEVERITY: major] Verifier cache returns the same VerifiedClaim object for duplicate claims, causing shared mutable state

**Location**: Section 3 (Caching), VerifierCache on VerificationEngine

**Finding**: The verifier cache "catches exact duplicate claims across findings in a batch" by returning a cached `VerifiedClaim` for claims with the same `(claim_type, frozen_params, repo_path, language)` key. But `VerifiedClaim` is a mutable dataclass (not frozen). The spec adds `suspect_reason` as a mutable field.

In a batch with two findings, if Finding #0 and Finding #3 both contain `FILE_EXISTS(path="config.yaml")`, the verifier runs once and caches the result. Finding #3 gets the same `VerifiedClaim` object from the cache. Now, during chaining propagation (step 9 of the resolution algorithm), if the FILE_EXISTS result is REFUTED, the engine marks its dependents as SUSPECT by setting `suspect_reason` on the dependent's VerifiedClaim. But if the cached VerifiedClaim for FILE_EXISTS is also mutated (e.g., to set `synthesized=True` or `suspect_reason` from a different finding's dependency chain), that mutation affects both Finding #0 and Finding #3's reports.

Even if the engine only mutates dependent claims (not the cached prerequisite), the cached VerifiedClaim objects are still shared across findings' `per_claim` lists. If any post-verification processing mutates them (e.g., setting `suspect_reason` based on one finding's context), the other finding's report is silently corrupted.

**Suggestion**: The verifier cache should return a copy of the cached `VerifiedClaim`, not the same object. Use `dataclasses.replace()` or `copy.copy()` when returning from cache:

```python
if key in self._cache:
    return dataclasses.replace(self._cache[key])
```

This ensures each finding gets its own instance that can be mutated independently during chaining propagation.

---

## [SEVERITY: minor] Extraction hint validation (500 chars, no built-in type names) does not prevent control characters or unicode exploits

**Location**: Section 4 (Mechanics), extraction hint validation

**Finding**: The spec says hints are validated as "max 500 chars each, must not redefine built-in type names." This catches two attack vectors (length and type name collision) but misses others:

1. **Control characters**: An extraction hint containing `\x00` (null byte), `\x08` (backspace), `\r` (carriage return without newline), or ANSI escape sequences could corrupt the LLM prompt in unpredictable ways. Some LLM APIs strip or mishandle null bytes. Backspace characters could visually hide text in log output. Carriage returns without newlines could overwrite previous prompt text in some rendering contexts.

2. **Unicode homoglyphs**: A hint containing `FILE_ЕХISTS` (with a Cyrillic E and I) would pass the "must not redefine built-in type names" check because the string is not equal to `FILE_EXISTS`. But the LLM would likely interpret it as the same type, causing confusion.

3. **Zero-width characters**: Unicode zero-width joiners (`‍`), zero-width spaces (`​`), and right-to-left marks (`‏`) could be embedded in type names or hint text to create visually identical but semantically different strings.

4. **Excessively long lines**: The 500-char limit applies to the entire hint, but a single 500-char line with no whitespace could cause formatting issues in the LLM prompt.

These are not high-probability attacks (since hints come from developers, not adversarial input), but they represent gaps in the validation logic.

**Suggestion**: Add validation for: (a) reject or strip control characters (anything with Unicode category `Cc` except `\n` and `\t`), (b) normalize Unicode to NFC before comparing against built-in type names, (c) reject type names that are confusable with built-in names (using Unicode confusable detection, or simply requiring ASCII-only type names). The simplest approach is to require type names to match `^[A-Z][A-Z0-9_]*$` and hint text to be printable ASCII plus basic whitespace.

---

## [SEVERITY: minor] Per-finding dependency isolation in batch mode conflicts with shared verifier cache semantics

**Location**: Section 5 (Verification Phase), points 1-2

**Finding**: The spec says "dependency graphs are per-finding" but "all claims from all items verified together through a single engine run (shared grep cache)." The verifier cache (Section 3) also lives on the engine instance and is shared across findings.

Consider this scenario: Finding #0 has `FUNCTION_CALLED(name="process")` which depends on `FUNCTION_EXISTS(name="process")`. The engine synthesizes `FUNCTION_EXISTS(name="process")` for Finding #0 and verifies it (VERIFIED). The result is cached.

Finding #3 also has `FUNCTION_CALLED(name="process")` which also depends on `FUNCTION_EXISTS(name="process")`. Because dependency graphs are per-finding, the engine should synthesize a separate `FUNCTION_EXISTS(name="process")` for Finding #3. But when it goes to verify this synthesized claim, the verifier cache returns the cached result from Finding #0's synthesis.

This is correct in the sense that the grep result is the same (both check the same repo). But it creates an inconsistency: the dependency graph is per-finding (so the synthesis and edge tracking happen independently), but the verification result is shared (so the actual check runs only once). The synthesized claim objects are different (per-finding isolation), but they produce identical VerifiedClaim results (from the shared cache).

This is fine for correctness as long as the per-finding dependency graph tracks edges using the per-finding synthesized claim objects, not the cached results. But it means the engine creates N synthesized claim objects for N findings that reference the same file, runs deduplication within each finding's graph, but gets the verification result from a cross-finding cache. The spec should clarify that this is intentional and explain why it is correct despite the apparent mixing of scopes.

**Suggestion**: Add a sentence to Section 5 clarifying: "The verifier cache is shared across findings (safe, since verification results are deterministic for the same claim parameters and repo). Each finding's dependency graph references its own synthesized claim objects, but the underlying verification is deduplicated via the engine-level cache."

---

## [SEVERITY: minor] Cycle detection in custom dependency registration only checks at registration time, not at synthesis time

**Location**: Section 4 (Optional Dependency Registration), last paragraph

**Finding**: The spec says "Registering a dependency that creates a cycle raises `ValueError`." This catches direct cycles at registration time (A depends on B, B depends on A). But cycles can emerge at synthesis time through parameter-based matching that registration-time validation cannot predict.

Example: Custom type `SCHEMA_EXISTS` depends on `FILE_EXISTS` via `file -> path`. Built-in rule R3 says `FUNCTION_EXISTS` (with `file`) depends on `FILE_EXISTS` via `file -> path`. No cycle exists in the registered dependency rules.

But suppose a specific claim has parameters that create a situation where synthesis generates unexpected chains. While the spec's max depth of 2 and visited set prevent infinite synthesis, they don't prevent a scenario where a synthesized claim shadows an extracted one and changes the topological ordering in unexpected ways.

More directly: the registration-time cycle check operates on the type-level graph (does type A depend on type B?). But the runtime dependency graph operates on claim instances (does this specific claim A with these parameters depend on this specific claim B with those parameters?). A cycle at the instance level without a cycle at the type level is possible if a custom verifier's dependency is defined broadly (e.g., `depends_on="FUNCTION_EXISTS"` with `source_param="name"`, `target_param="name"`) and the extracted claims happen to create a mutual dependency through parameter values.

Actually, re-examining this: the dependency rules are directional (A depends on B) and synthesis only creates prerequisites (not dependents). So a claim A with dependency on type B would synthesize a B, but the synthesized B would only synthesize further prerequisites of B's type, never back to A's type (unless B depends on A at the type level, which registration-time check catches). So instance-level cycles through parameter values alone are not possible with the current directional synthesis model.

**Note**: This finding is lower severity than initially assessed. The registration-time check is sufficient for type-level cycles, and the synthesis direction prevents instance-level cycles. Retaining as minor because the spec should explicitly state why instance-level cycles cannot occur (the directional synthesis argument), so implementers don't accidentally change the synthesis direction and introduce the vulnerability.

---

## [SEVERITY: minor] GrepCache returns mutable list references, enabling cache corruption

**Location**: Section 3 (Caching), GrepCache code snippet

**Finding**: The `grep()` function caches `list[str]` results:

```python
cache[key] = result
return result
```

And on cache hit:
```python
return cache[key]
```

Both the cache storage and cache hit return the same `list` object reference. If a caller mutates the returned list (e.g., `results = grep(...); results.append("extra")`), the cached entry is also modified, corrupting future cache lookups.

Looking at the existing verifier code, `verify_function_called` (symbol_claims.py line 59) creates a `set` from grep results: `def_matches = set(_grep(def_pattern, repo_path))`. This doesn't mutate the original list. `verify_has_callers` does the same. And `call_only = [m for m in matches if m not in def_matches]` creates a new list via list comprehension, so `matches` is not mutated.

Currently, none of the built-in verifiers mutate the grep result list. But custom verifiers could. And even built-in verifiers could be modified in the future to mutate the list (e.g., `matches.sort()` or `matches.pop()`), silently corrupting the cache.

**Suggestion**: Return a copy of the cached list on cache hit: `return list(cache[key])`. Or return a tuple instead (immutable), though this changes the return type. The cheapest fix is a defensive copy on cache hit. Document that the cache stores references and callers must not mutate returned lists.

---

## [SEVERITY: minor] source_sentence substring matching for finding_index inference is ambiguous for similar findings

**Location**: Section 5 (Fallback and Partial Recovery), point 3

**Finding**: When `finding_index` is missing, the spec says to "attempt to infer from `source_sentence` matching against the original findings text (substring match)." If two findings in a batch contain overlapping or identical reasoning text (e.g., both mention "torch.load() is called at model.py:42"), the substring match would find the `source_sentence` in multiple findings. The spec doesn't define what happens on ambiguous matches.

Possible outcomes: (a) assign to the first match (biases toward earlier findings), (b) assign to all matches (duplicates the claim across findings, inflating their metrics), (c) discard on ambiguity (treats ambiguous as unassignable). None of these is specified.

This is especially problematic for batch scenarios where a tool reports similar findings about different aspects of the same code location. The reasoning text and source_sentences could be nearly identical.

**Suggestion**: On ambiguous substring match (found in multiple findings), discard the claim and count it as unassignable. Log a warning with the claim and the matching finding indices. This is the safest behavior because incorrectly assigning a claim to the wrong finding corrupts that finding's verification report.

---

## [SEVERITY: nit] Synthesized claims with `synthesized=True` go through safe_verify but are excluded from metrics, creating a silent cost with no visible accounting

**Location**: Section 2 (Synthesized Claims) and Section 3 (Caching, VerifierCache)

**Finding**: Synthesized claims are verified (triggering grep subprocess calls and potentially LLM-adjacent processing through safe_verify), cached in the verifier cache, and included in `per_claim` for debugging. But they are excluded from report metrics. This means:

1. The `total_claims` count excludes synthesized claims, but the `per_claim` list includes them. A consumer doing `len(report.per_claim)` would get a different number than `report.total_claims`.
2. The verifier cache includes synthesized claims, so the cache size and hit rate reflect work that is invisible in the report metrics.
3. In batch mode, synthesized claims across findings consume grep cache entries and verifier cache entries, but the per-finding reports don't account for this overhead. A batch with 20 findings might synthesize 60 FILE_EXISTS claims, all of which run grep or hit cache, but the reports show 0 additional claims.

This isn't a correctness bug, but it creates a confusing mismatch between what the system does and what it reports.

**Suggestion**: Add a `synthesized_claims` count to `VerificationReport` (separate from `total_claims`) so consumers can see how many prerequisite checks were performed. Or add a diagnostic section to the report output with synthesis and cache hit statistics.
