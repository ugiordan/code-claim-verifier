# Round 4: Correctness Deep-Dive Review

Reviewer: adversarial-correctness (round 4)
Date: 2026-06-15
Scope: Line-by-line correctness audit of calibration pseudocode, batch verification flow, and dependency resolution algorithm. Only new findings with real implementation impact.
Prior rounds: ~25 issues found and fixed across rounds 1-3. Round 3 auditor said "ready for implementation."

---

## [SEVERITY: major] Verifier cache does not preserve the `synthesized` flag per-claim, causing metric contamination in batch mode

**Location:** Section 3 (Caching, VerifierCache) and Section 5 (Batch Verification Phase, step 3)

The verifier cache stores the pre-chaining `VerifiedClaim` result, keyed by `(claim_type, frozen_params, repo_path, language)`. The `synthesized` flag is a field on `VerifiedClaim` (Section 2, line 94). The cache key does not include `synthesized`, which is correct since the raw verification result is identical regardless of whether the claim was synthesized.

The problem: the cached `VerifiedClaim` carries whatever `synthesized` value it had when first stored. On cache hit, `dataclasses.replace()` copies all fields as-is, including `synthesized`. The spec only mentions `dataclasses.replace()` in the context of SUSPECT marking isolation, not for correcting the `synthesized` flag.

Concrete failure scenario in batch mode:

1. Finding #0 has LLM-extracted FILE_EXISTS(path="model.py"). Engine verifies it, result has `synthesized=False`. Cached.
2. Finding #3's dependency resolution synthesizes FILE_EXISTS(path="model.py"). Engine hits cache, gets a copy via `dataclasses.replace()`. The copy has `synthesized=False` (from the cached result). But this claim was synthesized by the engine, not extracted by the LLM.
3. `calibrate()` filters with `real_claims = [c for c in verified_claims if not c.synthesized]`. Finding #3's synthesized FILE_EXISTS passes the filter because `synthesized=False`.
4. This phantom claim inflates Finding #3's `weighted_total` by 0.99 and (if VERIFIED) `weighted_verified` by 0.99, distorting the confidence score. It also inflates `total_claims` and `verified` counts.

The reverse scenario is equally bad: if a synthesized claim populates the cache first, subsequent real (LLM-extracted) claims with the same params get `synthesized=True` and are excluded from metrics, deflating the score.

**Fix:** After retrieving from the verifier cache and calling `dataclasses.replace()`, the engine must explicitly set `synthesized` to match the current claim's origin. Something like:

```python
cached = self._verifier_cache[key]
result = dataclasses.replace(cached, synthesized=is_synthesized_claim)
```

The spec should state that the `dataclasses.replace()` call sets both `suspect_reason` (for chaining) AND `synthesized` (to match the claim's origin). This is load-bearing for calibration correctness.

---

## [SEVERITY: minor] Multiple matching prerequisites create ambiguous dependency edges with unspecified SUSPECT propagation

**Location:** Section 2 (Resolution Algorithm, steps 3 and 9)

Step 3 says: "if the dependent claim exists but no matching prerequisite was extracted, synthesize it." This checks for the existence of ANY matching prerequisite, and if found, skips synthesis. But the spec does not define how the dependency edge is constructed when multiple matching prerequisites exist.

Example: the LLM extracts FUNCTION_CALLED(name="foo") and two FUNCTION_EXISTS claims: FUNCTION_EXISTS(name="foo", file="bar.py") and FUNCTION_EXISTS(name="foo", file="baz.py"). Rule R4 matches on `name`. Both FUNCTION_EXISTS claims match. Does FUNCTION_CALLED depend on both? Or just the first?

If both are edges: Step 9 propagates SUSPECT when "a dependency is REFUTED." If FUNCTION_EXISTS(file="bar.py") is REFUTED but FUNCTION_EXISTS(file="baz.py") is VERIFIED, FUNCTION_CALLED becomes SUSPECT because one dependency is REFUTED. This is semantically wrong: the function exists in baz.py, so FUNCTION_CALLED's prerequisite is satisfied.

If only the first match: the result depends on iteration order, which is non-deterministic (dict ordering, list ordering of extracted claims).

The practical impact is low because LLMs rarely extract duplicate claims for the same function name with different files, but the algorithm needs a defined behavior for correctness. The most logical semantics for existence-checking dependencies is ANY-match: SUSPECT propagation should fire only when ALL matching prerequisites are REFUTED, not when any single one is.

**Fix:** Specify: "When multiple prerequisite claims match a dependency rule, the dependent is marked SUSPECT only if ALL matching prerequisites are REFUTED. If any matching prerequisite is VERIFIED, the dependency is considered satisfied."

---

## [SEVERITY: nit] `errored` count not listed among counts that exclude synthesized claims

**Location:** Section 2 (Calibration Impact, line 122)

The spec says: "Counts (verified, refuted, verifiable_claims, total_claims) exclude synthesized claims." The `errored` count in the existing `calibrate()` function (calibrator.py line 17: `errored = sum(1 for c in verified_claims if c.error)`) is not mentioned. If `errored` counts synthesized claims that errored, it's inconsistent with the other counts.

This has minimal practical impact because `errored` is informational and not used in the confidence calculation (`rate`, `action`). Synthesized claims rarely error (FILE_EXISTS either succeeds or is REFUTED cleanly). But for consistency, `errored` should use the same `real_claims` filter.

**Fix:** Add `errored` to the exclusion list: "Counts (verified, refuted, verifiable_claims, total_claims, errored) exclude synthesized claims."

---

## Summary

The Round 3 auditor was mostly right. The spec is clean. One genuine correctness bug survived: the verifier cache leaks `synthesized` flag values across claims in batch mode, which directly undermines the synthesized claim filtering in calibration. The multiple-prerequisites ambiguity is a design gap that should be closed for completeness but has low practical impact. The errored count is a consistency nit.

Total new findings: 1 major, 1 minor, 1 nit.
