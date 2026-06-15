# Round 4 Architectural Review

Reviewer: adversarial-arch (round 4)
Scope: Full spec review against all codebase files. Looking for new issues not covered by the ~25 fixes from Rounds 1-3.

---

## [SEVERITY: major] `synthesized` flag on VerifiedClaim contaminates verifier cache across findings in batch mode

**Location:** Section 2 (Type Changes, Synthesized Claims), Section 3 (VerifierCache), Section 5 (Verification Phase step 3)

The verifier cache is keyed by `(claim_type, frozen_params, repo_path, language)` and stores `VerifiedClaim` objects. The spec says the cache stores "pre-chaining" results (before SUSPECT marking). But `synthesized` is not part of "chaining" as the spec defines it. Chaining refers to SUSPECT propagation (step 9 of the resolution algorithm). Synthesis happens at step 3 (dependency graph construction), BEFORE verification (step 8) and caching. An implementer would reasonably set `synthesized=True` on the `VerifiedClaim` immediately after verifying a synthesized claim, and then cache that result.

This creates a correctness bug in batch mode:

1. Finding #0 has `FUNCTION_CALLED("foo")`. R4 triggers, synthesizing `FUNCTION_EXISTS("foo")`.
2. Engine verifies the synthesized `FUNCTION_EXISTS("foo")`, gets a `VerifiedClaim`, sets `synthesized=True`, caches it.
3. Finding #1 has an LLM-extracted `FUNCTION_EXISTS("foo")` (same type, same params, different origin).
4. Engine looks up cache: hit. Returns `dataclasses.replace()` copy. The copy has `synthesized=True`.
5. Finding #1's calibrator filters this claim out of metrics because `synthesized=True`. But the LLM genuinely asserted this claim. Its contribution to the verification rate is silently dropped.

The root cause: `synthesized` is a per-claim-instance property (how the claim entered the dependency graph), not a verification-result property. But it's stored on `VerifiedClaim` and the cache doesn't differentiate between synthesized and extracted claims with identical type+params.

The spec explicitly handles the analogous problem for `suspect_reason` by noting the cache stores "pre-chaining" results. But "pre-chaining" naturally reads as "before SUSPECT propagation" (step 9), not "before synthesis marking." The spec needs to explicitly state that BOTH `synthesized` and `suspect_reason` are set AFTER cache retrieval, on the `dataclasses.replace()` copy. The cached entry always has `synthesized=False` and `suspect_reason=None`.

A secondary issue in the same area: `dataclasses.replace()` is a shallow copy, so `copy.claim` still references the cached `TypedClaim` object. In batch mode, the cached `TypedClaim` may have a different `source_sentence` and `id` than the actual claim being processed. The cache hit should also swap the `claim` reference: `dataclasses.replace(cached, claim=actual_typed_claim, synthesized=..., suspect_reason=None)`.

**Fix:** Add this sentence to Section 3 (VerifierCache): "The cached `VerifiedClaim` always has `synthesized=False` and `suspect_reason=None`. After cache retrieval, the engine sets both fields on the `dataclasses.replace()` copy and swaps the `claim` reference to the actual `TypedClaim` being processed. This prevents a synthesized claim from one finding from contaminating the cache for an extracted claim with the same parameters in another finding."

---

## Summary

One new finding. The Round 3 red-team auditor was almost right that no Round 4 was needed. The two fixes they required (synthesized claim filtering in calibration, batch architecture clarification) were correctly applied in the current spec. But the batch architecture fix (shared verifier cache across findings) interacted with the `synthesized` flag in a way that wasn't visible until you trace through cross-finding cache sharing with mixed synthesized/extracted claims of the same type.

Everything else in the spec is solid. The dependency rules are consistent with the existing verifier code. The cache lifecycle is well-defined. The parameter name mapping prevents the known `file` vs `path` mismatch. The extraction changes are backward-compatible. The eval framework design is coherent (the deferred nits from Round 3 remain valid but non-blocking).
