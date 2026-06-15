# Adversarial Review: CCV Improvements Design Spec

**Spec**: `docs/superpowers/specs/2026-06-15-ccv-improvements-design.md`
**Reviewers**: Architecture specialist, Correctness specialist, Security specialist
**Auditor**: Red-team auditor (severity calibration, blind spot detection)

---

## Top 5 Findings (Priority Order)

### 1. SUSPECT confidence multiplier is mathematically broken
**Severity**: Major (highest real-world impact)
**Section**: 2 (Claim Chaining, Calibration Impact)

The spec says "SUSPECT claims contribute to the verification rate at their reduced confidence (original * 0.5)." This has zero effect on the calibrated confidence rate for VERIFIED claims.

The existing formula in `calibrator.py:29-31`:
```
rate = weighted_verified / weighted_total
```

For a SUSPECT-VERIFIED claim, 0.5x applies to both numerator and denominator, canceling out. For a SUSPECT-REFUTED claim, 0.5x reduces only the denominator, making the rate go *up* (opposite of intent).

**Fix**: Either (a) SUSPECT-VERIFIED claims contribute full confidence to `weighted_total` but reduced confidence to `weighted_verified`, or (b) add a separate penalty term outside the existing formula, or (c) count SUSPECT-VERIFIED as fractionally verified in the count-based metrics.

---

### 2. GrepCache module-level global state is thread-unsafe
**Severity**: Major (consensus across all 3 reviewers)
**Section**: 3 (Caching)

The grep cache uses `global _cache` with `enable_cache()` / `disable_cache()` free functions. Concurrent `VerificationEngine` instances in the same process share and corrupt each other's cache. The spec adds `as_tools()` for agent framework integration, where concurrent tool execution is standard.

**Fix**: Use `contextvars.ContextVar` instead of module-level global. The engine sets a context token on entry and resets on exit. No verifier signature changes needed, thread-safe, re-entrant.

---

### 3. Synthesized claim parameter name mapping gap
**Severity**: Major
**Section**: 2 (Claim Chaining, Rules)

Rule R1 copies `file` or `path` values from dependent claims to synthesized FILE_EXISTS claims. But `verify_file_exists` reads `claim.parameters.get("path", "")`. If a dependent claim has `file` but not `path`, the synthesized claim gets the wrong parameter name, and the verifier falls back to empty string.

Additionally, R1 is overly broad: FILE_CLASSIFICATION only checks path patterns (never reads the file), but R1 would synthesize a FILE_EXISTS dependency for it.

**Fix**: (a) Replace R1 with explicit per-type rules (as R2-R6 already are). (b) Define parameter name mapping for synthesized claims (e.g., dependent's `file` maps to FILE_EXISTS's `path`). (c) Mark synthesized claims with `synthesized=True` and exclude from report metrics to avoid phantom entries.

---

### 4. Verifier cache key uses hash() with collision risk
**Severity**: Major (consensus across all 3 reviewers)
**Section**: 3 (Caching, VerifierCache)

`hash(params_frozen)` in the cache key introduces collision risk and fails on nested dicts/lists. Two different parameter sets with the same hash return wrong cached results silently.

**Fix**: Use the frozen tuple directly as the cache key. Add a recursive `freeze()` function for nested structures (dicts to frozenset, lists to tuples).

---

### 5. Eval calibration curve assumes continuous confidence, but verifiers use discrete hardcoded values
**Severity**: Major (blind spot, no reviewer caught this)
**Section**: 7 (Evaluation Framework)

Every verifier hardcodes `method_confidence` (0.99, 0.95, 0.90, 0.85, 0.80, 0.70, 0.65, 0.60). The calibration curve will be a step function with ~8 points, not the smooth curve the sample output shows. For ICSE peer review, this methodology flaw would be flagged immediately.

**Fix**: Either (a) make confidence values continuous (adjust based on match quality, not just claim type), or (b) change eval methodology to per-type accuracy reporting instead of calibration curves.

---

## Additional Findings Worth Addressing

### 6. Batch extraction partial failure handling is underspecified (Major)
One bad `finding_index` triggers full re-extraction. Define partial recovery: accept valid indices, drop invalid ones, re-extract only orphaned items.

### 7. Extraction-verification coupling via dynamic claim type validation (Major)
`_parse_extraction_output` needs the engine's registry to validate custom types, but extraction is currently a pure module. Fix: pass `valid_types: frozenset[str]` as a parameter.

### 8. Unbounded recursive synthesis needs cycle guard (Major)
Custom dependency registration can create cycles. Add `max_synthesis_depth=2`, visited set during synthesis, cycle detection in augmented graph.

### 9. Batch prompt delimiter collision (Minor)
`--- Finding #N ---` delimiters could appear in reasoning text. Use a more unique delimiter or structured JSON format for batch input.

### 10. Batch verification shared dependency graph allows cross-finding dependency satisfaction (Minor, blind spot)
A FILE_EXISTS from Finding #0 can satisfy dependencies in Finding #3. Clarify whether this is intentional (optimization) or a bug.

### 11. Lockfile substring matching amplified by caching (Minor, pre-existing)
`_parse_go_sum` uses `package in parts[0]` (substring). `"fmt"` matches `"github.com/some/fmtlib"`. With caching, the false positive persists across the batch.

---

## Severity Adjustments (Red-Team Auditor)

| Original | Adjusted | Finding |
|----------|----------|---------|
| Critical | **Major** | GrepCache global state (all 3 reviews inflated) |
| Critical | **Major** | Recursive synthesis loops (requires user misconfiguration) |
| Critical | **Major** | hash() cache collision (near-zero practical probability) |
| Critical | **Major** | Prompt injection via hints (developer API, not untrusted input) |
| Major | **Minor** | Custom verifier filesystem access (trusted developer code) |
| Major | **Minor** | CLI stdin limits (local tool, not attack surface) |
| Major | **Minor** | Eval fixture symlinks (developer-chosen path) |
| Major | **Minor** | Grep pattern sanitization (existing code already escapes) |
| Major | **Minor** | as_tools() classmethod vs instance (design clarity, not crash) |
| Major | **Minor** | Backwards compat break in _grep (private API, no obligation) |

---

## Recommendations Before Implementation

1. **Fix the SUSPECT calibration formula** before writing code. This is a design-level decision that affects the calibrator API.
2. **Switch grep cache to contextvars** in the spec. Trivial change, prevents a real concurrency bug.
3. **Replace R1 with explicit per-type rules** and define parameter name mapping for synthesized claims.
4. **Drop hash() from cache keys**, use frozen tuples directly.
5. **Decide on calibration methodology** for the eval framework: per-type accuracy tables vs continuous confidence curves.
6. **Add cycle guard and depth limit** to dependency synthesis.
7. **Define partial recovery** for batch extraction failures.
