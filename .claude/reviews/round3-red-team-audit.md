# Round 3 Red Team Audit

## 1. Overall Assessment

The spec is ready for implementation with two targeted fixes. After three rounds, the design is solid. The remaining findings fall into two categories: (a) two real design gaps that would cause implementer confusion and (b) a handful of minor clarification requests that are helpful but not blocking.

This does not need a Round 4. The two real issues can be fixed in-line and don't require another full review cycle.

## 2. Consensus Findings

Three findings were flagged by multiple reviewers. I code-traced each one against the existing codebase to verify.

### 2a. Synthesized claims leak into calibration (Arch + Correctness: both MAJOR)

**Verdict: Real. Must fix.**

Both reviewers independently identified the same gap. The calibration pseudocode in Section 2 iterates `for c in verifiable` without filtering `synthesized=True` claims. I verified the existing `calibrator.py` (lines 14-31): it builds `verifiable` as `[c for c in verified_claims if c.verdict != "UNVERIFIABLE"]` and feeds that directly into weighted sums. There is no synthesized filter.

The spec says synthesized claims are "excluded from report metrics" but never specifies WHERE this filtering happens: inside `calibrate()`, or before calling it. Additionally, `calibrator.py` is not listed in the Modified Files table (Section 7), which means an implementer following the file change list would skip it entirely.

The arch reviewer and correctness reviewer arrived at this independently with the same code trace. This is a genuine design gap, not a theoretical concern.

### 2b. Single engine run vs. per-finding dependency isolation (Arch + Correctness: both MAJOR)

**Verdict: Real. Must fix.**

Both reviewers flagged that Section 5 simultaneously requires "a single engine run" and "per-finding dependency graphs." I confirmed this is architecturally contradictory as stated. The current codebase has no batch mode, so there is no existing code to disambiguate the intent.

The resolution is straightforward (both reviewers converged on the same answer: shared grep cache + shared verifier cache + per-finding dependency graphs), but the spec must state it explicitly. An implementer reading "single engine run" would build one graph and get cross-finding dependency leakage.

### 2c. Confusion matrix axis orientation (Correctness nit + Security nit)

**Verdict: Real but not blocking.**

Both flagged that the confusion matrix JSON doesn't label which axis is predicted vs. actual. They're right, but this is a one-line fix ("outer key is ground truth, inner key is predicted") and is genuinely a nit. It would not cause implementation bugs; it would cause documentation ambiguity when writing the ICSE paper.

## 3. Severity Calibration

### Inflation detected

**Batch delimiter injection (Correctness: MINOR):** Slightly inflated. The scenario requires a file literally named `a>>>b.py` being passed as `finding_file`. This is a developer-facing library where the developer provides their own file paths. The finding is technically correct but the risk is near-zero. Appropriate severity: nit, not minor.

**Batch fallback doubles LLM cost (Security: MINOR):** Not inflated. This is a legitimate design concern. A developer unaware of batch extraction failures could see 10,001 LLM calls instead of ~1,667. A circuit breaker or at minimum a loud warning is warranted. However, this is a quality-of-life concern, not a correctness or security issue. Severity is correctly calibrated as minor.

**CLI streaming semantics (Security: MINOR):** Correctly calibrated. The word "stream" in the CLI spec is misleading since adaptive batching requires buffering all items. This needs a clarification, not a code fix.

**register() collision check (Security: MINOR):** Correctly calibrated. The code-traced scenario (two plugins registering the same custom type) is realistic in library integration contexts. The fix is a two-line change to the collision check.

### No inflation detected

The ABSENCE file-scope fallback finding (Arch + Correctness: both MINOR) is correctly severity-calibrated. I verified the code: `security_claims.py` line 15 does fall back to `repo_path` when the file doesn't exist. This is an existing bug the spec should acknowledge, whether through a chaining rule or a verifier fix.

## 4. Final Fixes Needed Before Implementation

Only two items must be fixed. Everything else can be deferred to implementation-time judgment calls.

### Fix 1: Synthesized claim filtering in calibration

Add `calibrator.py` to the Modified Files table. Add one of these to Section 2:
- Option A: Specify that `calibrate()` receives a pre-filtered list (engine strips synthesized claims before calling calibrate, then appends them to `per_claim` afterward).
- Option B: Update the calibration pseudocode to filter: `verifiable = [c for c in verified_claims if c.verdict != "UNVERIFIABLE" and not c.synthesized]`.

Either is fine. The spec just needs to pick one.

### Fix 2: Batch verification architecture

Replace the sentence "All claims from all items verified together through a single engine run" with something like: "`verify_batch()` opens one grep cache context and one verifier cache for the entire batch, but builds a separate dependency graph per finding. 'Single engine run' means single cache lifecycle, not single dependency graph." This resolves the contradiction without changing the design intent.

### Everything else

The remaining findings (confusion matrix labeling, ABSENCE file-scope fallback, delimiter injection, streaming semantics, register() collisions, eval Stage 2 chaining scope) are all legitimate observations that can be addressed during implementation without spec revision. None of them represent ambiguity severe enough to cause an implementer to build the wrong thing.

## 5. Blind Spots

No significant blind spots. The three reviewers covered architecture, correctness/edge cases, and security/robustness. The spec's surface area is well-covered for a Round 3 review.

One minor gap: no reviewer examined the `_freeze()` function for correctness with unhashable custom parameter types (e.g., a parameter value that is a custom object with no `__eq__`). The depth-20 cap handles deep nesting, but the `str()` fallback at depth 20 means two structurally different deeply-nested values could collide in the cache if their `str()` representations match. This is extremely unlikely in practice (claim parameters are JSON-derived) and not worth blocking on.
