# Round 4 Security and Robustness Review: CCV Improvements Design Spec

Reviewer: adversarial-security (round 4)
Date: 2026-06-15
Scope: Attempted to prove Round 3 auditor wrong ("no Round 4 needed"). Could not.
Threat model: developer-facing Python library, not a web service.

---

## Verdict: No new findings. The Round 3 auditor was right.

### What I checked

1. **Synthesized claim filtering in calibration (Round 3 Fix 1)**: Confirmed fixed. Lines 111-122 of the spec now show `real_claims = [c for c in verified_claims if not c.synthesized]` before building the verifiable list. The engine passes the full list to `calibrate()`, which filters internally. Counts exclude synthesized, `per_claim` includes them. `calibrator.py` is now in the Modified Files table (line 539).

2. **Batch verification architecture (Round 3 Fix 2)**: Confirmed fixed. Lines 290-297 now explicitly state "shared caches but per-finding dependency resolution." The architecture is: one grep cache context + one verifier cache for the batch, separate dependency graph per finding, `dataclasses.replace()` for independent SUSPECT marking. No more "single engine run" ambiguity.

3. **`safe_path` edge cases**: Checked empty string, dot, and exact-repo-root inputs. All return `None` correctly due to the `abs_repo + os.sep` prefix check. No bypass possible.

4. **Grep command injection via claim parameters**: `subprocess.run` with list args (no `shell=True`). Pattern and path are separate list elements. No injection vector.

5. **`_freeze()` correctness**: Depth cap at 20, `str()` fallback for deeply nested values. Prior rounds flagged the theoretical `str()` collision risk but correctly dismissed it (claim parameters are JSON-derived, always shallow). `sorted(value.items())` is safe because JSON keys are always strings.

6. **Chaining rule parameter semantics**: Verified that R4/R5 (FUNCTION_CALLED/HAS_CALLERS -> FUNCTION_EXISTS) correctly synthesize claims with only `name`, not `file`. This means synthesized FUNCTION_EXISTS claims search the whole repo, which matches the behavior of FUNCTION_CALLED (also repo-wide). No false dependency chain through R3 (which requires `file` parameter to fire).

7. **`dataclasses.replace()` shallow copy safety**: Confirmed that SUSPECT propagation only mutates `suspect_reason` (a VerifiedClaim field), never `claim.parameters` (TypedClaim). Shared TypedClaim references are safe because the chaining layer never mutates them.

8. **Custom dependency cycle detection at registration time**: Confirmed that the spec says `register_dependency()` raises `ValueError` on cycles. Built-in rules form a DAG with FILE_EXISTS as a leaf (no incoming edges). Cycle detection at registration time on the type-level graph is sound.

9. **Batch language handling**: Each finding has its own `finding_file` and therefore its own language. Per-finding dependency graphs (already specified) imply per-finding `verify_all()` calls with per-finding language. Verifier cache keys include language (line 189). Two identical claims from different-language findings are cached separately. Correct by construction.

10. **Provider API key leakage**: Spec explicitly states keys are env-only (never CLI flags), and providers must not log headers or include keys in error messages (lines 361-362). Sufficient for a developer-facing library.

### Deferred items from Round 3 (still correctly deferred)

The following Round 3 findings were marked as "can be addressed during implementation" by the red team auditor. I agree with that assessment. None would cause an implementer to build the wrong thing:

- Confusion matrix axis labeling (nit, one-line doc fix)
- ABSENCE scope="file" fallback to repo-wide search (existing code bug, not a spec design issue)
- Batch delimiter injection via finding_file containing `>>>` (requires pathological filenames from the developer themselves)
- CLI "stream" language for verify-batch (misleading but not incorrect)
- register() custom-to-custom collision check (straightforward implementation-time decision)
- Eval Stage 2 chaining scope (paper-writing decision, not implementation ambiguity)

### One observation (not a finding)

The `errored` count is not explicitly listed in the synthesized claim exclusion clause (line 122 says "Counts (verified, refuted, verifiable_claims, total_claims) exclude synthesized claims" but omits `errored`). Any implementer reading the filtering pattern would apply it to `errored` as well. If they don't, and a synthesized claim errors, you could theoretically get `errored > total_claims`, which is cosmetically wrong but functionally harmless. Not worth a spec revision.

### Conclusion

The spec has been through three rounds of adversarial review with ~25 issues found and fixed. The two major issues from Round 3 (synthesized claim calibration leak and batch architecture contradiction) are properly resolved. The remaining deferred items are all minor/nit severity and correctly categorized as implementation-time decisions. The spec is ready for implementation.
