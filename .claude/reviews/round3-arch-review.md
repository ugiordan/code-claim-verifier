# Round 3 Architectural Review

## [SEVERITY: major] calibrator.py missing from Modified Files and synthesized claim filtering unspecified

The spec states in Section 2 (Synthesized Claims): "excluded from report metrics (verified, refuted, verifiable_claims counts)." It also specifies asymmetric SUSPECT weighting in the Calibration Impact subsection. Both of these require modifying `calibrator.py`.

Problem 1: `calibrator.py` does not appear anywhere in the Modified Files tables (neither Section 1 nor Section 7). An implementer following the file change lists would not know to touch the calibrator.

Problem 2: The spec never specifies WHERE synthesized claims get filtered out. The calibrator code snippet (lines 112-117) only shows SUSPECT weighting logic. The existing `calibrate()` function receives a flat `list[VerifiedClaim]` and counts everything. Someone implementing this would need to add filtering like:

```python
non_synth = [c for c in verified_claims if not c.synthesized]
```

But the spec doesn't say whether this filtering happens inside `calibrate()` (requiring a signature-aware change) or before calling it (in the engine). If it's inside calibrate, then `per_claim` (which the spec says should include synthesized claims "for debugging transparency") would also be filtered. If it's before, the engine is responsible, but then `calibrate()` never sees synthesized claims at all and can't include them in `per_claim`.

This is a design gap: the spec needs to either (a) add calibrator.py to the modified files list and specify that `calibrate()` filters synthesized claims from metric computation while keeping them in `per_claim`, or (b) specify that the engine strips synthesized claims before calling calibrate and handles `per_claim` assembly itself.

Location: Section 2 (Synthesized Claims + Calibration Impact), Section 7 (Summary of All New/Modified Files)

## [SEVERITY: major] Batch verification phase has contradictory single-run vs. per-finding isolation requirements

Section 5 Verification Phase states:

- Step 1: "All claims from all items verified together through a single engine run (shared grep cache for performance)"
- Step 2: "Dependency graphs are per-finding, not shared across findings"

These two requirements are architecturally incompatible with the `verify_all()` method designed in Section 1. The engine's `verify_all()` builds a single dependency graph, does a single topological sort, and verifies in order. Per-finding dependency isolation means N separate dependency graphs, N separate topological sorts, and N separate SUSPECT propagation passes.

The obvious resolution is N separate `verify_all()` calls (one per finding). But that breaks the shared grep cache: per Section 3 Lifecycle, the grep cache is scoped per `verify()` or `verify_batch()` call via `cache_context()`/`reset_cache()`. If `verify_all()` is called N times within a single `verify_batch()`, they share the outer grep cache context. That works.

However, the verifier cache is "a fresh dict created at the start of each `verify()` or `verify_batch()` call." If you call `verify_all()` N times, you need to decide: one shared verifier cache across all findings (shared verification results, which is correct since the same claim against the same repo yields the same result), or N separate verifier caches (wasteful, re-verifies identical claims). The spec doesn't address this because it assumes a single engine run.

The spec should explicitly state: `verify_batch()` wraps a single grep cache context, creates a single verifier cache, but calls `_build_dependency_graph()` and `_propagate_suspect()` per finding. This is architecturally different from "a single engine run" and the spec should describe it accurately.

Location: Section 5 (Verification Phase), Section 1 (New Architecture)

## [SEVERITY: minor] File-scoped ABSENCE claims can produce false VERIFIED when file does not exist

The spec excludes ABSENCE from dependency rules (line 64): "ABSENCE is excluded because it operates on pattern presence, not file existence."

But `verify_absence` with `scope="file"` resolves a specific file path and greps within it. If the file doesn't exist, `safe_path` returns a valid resolved path but `os.path.isfile(resolved)` fails, so `search_path` falls back to `repo_path` (the entire repo). This means a file-scoped absence check silently widens to a repo-wide search when the file is missing.

If the pattern is genuinely absent from the entire repo, the claim is VERIFIED, which is technically correct but misleading. The LLM claimed "pattern X is absent from file Y" and CCV confirms "yes, absent" but actually searched the entire repo because file Y doesn't exist.

More critically: if the pattern exists elsewhere in the repo but not in the (nonexistent) target file, the claim gets REFUTED even though the LLM's assertion about that specific file might be vacuously true (file doesn't exist, so nothing is in it).

This is an existing code issue that the chaining design should address. A file-scoped ABSENCE claim with a `file` parameter has the same FILE_EXISTS dependency as MITIGATION_EXISTS. Consider adding:

| R8 | ABSENCE (scope="file") | FILE_EXISTS | `file` | `path` |

Location: Section 2 (Inference Rules), `verify_absence` in security_claims.py

## [SEVERITY: minor] Eval confusion matrix dimensions don't account for SUSPECT or synthesized claims

Section 7 Stage 2 defines a 3x3 confusion matrix with axes VERIFIED/REFUTED/UNVERIFIABLE. But the chaining design (Section 2) introduces SUSPECT claims that retain their original verdict while being flagged. The eval framework doesn't specify how to handle these.

Options the spec should address:
- Treat SUSPECT-VERIFIED as VERIFIED for confusion matrix purposes (ignoring the flag). This loses signal about chaining accuracy.
- Add SUSPECT-VERIFIED and SUSPECT-REFUTED as separate categories (5x3 matrix).
- Report SUSPECT rates as a separate metric alongside the confusion matrix.

Similarly, synthesized claims have ground truth implications: if the eval dataset includes ground truth for FILE_EXISTS but the extraction misses it, chaining would synthesize it. Does a synthesized-and-verified FILE_EXISTS count as a "correct extraction" in Stage 1? The spec should clarify that ground truth matching in Stage 1 operates only on LLM-extracted claims (not synthesized ones), and that Stage 2 should document its SUSPECT handling.

Location: Section 7 (Three Evaluation Stages, Stage 2)
