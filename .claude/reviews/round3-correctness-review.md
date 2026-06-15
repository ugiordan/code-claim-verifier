# Round 3: Correctness and Edge Case Review

## [SEVERITY: major] Synthesized claims leak into calibration weighting

**Location**: Section 2 "Synthesized Claims" + "Calibration Impact"

The spec states synthesized claims are "excluded from report metrics (verified, refuted, verifiable_claims counts)" but the calibration pseudocode (lines 112-116) iterates over all `verifiable` claims without filtering out `synthesized=True`:

```python
for c in verifiable:
    weighted_total += c.method_confidence
    if c.verdict == "VERIFIED":
        factor = 0.5 if c.suspect_reason else 1.0
        weighted_verified += c.method_confidence * factor
```

This means a synthesized FILE_EXISTS (confidence 0.99) that the LLM never asserted would contribute 0.99 to `weighted_total` and potentially to `weighted_verified`, inflating or deflating the rate depending on its verdict. The spec needs `verifiable = [c for c in verified_claims if c.verdict != "UNVERIFIABLE" and not c.synthesized]` in the calibrator update, or an explicit statement that `calibrate()` receives a pre-filtered list. The current design has `per_claim` containing synthesized claims for transparency but passing that same list to calibrate, creating a contradiction.

**Fix**: Add `and not c.synthesized` to the verifiable filter in the calibration pseudocode, or specify that the engine filters synthesized claims before passing to `calibrate()` while still including them in `per_claim` afterward.


## [SEVERITY: major] Batch "single engine run" contradicts per-finding dependency isolation

**Location**: Section 5 "Verification Phase", steps 1-2

Step 1 says "All claims from all items verified together through a single engine run (shared grep cache for performance)." Step 2 says "Dependency graphs are per-finding, not shared across findings."

The engine as designed in Section 2 builds one dependency graph, runs one topological sort, and verifies in that order. The per-finding isolation requirement means the engine must build N separate dependency graphs (one per finding) but somehow share the grep cache and verifier cache across them. The spec doesn't describe how this works mechanically.

Two possible interpretations, both with issues:
1. The engine runs `verify_all()` N times (once per finding) with a shared grep cache context. But this contradicts "single engine run" and means the verifier cache either spans findings (leaking chaining state) or is reset per finding (losing cross-finding cache benefit).
2. The engine builds one combined graph but partitions dependency edges by finding_index. This requires new graph construction logic not described in Section 2's algorithm.

**Fix**: Specify that batch verification runs one grep cache context but N separate dependency graph resolutions. The verifier cache is shared (safe because it caches pre-chaining results). Clarify that "single engine run" means "single cache lifecycle" not "single graph."


## [SEVERITY: minor] Batch delimiter injection via finding_file

**Location**: Section 5 "Extraction Phase (Adaptive Batching)", step 2

The batch extraction delimiter format is `<<<FINDING_0:model.py>>>` where `model.py` comes from user-supplied `finding_file`. If `finding_file` contains `>>>` (e.g., a file named `a>>>b.py` or a malicious input), the delimiter parsing breaks. The spec notes the delimiters are "unlikely to appear in reasoning text" but doesn't account for `finding_file` content appearing inside the delimiter itself.

**Fix**: Either sanitize `finding_file` within delimiters (strip `>` and `<` characters) or don't embed `finding_file` in the delimiter at all (use only the index: `<<<FINDING_0>>>`). The finding_file can be tracked in a separate mapping.


## [SEVERITY: minor] source_sentence substring match for finding_index inference is non-deterministic

**Location**: Section 5 "Fallback and Partial Recovery", step 3

When `finding_index` is missing, the spec uses `source_sentence` substring matching against original findings text. If two findings contain identical or overlapping text (e.g., two findings about the same function), the substring match could map the claim to either finding. The spec doesn't define tie-breaking behavior (first match? error? both?).

In practice this matters because findings from the same repo often share function names and code patterns. A claim with `source_sentence: "torch.load() is used"` would match any finding whose reasoning mentions `torch.load()`.

**Fix**: Specify first-match wins (match against findings in index order, take the first hit) and document the known ambiguity. Or require that on ambiguous match, the claim is discarded rather than randomly assigned.


## [SEVERITY: minor] ABSENCE with scope="file" silently falls back to repo-wide search on missing file

**Location**: Section 2 "Inference Rules" note about ABSENCE exclusion

The spec explicitly excludes ABSENCE from dependency rules because it "operates on pattern presence, not file existence." However, `verify_absence` with `scope="file"` does depend on the file existing. The current code (security_claims.py lines 12-15) falls back to searching the entire repo when the file is missing (`search_path = resolved if resolved and os.path.isfile(resolved) else repo_path`). This means an ABSENCE claim scoped to a non-existent file silently becomes a repo-wide absence check, which could flip the verdict (pattern absent from the missing file but present elsewhere in the repo).

This isn't a new bug (it exists in the current code), but the spec's explicit exclusion of ABSENCE from chaining means it will persist. The fix belongs either in the spec (add ABSENCE with scope="file" as a conditional dependency) or as a bugfix note for the verifier itself.

**Fix**: Add a note that `verify_absence` with `scope="file"` should return UNVERIFIABLE (not fall back to repo) when the file doesn't exist, independent of chaining. Alternatively, add a conditional dependency rule for ABSENCE when `scope="file"` is set.


## [SEVERITY: nit] Eval confusion matrix axis labels unspecified

**Location**: Section 7 "Verification accuracy" report output

The confusion matrix JSON shows:
```json
"VERIFIED": {"VERIFIED": 120, "REFUTED": 3, "UNVERIFIABLE": 2}
```

The spec doesn't state which axis (outer key vs inner key) is predicted and which is actual/ground-truth. Standard convention is `matrix[actual][predicted]` but ML convention is often `matrix[predicted][actual]`. For a paper-quality evaluation framework (targeting ICSE 2027), this ambiguity would cause misinterpretation of false positive/negative rates.

**Fix**: Label the axes explicitly, e.g., "outer key is ground truth verdict, inner key is predicted verdict" or use the report structure `confusion_matrix[actual][predicted]`.
