# Round 3 Security and Robustness Review: CCV Improvements Design Spec

Reviewer: adversarial-security (round 3)
Date: 2026-06-15
Scope: NEW issues only. All ~21 issues from rounds 1 and 2 are confirmed fixed and not re-flagged.
Threat model: developer-facing Python library, not a web service. Custom verifiers and hints from developer, not untrusted users.

---

## [SEVERITY: minor] Batch fallback to per-item re-extraction doubles LLM cost with no circuit breaker

**Location:** Section 5 (Fallback and Partial Recovery), "partial" and "strict" modes

When batch extraction produces <50% assignable claims (or in "strict" mode, any invalid finding_index), the spec falls back to per-item extraction for the entire batch. This means the batch has already consumed one LLM call for the batch extraction that failed, and now N additional LLM calls run for each individual item. For a batch of 100 items grouped into 16 sub-batches, a single failing sub-batch triggers 100 per-item calls on top of the original batch call.

The spec has no circuit breaker for cascading fallback costs. If batch extraction consistently fails (e.g., a model that does not follow the finding_index instruction well), every `verify_batch()` call silently doubles its LLM spend. With the CLI's `--max-items 10000` default, a failing batch could produce 10,001 LLM calls (1 batch + 10,000 per-item) instead of the expected ~1,667 batch calls.

The "raise" fallback mode exists for cost-sensitive callers, but "partial" is the default. A developer who does not realize batch extraction is failing may incur significant unexpected API costs.

**Suggestion:** Add a `max_fallback_calls` parameter (or derive it from `max_items`) that caps the total number of per-item fallback calls. When the cap is reached, remaining items get empty reports rather than triggering more LLM calls. Alternatively, log a warning at the first fallback and track the fallback rate so the developer can switch to "raise" mode if the model is not batch-capable.

---

## [SEVERITY: minor] Eval Stage 2 runs ground truth claims directly against fixture repos, bypassing extraction

**Location:** Section 7 (Evaluation Framework), Stage 2 description

Stage 2 says: "For each ground truth claim with expected verdict, run verifier against fixture repo." The ground truth claims are defined in the dataset JSONL with `claim_type`, `parameters`, and `expected_verdict`. These are constructed as `TypedClaim` objects and passed directly to verifiers.

The problem: ground truth claims lack `source_sentence` and `id` fields. When `TypedClaim` is constructed from ground truth, `source_sentence` defaults to `""` and `id` is auto-generated via `uuid.uuid4()[:8]`. This is fine for verification (verifiers ignore `source_sentence` and `id`). But the resulting `VerifiedClaim` objects flow into `calibrate()`, which is now expected to handle `synthesized` and `suspect_reason` fields.

More significantly, Stage 2 uses the verifier directly without the engine's chaining and dependency graph. If the eval goal is to measure verification accuracy of the built-in verifiers in isolation, this is correct. But if the eval goal is to measure the full pipeline's accuracy (including chaining's SUSPECT marking), Stage 2 misses the chaining layer entirely. A ground truth claim like `FUNCTION_CALLED(name="foo", expected=true)` whose file does not exist would be REFUTED by the verifier alone, but the chaining layer would also mark it as SUSPECT. The expected_verdict in the dataset cannot express "VERIFIED but SUSPECT."

The spec does not clarify whether Stage 2 evaluates raw verifier accuracy or post-chaining pipeline accuracy. These produce different numbers, and the choice matters for the ICSE paper.

**Suggestion:** Specify whether Stage 2 runs claims through the engine (with chaining) or directly through verifiers (without chaining). If through the engine, the dataset format needs a way to express SUSPECT expectations. If directly through verifiers, document that Stage 2 measures verifier accuracy in isolation and a separate Stage 2b could measure post-chaining accuracy.

---

## [SEVERITY: minor] CLI verify-batch streams JSONL output but batch extraction requires all items upfront for grouping

**Location:** Section 5 (Batch API) and Section 6 (CLI verify-batch)

The CLI spec says verify-batch is "processed as a stream" from file or stdin. But the batch extraction phase (Section 5) requires knowing all items upfront to group them by cumulative reasoning text length. Adaptive batching groups items into sub-batches based on `max_chars_per_batch`, which is a global optimization over the full input set.

These two design goals conflict. True streaming would process items as they arrive (one at a time from stdin), but adaptive batching needs to see the full list to decide grouping boundaries. The spec does not reconcile this.

Possible interpretations: (a) "stream" means "read JSONL lazily line by line" but still buffer all items before calling `verify_batch()`, which is not real streaming and still requires full memory. (b) "stream" means each item is independently extracted and verified, which loses the batch extraction cost savings. (c) "stream" means items are buffered in chunks of `max_items` and each chunk is processed as a batch, which is a middle ground but not specified.

**Suggestion:** Clarify the streaming semantics. If the CLI buffers all items into a list before calling `verify_batch()`, say so and drop the "stream" language (it is misleading). If real streaming is intended, specify a windowed batching approach (e.g., buffer items until their cumulative text length reaches `max_chars_per_batch`, then flush and process that batch, repeat).

---

## [SEVERITY: minor] register() collision check is one-directional and does not guard against custom-to-custom conflicts

**Location:** Section 4 (Custom Claim Types), Mechanics

The spec says `register()` "validates claim_type is not already registered (raises ValueError on collision with built-ins)." This prevents overwriting built-in types but does not address the scenario where `register()` is called twice with the same custom type name.

If a developer registers `DATABASE_QUERY` twice (perhaps from two different plugins or initialization paths), the second registration silently overwrites the first. The collision check only fires against built-in types, not against previously registered custom types.

This is relevant in library integration scenarios where multiple modules call `register()` on the same `CodeClaimVerifier` instance. The second module's verifier silently replaces the first, and claims that were designed for the first verifier's logic are now routed to the second.

**Suggestion:** The collision check should apply to all existing registry entries, not just built-ins. Raise `ValueError` if the claim_type is already registered (whether built-in or custom). If intentional overwrite of a custom type is needed, provide an explicit `register(claim_type, ..., overwrite=True)` parameter.

---

## [SEVERITY: nit] Eval confusion matrix orientation is ambiguous

**Location:** Section 7 (Evaluation Framework), Report Output

The confusion matrix in the report output example:

```json
"confusion_matrix": {
    "VERIFIED": {"VERIFIED": 120, "REFUTED": 3, "UNVERIFIABLE": 2},
    "REFUTED": {"VERIFIED": 5, "REFUTED": 45, "UNVERIFIABLE": 1},
    "UNVERIFIABLE": {"VERIFIED": 0, "REFUTED": 1, "UNVERIFIABLE": 15}
}
```

The outer key and inner key meanings are not labeled. Is the outer key "predicted" and inner key "actual," or vice versa? The example is consistent with either orientation because the diagonal dominates. Standard convention in ML is `confusion_matrix[actual][predicted]`, but scikit-learn uses `confusion_matrix[true][predicted]` while some other frameworks use `[predicted][true]`.

For the ICSE paper, the false_refuted_rate and false_verified_rate definitions depend on orientation. "False REFUTED" means "predicted REFUTED but actually VERIFIED," which reads from `confusion_matrix["VERIFIED"]["REFUTED"]` if outer=actual, or `confusion_matrix["REFUTED"]["VERIFIED"]` if outer=predicted. The example numbers (3 vs 5) would give different rates depending on orientation.

**Suggestion:** Label the orientation explicitly. Something like: "Outer key is ground truth (actual), inner key is predicted verdict." One sentence prevents implementer confusion.
