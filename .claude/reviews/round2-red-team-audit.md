# Round 2 Red Team Audit

Auditor: adversarial-red-team
Date: 2026-06-15
Scope: Severity calibration, consensus analysis, blind spots, and final prioritized list across all three Round 2 reviews.

Context: This is a design spec review for a **local developer tool** (Python library). Not a web service, not multi-tenant, not deployed in production. Custom verifiers and extraction hints come from the developer using the library, not from untrusted users.

---

## 1. Severity Calibration

### Findings confirmed at stated severity

**ARCH: VerificationEngine lifecycle ambiguity (major)** - CONFIRMED MAJOR. Code-traced. The spec says "No persistence across runs. No staleness risk" but never defines what a "run" is. The current `CodeClaimVerifier.__init__` (line 19-24 of `__init__.py`) creates no engine, so this is genuinely ambiguous for implementers. A developer implementing this spec could reasonably build either a per-call or per-instance engine and get different caching behavior. This is the kind of ambiguity that produces bugs in implementation.

**ARCH: Grep cache shared across per-finding dependency graph isolation (major)** - CONFIRMED MAJOR. Code-traced. The scenario is specific and correctly reasoned: verifier cache is keyed by `(claim_type, frozen_params)` and shared across findings, but SUSPECT marking is per-finding. A cache hit returns a VerifiedClaim from a different finding's dependency context, bypassing the chaining logic. This is a real design inconsistency.

**CORRECTNESS: Verifier cache returns same VerifiedClaim object for duplicate claims (major)** - CONFIRMED MAJOR. Code-traced. `VerifiedClaim` is a mutable dataclass (confirmed in types.py line 28-35). The spec adds mutable `suspect_reason` field. Shared references between findings would silently corrupt reports. The fix (`dataclasses.replace()`) is correct and trivial.

**CORRECTNESS: Topological sort after deduplication leaves dangling edges (major)** - CONFIRMED MAJOR. This is a real graph algorithm concern. The spec lists deduplication (step 5) after synthesis (steps 3-4) as sequential steps, but edge re-targeting is never mentioned. An implementer following these steps literally would produce a broken graph.

### Findings downgraded

**CORRECTNESS: SUSPECT asymmetric weighting boundary behavior (major -> minor).** The math is correct but the conclusion overstates the impact. The reviewer flags that a single SUSPECT-VERIFIED claim always produces rate=0.5 regardless of method_confidence. This is mathematically inevitable (confidence * 0.5 / confidence = 0.5) and arguably intentional: SUSPECT means "the foundation is shaky," so treating it as FLAG-worthy for a single-claim finding is reasonable. The reviewer suggests making the factor configurable, which is a nice-to-have, not a spec defect. A developer hitting this in practice would have a finding with only one verifiable claim where the prerequisite was REFUTED. FLAG is the right action for that situation. The lack of configurability is a minor limitation, not a major spec gap.

**CORRECTNESS: Partial recovery >50% off-by-one at exactly 50% (major -> minor).** Valid observation, trivially fixable, but calling it "major" is severity inflation. In practice, this manifests only when a batch has an even number of claims with exactly half valid. The spec should say `>=50%`, and any competent implementer would make this choice. This is a nit in the spec wording, not a correctness hazard.

**CORRECTNESS: _freeze() does not handle set values (major -> minor).** The reviewer acknowledges "claim parameters are typically str -> str|int|bool" and then constructs a scenario with `{"scopes": {"read", "write"}}`. LLM-extracted JSON does not produce Python sets (JSON has no set type). Manually constructed claims could, but this is a developer tool where the developer controls the input. The crash would be immediate and obvious. Minor robustness improvement, not a major design flaw.

**SECURITY: GrepCache returns mutable list references (major -> minor).** All three reviews flagged this, but the security review inflated it to "major" by calling it "cache poisoning." This is a local developer tool. The "attacker" would be the developer's own code mutating a list in-place. Every built-in verifier already creates new lists (confirmed by reading symbol_claims.py lines 59-60). The fix is a one-line defensive copy. This is a latent bug worth fixing, not a security vulnerability.

**SECURITY: contextvars cache shared by reference across asyncio child tasks (major -> minor).** The spec describes a synchronous design. The entire verification pipeline (`verify()`, `verify_batch()`) is synchronous. There is no `async` anywhere in the codebase. This finding is speculative: "if the engine is ever used inside an async context where someone spawns subtasks..." That is a future hypothetical, not a present spec defect. Minor at best. Document it as a known limitation if async support is ever added.

**SECURITY: Batch delimiter can appear in adversarial reasoning text (major -> minor).** The reasoning text comes from another LLM's output about code. The "adversarial" scenario is an LLM reasoning about CCV itself, which would require the target repo being CCV. Even then, the delimiter `<<<FINDING_0:model.py>>>` is specific enough (with the exact finding index and filename) that accidental collision is extremely unlikely. This is a robustness improvement, not a security vulnerability. In a local developer tool, the developer can see the extraction output and debug it.

**SECURITY: source_sentence substring matching is exploitable via cross-finding text quoting (major -> minor).** "Exploitable" implies an attacker, but the input is the developer's own findings. The actual concern is robustness: ambiguous matches could cause misattribution. The architectural review and correctness review both flag this same issue as minor/major respectively. It is a valid robustness concern (minor), not a security exploit.

**ARCH: calibrate() signature and responsibility split (major -> minor).** This is a valid design question (who filters synthesized claims?) but the spec provides enough information for a competent implementer to make the right call. The reviewer even proposes the correct solution: calibrate receives all claims, partitions internally. This is implementation detail that doesn't need to be spelled out at the spec level.

**ARCH: Verifier function signature cannot support chaining context (major -> minor).** The reviewer explicitly says "This is not a blocker for v1" and proposes it as a future enhancement. Self-classified as non-blocking, so labeling it major is inconsistent.

### Findings confirmed at minor/nit

**ARCH: safe_path rejects repo root (minor)** - Confirmed. Code-traced against security.py line 9. Pre-existing behavior, amplified by chaining.

**ARCH: _freeze() frozenset vs tuple performance (minor)** - Valid but micro-optimization. The "hot path" claim is overstated. This runs once per claim, not in a tight loop.

**ARCH: register_dependency allows modifying built-in types (minor)** - Valid design concern.

**ARCH: Batch substring matching fragility (minor)** - Same finding as correctness and security reviews. Valid.

**CORRECTNESS: Extraction hint validation misses control characters (minor)** - Valid but context matters. Hints come from the developer. This is a defensive hardening suggestion, not a vulnerability.

**CORRECTNESS: Per-finding dependency isolation conflicts with shared cache (minor)** - Same finding as ARCH review's grep cache sharing issue. The reviewer's own analysis concludes it's "fine for correctness" and asks for clarifying documentation. Correct severity.

**CORRECTNESS: GrepCache returns mutable list references (minor)** - Same as security review's finding. Confirmed minor.

**SECURITY: _freeze() recursion depth (minor)** - Valid but the scenario requires programmatically crafted claims with 1000+ nesting levels. LLM-extracted JSON is flat. Minor.

**SECURITY: 500-char hint doesn't prevent prompt injection (minor)** - Hints come from the developer, not untrusted users. The developer is injecting into their own prompt. This is a non-issue for the threat model. Downgrade to nit.

**SECURITY: finding_index type not validated (minor)** - Valid robustness concern. JSON returns numbers, but string coercion is cheap insurance.

**SECURITY: Provider error messages could leak API keys (minor)** - Valid operational concern, correctly scoped.

**SECURITY: VerifierCache returns cached VerifiedClaim with wrong claim identity (minor)** - Overlaps with correctness review's shared mutable state finding. Valid.

---

## 2. Consensus Analysis

### Findings appearing in multiple reviews (corroborated)

| Finding | Reviews | Agreement |
|---------|---------|-----------|
| GrepCache mutable list references | ARCH (implied), CORRECTNESS, SECURITY | 3/3, all agree on defensive copy fix |
| source_sentence substring matching ambiguity | ARCH, CORRECTNESS, SECURITY | 3/3, all agree on "discard on ambiguity" |
| Verifier cache shared mutable state across findings | ARCH (grep cache sharing), CORRECTNESS (mutable VerifiedClaim), SECURITY (wrong claim identity) | 3/3, different angles on same root cause |
| safe_path rejects repo root | ARCH, SECURITY | 2/3, both note misleading "path traversal" error for empty paths |
| _freeze() edge cases | ARCH (frozenset perf), CORRECTNESS (set type), SECURITY (recursion depth) | 3/3, different angles |

### Contradictions

None found. The three reviews are internally consistent. Where they overlap, they reinforce each other with compatible fix proposals.

### Severity escalation through corroboration

FLAG: The GrepCache mutable list finding was escalated from what should be a minor defensive coding practice to "major" in the security review purely by framing it as "cache poisoning." No new evidence was introduced. The same mutable-list-reference pattern is a standard Python defensive-copy concern, not a security vulnerability in a local developer tool. The correctness review correctly rates it minor.

FLAG: The source_sentence substring matching finding was rated "major" in the security review by framing it as "exploitable," but the "exploitation" requires the developer's own findings to contain adversarial text. The architecture and correctness reviews correctly rate it minor.

---

## 3. Blind Spots

### BLIND_SPOT: Evaluation framework (Section 7) received zero review from any agent

Section 7 defines an entire eval framework (extraction quality, verification accuracy, calibration analysis) with dataset format, three evaluation stages, fixture repos, and mock vs real LLM modes. None of the three reviewers examined it. This is the largest section of the spec by feature count. Potential issues:

- The extraction matching criteria (claim_type identical + ground truth parameter keys present with equal values) could produce false matches when parameters are semantically equivalent but syntactically different (e.g., `name: "torch.load"` vs `name: "torch.load()"`)
- The ECE calculation method is not specified. ECE has multiple formulations (binned ECE, debiased ECE, adaptive ECE). For a per-type accuracy table with ~8 types, the bin count matters significantly.
- The `--mock-extraction` flag creates a code path where ground_truth_claims are used as extraction output, but the format shown in the dataset (`expected_verdict` field on ground truth claims) differs from the format used in extraction output (`source_sentence`, `parameters`). The mock path needs to construct valid `TypedClaim` objects from ground truth entries.
- Fixture repos must be version-controlled and immutable for reproducible eval. The spec doesn't address this.

### BLIND_SPOT: CLI input validation and resource limits

The CLI accepts `--reasoning` from stdin (max 100KB) and `--input` JSONL (max 10000 items). But:
- No validation on individual JSONL line size. A single line could be 1GB.
- The `--max-items 10000` cap prevents unbounded batch size, but 10000 items with max_chars_per_batch=6000 could produce ~1600 LLM extraction calls. No rate limiting or cost estimation is mentioned.
- No validation that `--repo` is actually a directory (or exists at all) before starting extraction (which costs LLM calls).

### BLIND_SPOT: to_dict() serialization does not include new fields

The existing `VerificationReport.to_dict()` (types.py lines 52-77) serializes claims with: type, params, source, verdict, confidence, evidence, method. The spec says `to_dict()` must include `suspect_reason` and `synthesized` fields, but no reviewer checked whether the spec's serialization format is actually compatible with existing consumers. The CLI outputs JSON reports using `to_dict()`. If existing code parses CCV output, the schema change could break consumers.

### BLIND_SPOT: Language detection fallback for batch mode

In batch mode, `finding_file` is per-item, but the spec says all claims are verified together in a single engine run. The current `verify()` method (line 44 of `__init__.py`) calls `detect_language(finding_file)` once per call and passes the language to all verifiers. In batch mode, different items have different finding_files and therefore different languages. The spec doesn't address how per-item language is propagated to verifiers when all claims are verified together.

### BLIND_SPOT: Dependency rule R4 and R5 parameter semantics are underspecified

R4 says FUNCTION_CALLED depends on FUNCTION_EXISTS via `name -> name`. But FUNCTION_EXISTS also has an optional `file` parameter. The synthesized FUNCTION_EXISTS from R4 would only have `name` (copied from FUNCTION_CALLED), not `file`. This means the synthesized prerequisite searches the entire repo for the function definition, which is correct but slower than a file-scoped search. More importantly, FUNCTION_CALLED doesn't have a `file` parameter in its current schema, so there is no way to scope the prerequisite search. This is a design limitation, not a bug, but no reviewer caught it.

---

## 4. Final Prioritized List

Ranked by real-world impact on a developer using this library.

### P0: Must fix before implementation

1. **Verifier cache returns shared mutable VerifiedClaim objects across findings** (CORRECTNESS major). Silent data corruption in batch mode. One-line fix with `dataclasses.replace()`. Highest impact-to-effort ratio.

2. **VerificationEngine lifecycle ambiguity** (ARCH major). Without this clarification, two implementers would build incompatible caching behavior. Define: engine lives on the CodeClaimVerifier instance, verifier cache is cleared per `verify()`/`verify_batch()` call, grep cache is per-call via contextvars.

3. **Verifier cache bypasses per-finding chaining (SUSPECT marking)** (ARCH major). The grep cache sharing + verifier cache sharing + per-finding chaining isolation creates a real semantic inconsistency. Fix: apply SUSPECT marking as a post-cache decoration pass.

4. **Topological sort after deduplication needs edge re-targeting** (CORRECTNESS major). Graph algorithm correctness issue. Fix: specify canonicalization during synthesis rather than post-hoc deduplication.

### P1: Should fix, but implementer could work around

5. **verify_all() flat list API contradicts per-finding chaining isolation** (ARCH minor/nit). The engine needs a per-finding entry point or group-aware verify_all. Implementer will discover this immediately.

6. **Partial recovery threshold: define behavior at exactly 50%** (CORRECTNESS minor). One-word fix: change `>50%` to `>=50%`.

7. **GrepCache mutable list references** (CORRECTNESS/SECURITY minor). Defensive copy on cache hit. Simple, cheap, prevents a class of latent bugs.

8. **source_sentence substring matching ambiguity resolution** (all three reviews). Define: discard on ambiguous match.

### P2: Nice to have

9. **_freeze() should handle set type** (CORRECTNESS minor). Unlikely in practice with LLM-extracted JSON, but cheap to add.

10. **safe_path empty-path error message** (ARCH/SECURITY minor). Distinguish "empty path" from "path traversal" in error evidence.

11. **finding_index type coercion** (SECURITY minor). Coerce to int. Trivial.

12. **register_dependency guard for built-in types** (ARCH minor). Prevent surprising behavior.

### Not worth spec changes

- **SUSPECT factor configurability** (CORRECTNESS). Implementation detail. Can be added later if needed.
- **Prompt injection in extraction hints** (SECURITY). Developer injects into their own prompt. Not a threat.
- **contextvars async task sharing** (SECURITY). Speculative. No async in the design.
- **Control characters in hints** (CORRECTNESS). Developer-provided input. Not a threat.
- **_freeze() recursion depth** (SECURITY). LLM JSON is flat. Not a real risk.
- **Batch delimiter collision** (SECURITY). Extremely unlikely with `<<<FINDING_N:filename>>>` format.
