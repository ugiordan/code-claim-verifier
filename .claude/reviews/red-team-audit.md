# Red Team Audit: CCV Improvements Design Spec Reviews

Auditor: Red Team (adversarial review of arch, correctness, and security agent outputs)
Spec reviewed: `docs/superpowers/specs/2026-06-15-ccv-improvements-design.md`
Codebase: `code_claim_verifier/` (all modules, verified against source)

---

## 1. Severity Calibration

### Finding: GrepCache module-level global state (Arch: critical, Correctness: major, Security: critical)

**Verdict: Downgrade to major.**

All three reviewers flagged this. The arch and security reviews rate it critical, but this is severity inflation. The code being reviewed is a design spec for a library, not a production service. The concurrency scenario (two VerificationEngine instances in the same process) is real but unlikely in the primary use case: CLI tool or single-threaded library consumer. The agent-framework scenario (`as_tools()` in a web server) is a valid future concern but speculative. The "cache poisoning" framing from the security review is dramatic, since the attacker would need to run code in the same process, at which point they already have full access.

The fix is correct (use `contextvars.ContextVar` or instance-scoped cache), and the problem is real, but "critical" implies data loss or security breach in normal use. This is a design flaw that causes incorrect behavior only under concurrent use, which the current codebase doesn't support and the spec doesn't claim to support. Major is the right severity.

The security review's sub-point about custom verifier functions calling `grep.disable_cache()` (finding 1, point 2) is speculative. Custom verifiers are trusted code provided by the library consumer. If they're sabotaging the cache, the attacker already controls the host process. This inflates the perceived severity.

### Finding: Unbounded recursive synthesis / infinite loops (Correctness: critical)

**Verdict: Downgrade to major.**

The correctness review rates this critical based on a circular dependency scenario (custom type A depends on B, B depends on A). This requires the user to explicitly call `register_dependency` in a way that creates cycles. It's a real bug, but "critical" implies it happens in normal use. Built-in rules (R1-R6) have no cycles (all dependencies point toward FILE_EXISTS/FUNCTION_EXISTS which are leaf types). The user would have to deliberately misconfigure custom dependencies to trigger this. A depth limit and cycle guard are the right fix, but the severity should reflect that this only affects custom type users who misconfigure their dependency graph. Major.

### Finding: Verifier cache uses hash() of frozen parameters (Correctness: critical, Arch: minor, Security: minor)

**Verdict: Downgrade to major (from correctness's critical), confirm as major.**

The correctness review inflates this to critical. The arch and security reviews correctly assess it as minor to medium. The collision probability for Python's `hash()` on typical claim parameter tuples is astronomically low in practice. But the fix is trivial (just drop the `hash()` wrapper and use the tuple directly as the dict key), and the principle is correct: there's no reason to introduce collision risk when it's avoidable. The "unhashable nested values" sub-point from the correctness review is a legitimate addition that the other two reviews missed. Major, not critical, because the practical impact is near-zero but the fix costs nothing.

### Finding: Prompt injection via custom extraction hints (Security: critical, Correctness: major)

**Verdict: Downgrade to major.**

The security review rates this critical, but the threat model is wrong. The `extraction_hint` is provided by the library consumer (the developer calling `register()`), not by an external attacker. This is the same trust boundary as "the developer writes Python code that imports the library." A developer who writes a malicious extraction_hint can also write a malicious verifier function that does `os.system("rm -rf /")`. The "prompt injection" framing implies an untrusted input channel, but this is a developer-facing API.

The correctness review correctly calls this a "correctness issue" rather than a security issue. Poor extraction hints degrading built-in type extraction is a usability/robustness concern, not a security vulnerability. Major (for the correctness/robustness angle), not critical.

### Finding: SUSPECT confidence reduction interacts incorrectly with calibration formula (Correctness: major)

**Verdict: Confirm as major. This is the strongest finding across all three reviews.**

The correctness review provides a concrete mathematical proof that the 0.5x confidence multiplier on SUSPECT claims does nothing when the claim is VERIFIED (because it reduces both numerator and denominator symmetrically). And when the claim is REFUTED, it actually makes the rate go *up* slightly, which is the opposite of the stated intent. This is a real spec bug with a concrete, demonstrable proof. No other review caught this specific mathematical interaction. Confirmed major, arguably should be critical because it means the entire chaining/SUSPECT mechanism fails to achieve its stated purpose.

### Finding: Custom verifier functions have unrestricted filesystem access (Security: major)

**Verdict: Downgrade to minor.**

Same trust boundary issue as the extraction_hint finding. Custom verifiers are developer-provided code running in the developer's process. They can already do anything. The `SafeRepo` wrapper suggestion is a nice API improvement but framing it as a security finding overstates the risk. The developer trusts their own code. Minor (API design improvement).

### Finding: CLI stdin has no size limits (Security: major)

**Verdict: Downgrade to minor.**

The CLI is a local tool. The user runs it on their own machine with their own data. "An attacker could pipe gigabytes via stdin" requires the attacker to have shell access to the machine, at which point they don't need the CLI. The "unbounded API costs" concern is more valid (a huge JSONL file triggering many LLM calls), but that's a usability/cost concern, not security. Minor.

### Finding: Eval fixture path accepts arbitrary directories without symlink protection (Security: major)

**Verdict: Downgrade to minor.**

The `--fixtures` flag is a CLI argument provided by the developer running eval on their own machine. The symlink-following-grep point is technically correct (grep -r follows symlinks by default), but the threat model requires a malicious fixture repo, which the developer chose to point the tool at. Minor at best.

### Finding: No grep pattern sanitization for regex mode (Security: major)

**Verdict: Downgrade to minor.**

The security review itself acknowledges that existing code calls `re.escape(name)` on all user-derived patterns, and `verify_absence` uses `fixed=True`. The review then pivots to "custom verifiers might not sanitize patterns," which is speculative about code that doesn't exist yet. The 30-second timeout in subprocess provides a reasonable guard. Minor.

### Finding: Synthesized claims from chaining may bypass safe_path checks (Security: major)

**Verdict: Confirm as major.**

This is a real finding. If the engine synthesizes a FILE_EXISTS claim with a `file` parameter (from a dependent claim) but the target verifier expects `path`, the synthesized claim would have the wrong parameter name. `verify_file_exists` reads `claim.parameters.get("path", "")`, so a synthesized claim with `file` (not `path`) would get `""`, resolve to the repo root, and `os.path.isfile("")` would return False. Not a path traversal, but a silent failure that masks the intended check. The parameter name mapping gap is real and needs explicit handling in the spec. Confirmed major.

### Finding: Batch extraction partial finding_index failure (Correctness: major)

**Verdict: Confirm as major.**

The three scenarios (partial indices, out-of-range indices, duplicate indices) are all plausible with LLM output. The spec's all-or-nothing fallback strategy wastes valid work. This is a real design gap. Confirmed major.

### Finding: as_tools() classmethod vs instance state mismatch (Arch: major, Correctness: minor)

**Verdict: Confirm as minor.**

Both reviews flagged this. It's a real API design inconsistency but doesn't cause crashes, data loss, or security issues. It's a documentation/design clarity issue. The schemas work for built-in types; custom types are a secondary use case. Minor.

### Finding: Backwards compatibility break in _grep imports (Arch: major)

**Verdict: Downgrade to minor.**

`_grep` is underscore-prefixed (private). External code importing a private function from an internal module is already operating outside the public API contract. The spec is under no obligation to maintain backwards compatibility for private symbols. The deprecation shim suggestion is nice-to-have but the severity should reflect that this is a private API. Minor.

### Finding: Synthesized prerequisite claims change verification semantics silently (Arch: major)

**Verdict: Confirm as major.**

Phantom claims in the report output that don't map to any LLM assertion is a real problem for consumers. The suggestion to either mark them `synthesized=True` or inline the checks into dependent verifiers is sound. Confirmed major.

---

## 2. Consensus Analysis

### Genuine consensus (independently derived, code-traced):

**GrepCache global state** (all 3 reviews). All three identified the same module-level `_cache` global, cited the same code pattern (`enable_cache()` / `disable_cache()` as free functions), and independently arrived at the `contextvars` fix. This is genuine consensus. The underlying problem is objectively present in the spec.

**hash() in cache key** (all 3 reviews). All three identified that `hash(params_frozen)` in the cache key introduces collision risk. All three suggested using the frozen tuple directly. The arch and security reviews noted the PYTHONHASHSEED non-determinism angle; the correctness review added the unhashable nested values angle. Genuine consensus with complementary analysis.

**as_tools() classmethod/instance mismatch** (arch + correctness). Both independently identified the same design inconsistency. Genuine consensus.

### Echo chamber risk:

**Prompt injection via extraction_hint** (correctness + security). The security review calls it "critical" and uses language like "prompt injection payload" and "leak the reasoning content." The correctness review more accurately calls it a "correctness issue." But both frame the threat around a developer-provided API parameter, which is the wrong threat model for a security finding. The security review's dramatic framing may have been influenced by pattern-matching on "user input goes into LLM prompt" without considering the trust boundary. Not exactly echo chamber (they reached different severities), but the shared finding obscures the fact that the real concern is robustness, not security.

**No evidence of echo chamber** in the other findings. The three reviews have genuinely different focus areas (layering vs correctness vs security) and their overlapping findings are independently motivated.

---

## 3. Blind Spots

### BLIND_SPOT: No reviewer analyzed the eval framework's ground truth matching logic

Section 7 defines claim matching as "claim type + parameter key overlap (not exact string match)." None of the three reviews questioned what "parameter key overlap" means precisely. If ground truth has `{"name": "torch.load", "expected": true}` and extraction produces `{"name": "torch.load"}`, is this a match? What about extra parameters the LLM invented? The evaluation metrics (precision, recall) are only as good as the matching logic, and the spec leaves it ambiguous. For an ICSE paper, this is the most important thing to get right.

### BLIND_SPOT: No reviewer questioned the calibration curve methodology

Section 7 shows calibration buckets with `predicted` confidence values. But `method_confidence` in the existing code is hardcoded per verifier (0.85 for function_exists, 0.65 for function_called, etc.), not a continuous distribution. The calibration curve will have at most 5-6 distinct x-values (the hardcoded confidence levels), not the smooth distribution shown in the sample output. The eval framework's calibration stage assumes a calibration-curve-worthy distribution of confidence values, which the existing system doesn't produce. This is a fundamental flaw in the eval design that no reviewer caught.

### BLIND_SPOT: No reviewer examined the batch verification shared-dependency-graph semantics

Section 5 says "all claims from all items verified together through a single engine run (shared cache, shared dependency graph)." This means a FILE_EXISTS claim from Finding #0 satisfies the dependency for a FUNCTION_CALLED claim from Finding #3, even though they're about different findings. If Finding #0's FILE_EXISTS is VERIFIED but Finding #3's file doesn't actually exist, the dependency is incorrectly satisfied because they share the same file path. Cross-finding dependency satisfaction is either intentional (an optimization) or a bug (dependency leakage), and the spec doesn't clarify which.

### BLIND_SPOT: No reviewer checked whether the topological sort handles disconnected components

The dependency graph may have multiple disconnected subgraphs (e.g., file claims in one component, import claims in another). Standard topological sort handles this fine, but the spec doesn't mention it. More importantly, the spec doesn't define what happens when a claim has no dependencies and no dependents. Is it verified first? Last? The ordering of independent claims matters for the cache warming strategy.

### BLIND_SPOT: No reviewer analyzed error propagation in the VerificationEngine

The spec says `VerificationEngine.verify_all()` returns `list[VerifiedClaim]`. But what happens when the dependency graph construction itself fails (e.g., a registered dependency references a non-existent claim type)? What if topological sort encounters an error? The engine has multiple stages (extract, build graph, sort, verify, propagate) and the spec doesn't define error handling between stages. Currently `safe_verify()` catches exceptions per-claim, but engine-level errors are unaddressed.

### BLIND_SPOT: No reviewer questioned the `max_chars_per_batch` adaptive batching heuristic

Section 5 uses character count (`max_chars_per_batch=6000`) to decide batch boundaries. But LLM token limits are in tokens, not characters. A batch of 6000 characters of dense code could easily exceed the context window when combined with the system prompt, claim type definitions, and extraction instructions. The heuristic should be token-aware, or at least the default should be conservative enough to account for the ~3x character-to-token ratio in code.

### BLIND_SPOT: No reviewer examined what happens when `verify_batch` gets an empty items list

Trivial edge case but the spec doesn't address it. Does it return an empty list? Does `calibrate([])` get called? The existing code handles empty claims in calibrate(), but verify_batch's behavior with zero items is unspecified.

### BLIND_SPOT: The lockfile substring matching bug (Security: nit) deserves higher attention with caching

The security review flagged `_parse_go_sum` using `package in parts[0]` as a nit, noting it becomes more impactful with caching. This understates the issue. With batching, a false positive match on `"fmt"` matching `"github.com/some/fmtlib"` gets cached by the VerifierCache, then applied to every PACKAGE_VERSION claim for `"fmt"` in the batch. This is a pre-existing bug that the new features amplify. It deserved a standalone finding at minor-to-major severity, not a nit.

---

## 4. Final Prioritized List: Top 5 Findings That Actually Matter

### 1. SUSPECT confidence multiplier is mathematically broken (Correctness review, major)

**Why #1**: This is the only finding with a concrete proof that a core feature of the spec doesn't work as designed. The 0.5x confidence reduction on SUSPECT-VERIFIED claims has zero effect on the calibrated confidence rate. The entire chaining/SUSPECT mechanism is the headline feature of this spec, and its impact metric is provably broken. This isn't a hypothetical edge case. It's a formula that literally doesn't do what the spec says it does. The fix requires rethinking how SUSPECT claims feed into calibration, which may change the calibrator's API.

**Evidence**: Verified against existing `calibrator.py` lines 29-31. The formula `weighted_verified / weighted_total` treats SUSPECT-VERIFIED claims identically to normal VERIFIED claims when the confidence multiplier is applied symmetrically.

### 2. GrepCache module-level global state, thread-unsafe (All 3 reviews, downgraded to major)

**Why #2**: While the concurrency scenario isn't the primary use case today, the spec explicitly adds `as_tools()` for agent framework integration. Agent frameworks routinely run tools concurrently. Shipping a thread-unsafe global cache in a library that advertises agent integration is shipping a bug in the primary new use case. The fix (contextvars or instance-scoped cache) is well-understood and not disruptive.

**Evidence**: Verified against spec Section 3, the proposed `grep.py` code snippet uses `global _cache` with no locking or scoping.

### 3. Synthesized claim parameter name mapping gap (Security review, confirmed major)

**Why #3**: Rule R1 says "any claim with `file` or `path` param depends on FILE_EXISTS for that file/path value." But `verify_file_exists` reads `claim.parameters.get("path", "")`. If a dependent claim has a `file` parameter but the synthesized FILE_EXISTS gets that value under the key `file` instead of `path`, the check silently passes with an empty string. This is a concrete correctness bug in the spec's dependency inference design. Additionally, the correctness review's point about R1 being overly broad (catching FILE_CLASSIFICATION, which never reads the file) compounds this: the synthesized dependency is both incorrectly parameterized and sometimes unnecessary.

**Evidence**: Verified against `file_claims.py` line 14: `path = claim.parameters.get("path", "")`. The spec's rules table uses "the file/path value" ambiguously.

### 4. Batch extraction partial failure handling is underspecified (Correctness review, confirmed major)

**Why #4**: Batch extraction is the cost optimization that makes this library practical at scale. The all-or-nothing fallback (one bad `finding_index` triggers re-extraction of all items) wastes LLM calls and money. With batches of 20+ findings, a single malformed index could cost 20 extra API calls. The partial recovery strategy (accept valid indices, re-extract only the broken ones) is straightforward to specify and significantly impacts the operational cost of the library.

**Evidence**: Verified against spec Section 5, which only defines two states: "parseable" and "fall back to per-item re-extraction."

### 5. Evaluation calibration curve methodology doesn't match the system's confidence distribution (Blind spot, new finding)

**Why #5**: The eval framework is for an ICSE 2027 paper. The calibration curve in the sample output shows 7 buckets from 0.60 to 0.99, implying a continuous confidence distribution. But the existing verifiers use exactly 5 hardcoded confidence values: 0.99 (file_exists), 0.95 (line_content), 0.90 (package_version), 0.85 (function_exists, generated_or_vendored, dependency_type), 0.80 (file_classification, import_exists), 0.70 (mitigation_exists), 0.65 (function_called, has_callers, entry_point), 0.60 (absence). A calibration curve with discrete x-values is a step function, not a curve. For a peer-reviewed paper, this needs either: (a) making confidence values continuous (based on match quality, not just claim type), or (b) changing the eval methodology to report per-type accuracy instead of a calibration curve.

**Evidence**: Verified by reading every verifier function in the codebase. Each one hardcodes its `method_confidence` value. There is no per-result confidence adjustment.

---

## Summary of Flags

```
FLAG: GrepCache-Critical (Arch, Security) - Severity inflated from major to critical.
  Concurrency scenario is real but not the primary use case.
  "Cache poisoning" framing implies external attacker; actual threat is same-process.
  Downgrade to major.

FLAG: RecursiveSynthesis-Critical (Correctness) - Severity inflated from major to critical.
  Requires user-configured circular custom dependencies.
  Built-in rules have no cycles. Downgrade to major.

FLAG: HashCollision-Critical (Correctness) - Severity inflated from major to critical.
  Practical collision probability is near-zero for typical parameters.
  Fix is trivial but impact is minimal. Downgrade to major.

FLAG: PromptInjection-Critical (Security) - Severity inflated from major to critical.
  extraction_hint is a developer API, not an untrusted input channel.
  Same trust boundary as the verifier function itself.
  Reframe as robustness/correctness concern, not security. Downgrade to major.

FLAG: CustomVerifierFilesystemAccess (Security, major) - Severity inflated.
  Custom verifiers are trusted developer code. Downgrade to minor.

FLAG: CLIStdinLimits (Security, major) - Severity inflated.
  CLI is a local tool. Downgrade to minor.

FLAG: EvalFixturePath (Security, major) - Severity inflated.
  Developer chooses the fixture path. Downgrade to minor.

FLAG: GrepPatternSanitization (Security, major) - Severity inflated.
  Existing code already escapes patterns. Speculative about future custom verifiers.
  Downgrade to minor.

BLIND_SPOT: Eval ground truth claim matching logic is ambiguous.
  "Parameter key overlap" is not defined precisely enough for reproducible metrics.

BLIND_SPOT: Calibration curve methodology assumes continuous confidence distribution,
  but existing verifiers use discrete hardcoded confidence values (5-6 distinct levels).
  The eval framework's calibration stage will produce a step function, not a curve.

BLIND_SPOT: Batch verification shared dependency graph allows cross-finding dependency
  satisfaction. A FILE_EXISTS from Finding #0 satisfies dependencies in Finding #3.
  This is either intentional (optimization) or a bug (dependency leakage).

BLIND_SPOT: max_chars_per_batch uses character count, not token count. A 6000-char
  batch of dense code plus system prompt could exceed LLM context windows.

BLIND_SPOT: Lockfile substring matching bug (_parse_go_sum uses `package in parts[0]`)
  is amplified by both caching and batching. A false positive gets cached and
  applied to all PACKAGE_VERSION claims for that package in the batch.

BLIND_SPOT: No reviewer analyzed error propagation between VerificationEngine stages
  (graph construction failure, topological sort errors, synthesis failures).
```
