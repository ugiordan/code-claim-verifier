# Architecture Review: CCV Improvements Design Spec

Spec: `docs/superpowers/specs/2026-06-15-ccv-improvements-design.md`
Reviewer focus: layering, state management, dependency direction, API surface, scope, backwards compatibility.

---

## [SEVERITY: critical] GrepCache uses module-level mutable global state, unsafe for concurrency

**Location**: Section 3 (Caching), `grep.py` module-level `_cache`

**Finding**: The proposed `GrepCache` is a module-level `dict | None` toggled by `enable_cache()` / `disable_cache()` free functions using `global _cache`. This creates several problems:

1. **Thread safety**: Two `CodeClaimVerifier` instances running `verify_batch()` concurrently will stomp on each other. Instance A calls `enable_cache()`, instance B calls `disable_cache()` in its `finally` block while A is still running, silently disabling A's cache mid-verification. Worse, if both run simultaneously, cache entries from repo X leak into lookups for repo Y (the cache key is `(pattern, path, fixed)` where `path` is a relative-to-repo path, so identical paths from different repos would collide).

2. **Re-entrancy**: If a verifier function internally triggers another verification (unlikely today but the engine's dependency-graph synthesized-prerequisite feature in Section 2 could cause nested verification passes), the `finally` block from the inner call would nuke the outer cache.

3. **Testing friction**: Any test that imports `grep.py` shares the global state, making test isolation harder.

**Suggestion**: Make the cache an instance attribute on `VerificationEngine`. Pass it down to grep calls via a context parameter, or use `contextvars.ContextVar` so each engine run gets its own cache without changing verifier function signatures. If you want to keep verifier functions signature-stable (the spec explicitly says so), `contextvars` is the cleanest path:

```python
import contextvars
_grep_cache: contextvars.ContextVar[dict | None] = contextvars.ContextVar('_grep_cache', default=None)
```

The engine sets a token on entry and resets on exit. No global mutation, thread-safe, re-entrant.

---

## [SEVERITY: major] VerificationEngine creates a hidden coupling between extraction and verification

**Location**: Section 1 (VerificationEngine) and Section 4 (Custom Claim Types)

**Finding**: The spec says `_parse_extraction_output` should validate claim types against `self.engine.registry.keys()` instead of the module-level `CLAIM_TYPES` frozenset. This means the extraction module now needs access to the engine instance to know which types are valid. Currently `extract_claims()` is a pure module-level function. After this change, it either needs the engine passed in, or `CodeClaimVerifier.verify()` has to pass the valid type set into extraction, or `extractor.py` imports from `engine.py`.

This breaks the current clean layering where extraction knows nothing about verification. The dependency direction becomes circular or at least tangled: `engine.py` depends on `extractor.py` (to call extraction), and `extractor.py` depends on `engine.py` (to get the valid claim type set).

**Suggestion**: Pass the valid claim types as a parameter to `extract_claims()` and `_parse_extraction_output()`:

```python
def extract_claims(..., valid_types: frozenset[str] = CLAIM_TYPES) -> list[TypedClaim]:
```

This keeps extraction a pure function, avoids the circular dependency, and the engine just passes `frozenset(self.registry.keys())` when calling it.

---

## [SEVERITY: major] Synthesized prerequisite claims change verification semantics silently

**Location**: Section 2 (Claim Chaining), bullet 5

**Finding**: The spec says: "If no explicit dependency claim was extracted [...] the engine synthesizes the prerequisite claim and verifies it." This means the engine fabricates claims the LLM never made, verifies them, and uses the results to flag (SUSPECT) the actual extracted claims. This has several problems:

1. **Phantom claims in output**: The synthesized FILE_EXISTS claim appears in the `VerificationReport.per_claim` list even though the LLM never asserted the file exists. Consumers parsing the report see claims that don't map back to any source sentence.

2. **Confidence distortion**: A synthesized claim that gets REFUTED will halve the confidence of its dependents. But the original LLM reasoning might have been about a function name that happens to exist in multiple files. The synthesized FILE_EXISTS claim picks one file, doesn't find it, and penalizes the real claim.

3. **Non-determinism**: The spec doesn't define how the engine determines what file to synthesize a FILE_EXISTS claim for when the dependent claim doesn't have a `file` parameter (e.g., FUNCTION_CALLED with just a `name`).

**Suggestion**: Either (a) clearly mark synthesized claims as `synthesized=True` in the output and exclude them from report metrics, or (b) don't synthesize claims at all. Instead, run the prerequisite check inline as part of the dependent verifier (e.g., `verify_function_called` can check if the file exists first). Option (b) keeps the verifier functions self-contained and avoids phantom data in the report.

---

## [SEVERITY: major] `as_tools()` as a static/classmethod is inconsistent with instance-bound state

**Location**: Section 6 (Tool Schemas)

**Finding**: The spec says `as_tools()` returns "static schema definitions, not bound to an instance" and the call syntax is `CodeClaimVerifier.as_tools()`. But the schemas include `verify_claim` and `verify_all` which require a `repo_path`, an `llm_function`, and knowledge of registered custom types (which are instance-level). An agent framework receiving these schemas has no way to invoke them without a `CodeClaimVerifier` instance.

This creates an awkward gap: the schemas describe operations that require instance state, but the method producing them has no instance. The schemas will necessarily be incomplete (can't include custom type information) and callers need separate documentation on how to bind them to an instance.

**Suggestion**: Make `as_tools()` an instance method that returns schemas reflecting the instance's registered types. Or split into two methods: a classmethod `default_tools()` for the built-in schema, and an instance method `as_tools()` that includes custom types. The spec should also define the routing mechanism: how does the agent framework call `verify_claim` on the right instance?

---

## [SEVERITY: major] Backwards compatibility break in verifier imports

**Location**: Section 1 (File Changes), `verifiers/symbol_claims.py`

**Finding**: Currently `import_claims.py` and `security_claims.py` import `_grep` directly from `symbol_claims.py`:

```python
# import_claims.py line 8
from code_claim_verifier.verifiers.symbol_claims import _grep

# security_claims.py line 5
from code_claim_verifier.verifiers.symbol_claims import _grep
```

The spec says `_grep` moves to `grep.py` and all three modules change their imports. But `_grep` is a private function (underscore prefix) that's already used as a cross-module import (a code smell in the current codebase). Any external code that imports `_grep` from `symbol_claims` will break. More importantly, the spec needs to decide: does `symbol_claims._grep` become a re-export for backwards compat, or is this a clean break? The spec is silent on this.

**Suggestion**: Since `_grep` is private (underscore-prefixed), treat this as a clean break. But the new public function in `grep.py` should be named `grep` (no underscore) since it's now a public module API. Add a deprecation shim in `symbol_claims.py` if you want to be cautious:

```python
def _grep(*args, **kwargs):
    import warnings
    warnings.warn("Import grep from code_claim_verifier.grep", DeprecationWarning)
    from code_claim_verifier.grep import grep
    return grep(*args, **kwargs)
```

---

## [SEVERITY: minor] SUSPECT verdict conflates two distinct signals

**Location**: Section 2 (Claim Chaining, Type Change)

**Finding**: The spec adds `suspect_reason: str | None` to `VerifiedClaim` but doesn't add SUSPECT to the `Verdict` literal type. A SUSPECT claim keeps its original verdict (VERIFIED or REFUTED) and just gets a string annotation. This means:

1. Consumers checking `verdict == "VERIFIED"` will treat SUSPECT claims as fully verified unless they also check `suspect_reason`.
2. The calibrator needs special-case logic to detect the `suspect_reason` field and apply the 0.5 multiplier, but the spec doesn't show changes to `calibrator.py`.
3. The `VerificationReport.verified` count will include SUSPECT-VERIFIED claims, which is misleading.

This is a leaky abstraction: the "SUSPECT" state exists but isn't represented in the type system.

**Suggestion**: Either (a) add "SUSPECT" to the `Verdict` literal so consumers can pattern-match on it, or (b) add a separate `is_suspect: bool` field (cleaner than a nullable string) and update `calibrator.py` to handle it. Option (a) is cleaner for consumers but means `verify_function_called` returns a 4-way verdict. Option (b) keeps the 3-way verdict clean but requires all downstream code to check both fields. Either way, the spec must define the calibrator changes.

---

## [SEVERITY: minor] Batch extraction fallback could cause 2x LLM calls silently

**Location**: Section 5 (Batch Extraction and Verification, Fallback)

**Finding**: The fallback strategy says: if batch extraction fails to parse, re-extract per item. For a batch of N items, this means the first LLM call fails, then N individual LLM calls fire. For a batch of 20 items, that's 21 LLM calls when something goes wrong. There's no limit, no circuit breaker, and no user visibility into this happening (just "log warning").

**Suggestion**: Add a configurable `max_fallback_retries` or `fallback_strategy` parameter. At minimum, if the batch call fails, the per-item fallback should be opt-in (e.g., `fallback="per_item" | "skip" | "raise"`). Default to `"per_item"` for backwards compat but let cost-sensitive callers choose `"raise"`.

---

## [SEVERITY: minor] Scope creep: eval framework belongs in a separate package or at least a separate extras group

**Location**: Section 7 (Evaluation Framework)

**Finding**: The eval framework adds 6 new files under `code_claim_verifier/eval/`, fixture repos, a dataset, and a CLI subcommand. This is roughly half the new file count. The eval framework is explicitly for a paper (ICSE 2027), not for library consumers. Shipping it inside the main package means:

1. Every `pip install code-claim-verifier` includes eval code that most users will never use.
2. The fixture repos (synthetic Python/Go/TS projects) add to the package size.
3. The eval CLI subcommand (`eval`) clutters the user-facing CLI namespace.

**Suggestion**: Move eval to a separate extras group (`pip install code-claim-verifier[eval]`) and use a conditional import in `cli.py` (only register the `eval` subcommand if the eval package is available). Or better: keep it as a separate top-level `ccv-eval/` directory that imports `code_claim_verifier` as a dependency but isn't part of the main package distribution.

---

## [SEVERITY: minor] VerifierCache key uses `hash()` on frozen parameters, which is session-unstable

**Location**: Section 3 (Caching, VerifierCache)

**Finding**: The cache key includes `hash(params_frozen)` where `params_frozen = tuple(sorted(claim.parameters.items()))`. Python's `hash()` for strings is randomized per process (PYTHONHASHSEED). This means cache keys are not stable across processes, which is fine for in-memory caching within a single run. But the bigger problem is that `hash()` can collide: two different parameter sets could produce the same hash, causing incorrect cache hits. Using `hash()` as part of a dict key tuple means collisions result in silent wrong answers.

**Suggestion**: Use the frozen tuple directly as the key instead of hashing it:

```python
def _cache_key(self, claim, repo_path, language):
    params_frozen = tuple(sorted(claim.parameters.items()))
    return (claim.claim_type, params_frozen, repo_path, language)
```

Tuples of strings are perfectly valid dict keys and won't collide. The hash is computed by the dict internally.

---

## [SEVERITY: nit] `register()` rejects collisions with built-ins but the error UX is unclear

**Location**: Section 4 (Custom Claim Types)

**Finding**: The spec says `register()` raises `ValueError` on collision with built-in types. But it doesn't clarify what happens if a user calls `register()` twice with the same custom type. Can custom types be overridden? Can they be unregistered? The spec only addresses built-in collisions.

**Suggestion**: Define the full lifecycle: `register()` raises on any duplicate (built-in or previously registered custom), and add an `unregister(claim_type)` method for testing/reconfiguration. Or allow re-registration with a `force=True` parameter.

---

## [SEVERITY: nit] `register_dependency()` is a separate call from `register()`, easy to forget

**Location**: Section 4 (Optional Dependency Registration)

**Finding**: Custom type registration requires two separate calls: `verifier.register(...)` for the verifier function, and `verifier.register_dependency(...)` for chaining rules. This is a two-step process that's easy to get wrong (register the type but forget the dependency, or register the dependency for a type that doesn't exist yet).

**Suggestion**: Allow dependency declaration in the `register()` call itself:

```python
verifier.register(
    claim_type="DATABASE_QUERY",
    verifier_fn=my_db_verifier,
    extraction_hint="...",
    depends_on=[("FILE_EXISTS", "file")],  # optional
)
```

Keep `register_dependency()` for adding dependencies after the fact, but make the common case a single call.

---

## [SEVERITY: nit] The spec doesn't address `__all__` exports for the new public API surface

**Location**: Section 1 (File Changes), `__init__.py`

**Finding**: The current `__init__.py` has an explicit `__all__` list. The spec adds `register()`, `verify_batch()`, and `as_tools()` as new public API methods on `CodeClaimVerifier`, and adds `VerificationEngine` as a new class. But it doesn't specify whether `VerificationEngine` should be in `__all__` (public API) or kept as an internal implementation detail. If it's internal, users shouldn't import it directly. If it's public, it needs documentation and stability guarantees.

**Suggestion**: Keep `VerificationEngine` out of `__all__`. It's an implementation detail of `CodeClaimVerifier`. Users interact with the facade, not the engine. If someone needs engine-level access, they can import from `code_claim_verifier.engine` explicitly, understanding it's not part of the stable API.
