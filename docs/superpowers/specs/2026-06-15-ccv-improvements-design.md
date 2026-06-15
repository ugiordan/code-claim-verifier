# CCV Improvements: Chaining, Caching, Custom Types, Batch, CLI, Eval

## Overview

Five improvements to the CodeClaimVerifier library plus an evaluation framework. The core change is extracting a `VerificationEngine` class from the current module-level dispatch, then hanging chaining, caching, custom types, and batch support off it. CLI and tool schemas provide agent integration without MCP. The eval framework supports the ICSE 2027 paper.

## 1. VerificationEngine (Core Restructure)

### Current Architecture

```
CodeClaimVerifier.verify()
    → safe_verify()              # module-level in verifiers/__init__.py
    → VERIFIER_REGISTRY[type]()  # module-level dict
```

### New Architecture

```
CodeClaimVerifier.verify()
    → engine.verify_all(claims, repo_path, language)
        → build dependency graph (inference rules)
        → verify each claim in topological order (with cache)
        → propagate chaining (refuted deps → flag dependents)
        → return list[VerifiedClaim]
```

`VerificationEngine` owns three concerns:

- **Registry**: instance-level copy of built-in verifiers + user-registered custom verifiers. No global mutation.
- **Cache**: `GrepCache` for grep results, verifier-level cache for full results. Dict-based, scoped to engine lifetime.
- **Dependency graph**: inferred rules mapping claim types to prerequisites.

`CodeClaimVerifier` stays thin: holds LLM function, repo path, and engine instance. `verify()` and `verify_batch()` are the public API.

Existing verifier functions (`verify_file_exists`, `verify_function_called`, etc.) remain pure functions with the same `(claim, repo_path, language) -> VerifiedClaim` signature. No changes to their internals.

### File Changes

- New: `code_claim_verifier/engine.py` (VerificationEngine class)
- New: `code_claim_verifier/grep.py` (extracted from symbol_claims._grep, with cache support)
- Modified: `code_claim_verifier/__init__.py` (CodeClaimVerifier uses engine internally)
- Modified: `code_claim_verifier/verifiers/__init__.py` (VERIFIER_REGISTRY stays as default source, safe_verify delegates to engine)
- Modified: `code_claim_verifier/verifiers/symbol_claims.py` (import grep from grep.py)
- Modified: `code_claim_verifier/verifiers/import_claims.py` (import grep from grep.py)
- Modified: `code_claim_verifier/verifiers/security_claims.py` (import grep from grep.py)

## 2. Claim Chaining (Dependency Graph)

### Inference Rules

Dependencies inferred from shared parameters, not declared by the LLM. Each rule explicitly names the dependent type, the prerequisite type, the source parameter (on the dependent), and the target parameter (on the prerequisite):

| Rule | Dependent Claim | Depends On | Source Param | Target Param |
|------|----------------|------------|-------------|-------------|
| R1 | LINE_CONTENT | FILE_EXISTS | `path` | `path` |
| R2 | GENERATED_OR_VENDORED | FILE_EXISTS | `path` | `path` |
| R3 | FUNCTION_EXISTS (with `file`) | FILE_EXISTS | `file` | `path` |
| R4 | FUNCTION_CALLED | FUNCTION_EXISTS | `name` | `name` |
| R5 | HAS_CALLERS | FUNCTION_EXISTS | `name` | `name` |
| R6 | IMPORT_EXISTS (with `file`) | FILE_EXISTS | `file` | `path` |
| R7 | MITIGATION_EXISTS | FILE_EXISTS | `file` | `path` |

Note: FILE_CLASSIFICATION is excluded because it only checks path patterns (never reads the file). ABSENCE is excluded because it operates on pattern presence, not file existence.

### Parameter Name Mapping

When a dependency is synthesized, the source parameter value is copied to the target parameter name. For example, Rule R6 copies `IMPORT_EXISTS.parameters["file"]` into `FILE_EXISTS.parameters["path"]`. This mapping is explicit in the rules table to prevent the bug where `verify_file_exists` reads `parameters.get("path", "")` but receives a claim with only `file`.

### Resolution Algorithm

1. Extract claims from LLM output
2. Build dependency graph from inference rules
3. Identify missing prerequisites: for each rule, if the dependent claim exists but no matching prerequisite was extracted, synthesize it
4. Repeat step 3 until no new prerequisites are needed (max depth: 2 levels, with visited set for cycle detection)
5. Deduplicate synthesized claims: index by `(claim_type, frozen_parameters)`. When duplicates exist, keep one canonical instance and redirect all dependency edges from dependents to the canonical. This ensures the topological sort sees a clean graph with no dangling references.
6. Topological sort the complete graph (extracted + synthesized)
7. If a cycle is detected (possible with custom dependency rules), break it by marking all claims in the cycle as UNVERIFIABLE with evidence explaining the circular dependency
8. Verify in topological order
9. Propagate: if a dependency is REFUTED, mark all dependents as SUSPECT. When a dependent has multiple matching prerequisites of the same type (e.g., two FUNCTION_EXISTS for the same name but different files), use ANY-match semantics: SUSPECT fires only when ALL matching prerequisites are REFUTED. If at least one is VERIFIED, the dependent is not flagged.
10. If a dependency is UNVERIFIABLE, dependents run normally (don't punish unknowns)

### Synthesized Claims

Synthesized prerequisite claims are marked with `synthesized=True` on the `VerifiedClaim`. They appear in `per_claim` for debugging transparency but are excluded from report metrics (`verified`, `refuted`, `verifiable_claims` counts). This prevents phantom claims (that the LLM never asserted) from distorting confidence scores.

All synthesized claims go through `safe_verify()` for consistent error handling and path traversal protection.

### Type Changes

`VerifiedClaim` gains two fields:

```python
suspect_reason: str | None = None
synthesized: bool = False
```

A SUSPECT claim keeps its original verdict (VERIFIED/REFUTED) but is flagged. The consumer sees "this was VERIFIED but its prerequisite FILE_EXISTS was REFUTED." This keeps "I checked and it's wrong" distinct from "its foundation is wrong."

`VerificationReport.to_dict()` must include both new fields in its serialization.

### Calibration Impact

SUSPECT claims use asymmetric confidence treatment to lower the overall rate:

- A SUSPECT-VERIFIED claim contributes its **full** `method_confidence` to `weighted_total` (denominator) but only **half** to `weighted_verified` (numerator). This makes the rate go down.
- A SUSPECT-REFUTED claim contributes its **full** `method_confidence` to `weighted_total` (as normal REFUTED claims do). No change needed here.

This asymmetry is required because a symmetric 0.5x multiplier on both numerator and denominator cancels out for VERIFIED claims, having zero effect on the rate. The calibrator must filter out synthesized claims and then apply the asymmetric weighting:

```python
real_claims = [c for c in verified_claims if not c.synthesized]
verifiable = [c for c in real_claims if c.verdict != "UNVERIFIABLE"]

for c in verifiable:
    weighted_total += c.method_confidence
    if c.verdict == "VERIFIED":
        factor = 0.5 if c.suspect_reason else 1.0
        weighted_verified += c.method_confidence * factor
```

The engine passes the full list (including synthesized) to `calibrate()`, which filters internally and attaches all claims (including synthesized) to `per_claim` for debugging transparency. Counts (`verified`, `refuted`, `verifiable_claims`, `total_claims`, `errored`) exclude synthesized claims.

## 3. Caching

### Two Layers

**GrepCache** (grep.py, thread-safe via contextvars):

Uses `contextvars.ContextVar` instead of module-level global state. Each `VerificationEngine` run gets its own cache without changing verifier function signatures. Thread-safe, re-entrant, no cross-instance corruption.

```python
import contextvars

_grep_cache: contextvars.ContextVar[dict[tuple[str, str, bool], list[str]] | None] = (
    contextvars.ContextVar('_grep_cache', default=None)
)

def grep(pattern: str, path: str, fixed: bool = False) -> list[str]:
    cache = _grep_cache.get()
    if cache is not None:
        key = (pattern, path, fixed)
        if key in cache:
            return list(cache[key])  # defensive copy, prevents mutation of cached data
        result = _run_grep(pattern, path, fixed)
        cache[key] = result
        return list(result)  # defensive copy
    return _run_grep(pattern, path, fixed)

def cache_context() -> contextvars.Token:
    """Enter a caching context. Returns a token for reset."""
    return _grep_cache.set({})

def reset_cache(token: contextvars.Token) -> None:
    """Exit a caching context."""
    _grep_cache.reset(token)
```

The engine uses it as:
```python
token = grep.cache_context()
try:
    results = [self._verify_one(c) for c in ordered_claims]
finally:
    grep.reset_cache(token)
```

**VerifierCache** (on VerificationEngine):

Caches the **bare** verification result (with `synthesized=False` and `suspect_reason=None` always). On cache hit, returns a copy via `dataclasses.replace()` with `synthesized` and `suspect_reason` set to match the requesting claim's context, not the cached value. This prevents two bugs:

- **SUSPECT leakage**: per-finding SUSPECT marking from one finding doesn't corrupt another's copy
- **Synthesized flag leakage**: a synthesized claim that populates the cache first doesn't cause a real extracted claim to be excluded from metrics (or vice versa)

Keyed by `(claim_type, frozen_params, repo_path, language)`. Uses the frozen params tuple directly as the key (no `hash()` wrapper, avoids collision risk).

```python
def _freeze(value, _depth=0):
    """Recursively freeze nested structures for use as dict keys."""
    if _depth > 20:
        return str(value)  # safety cap for deeply nested structures
    if isinstance(value, dict):
        return frozenset((k, _freeze(v, _depth + 1)) for k, v in sorted(value.items()))
    if isinstance(value, set):
        return frozenset(_freeze(v, _depth + 1) for v in value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v, _depth + 1) for v in value)
    return value

def _cache_key(self, claim: TypedClaim, repo_path: str, language: str) -> tuple:
    params_frozen = _freeze(claim.parameters)
    return (claim.claim_type, params_frozen, repo_path, language)
```

### Lifecycle

**Engine lifecycle**: `VerificationEngine` is created once per `CodeClaimVerifier` instance and holds the registry and dependency rules (long-lived). Caches are **per-call**, not per-engine:

- Grep cache: engine calls `grep.cache_context()` at the start of each `verify()` or `verify_batch()` call, resets in `finally`. Each call gets its own isolated grep cache via contextvars.
- Verifier cache: a fresh dict is created at the start of each `verify()` or `verify_batch()` call. Not persisted across calls. If the repo changes between calls, there is no staleness risk.
- Concurrent engines don't interfere (contextvars isolation for grep, instance-scoped dict for verifier cache).

### Verifier Function Impact

None. Verifier functions call `grep()` from `grep.py` exactly as they currently call `_grep()` from `symbol_claims.py`. The cache is transparent and thread-safe.

## 4. Custom Claim Types

### Registration API

```python
verifier = CodeClaimVerifier(llm_function=my_llm, repo_path="/repo")

verifier.register(
    claim_type="DATABASE_QUERY",
    verifier_fn=my_db_verifier,
    extraction_hint='DATABASE_QUERY: {pattern: str, engine: str} - checks if a SQL query pattern exists',
)
```

### Mechanics

- `CodeClaimVerifier.__init__` copies the built-in `VERIFIER_REGISTRY` into `self.engine.registry` (instance-level)
- `register()` validates claim_type is not already registered (raises `ValueError` on collision with built-ins)
- `extraction_hint` is required (not optional). A custom type the LLM doesn't know about will never be extracted. If someone constructs claims manually (skipping extraction), they pass `extraction_hint=""` explicitly.
- During extraction, custom type hints are placed in a structurally separate section of the system prompt (under a `CUSTOM CLAIM TYPES:` header), distinct from the built-in type definitions and the user's `domain_context`. This prevents a poorly-written hint from overriding built-in extraction instructions. Hints are validated: max 500 chars each, must not redefine built-in type names.
- `extract_claims()` and `_parse_extraction_output()` accept a `valid_types: frozenset[str]` parameter (defaults to the module-level `CLAIM_TYPES`). The engine passes `frozenset(self.registry.keys())` when calling extraction. This keeps extraction a pure function with no dependency on the engine module.

### Verifier Function Contract

```python
def my_db_verifier(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    ...
```

Same signature as built-ins. The engine applies caching and chaining to custom types identically.

### Optional Dependency Registration

Dependencies can be declared inline with `register()`:

```python
verifier.register(
    claim_type="DATABASE_QUERY",
    verifier_fn=my_db_verifier,
    extraction_hint='DATABASE_QUERY: {pattern: str, engine: str, file: str} - checks SQL patterns',
    depends_on=[("FILE_EXISTS", "file", "path")],  # (target_type, source_param, target_param)
)
```

A separate `register_dependency()` is also available for adding dependencies after registration:

```python
verifier.register_dependency("DATABASE_QUERY", depends_on="FILE_EXISTS", source_param="file", target_param="path")
```

If no dependencies are declared, the custom type has no chaining. The built-in rules (Section 2) are always active. Registering a dependency that creates a cycle raises `ValueError`.

## 5. Batch Extraction and Verification

### API

```python
reports = verifier.verify_batch(
    items=[
        {"reasoning": "...", "evidence": {...}, "finding_file": "model.py"},
        {"reasoning": "...", "evidence": {...}, "finding_file": "util.go"},
    ],
    domain_context="security triage",
    max_chars_per_batch=6000,
    batch_fallback="partial",  # "partial" | "strict" | "skip" | "raise"
)
# Returns: list[VerificationReport], one per item
```

### Extraction Phase (Adaptive Batching)

1. Group items by cumulative reasoning text length. Split when sum exceeds `max_chars_per_batch` (default 6000).
2. Each batch gets one LLM extraction call. Prompt uses unique delimiters unlikely to appear in reasoning text:
   ```
   <<<FINDING_0:model.py>>>
   [reasoning text]
   <<<FINDING_1:util.go>>>
   [reasoning text]
   ```
3. Extraction output includes `finding_index` per claim for mapping back:
   ```json
   [{"finding_index": 0, "claim_type": "...", "parameters": {...}, "source_sentence": "..."}]
   ```
4. If a single item's reasoning exceeds `max_chars_per_batch`, it gets its own call.

### Verification Phase

The batch verification architecture uses shared caches but per-finding dependency resolution:

1. **One grep cache and one verifier cache** span the entire batch (shared). This is safe because grep results and raw verification results are repo-level facts, independent of which finding triggered them.
2. **Dependency graphs are built per-finding.** For each finding's claims, the engine constructs a separate dependency graph, synthesizes missing prerequisites, runs topological sort, and propagates SUSPECT marking. A FILE_EXISTS from Finding #0 does NOT satisfy dependencies in Finding #3.
3. **Verification itself is deduplicated across findings via the verifier cache.** If Finding #0 and Finding #3 both need FILE_EXISTS for `model.py`, it's verified once (cached), but each finding gets its own copy (via `dataclasses.replace()`) for independent SUSPECT marking.
4. After verification, claims are grouped back by finding index.
5. Each group gets its own `calibrate()` call for per-item reports.

### Fallback and Partial Recovery

Batch extraction output is validated per-claim:

1. If `finding_index` is present and in range `[0, len(items)-1]`: accept the claim, assign to that finding
2. If `finding_index` is present but out of range or negative: discard that claim (log warning)
3. If `finding_index` is missing: attempt to infer from `source_sentence` matching against the original findings text (substring match). If no match, discard.

After validation:
- If **all** claims are assignable: proceed normally
- If **>=50%** of claims are assignable: proceed with the valid subset (don't re-extract)
- If **<50%** are assignable: fall back to per-item extraction for the entire batch (log warning)
- If batch extraction **completely fails** (invalid JSON, no claims): fall back to per-item extraction

The fallback strategy is configurable via `batch_fallback` parameter:
- `"partial"` (default): use partial recovery as described above
- `"strict"`: any missing/invalid finding_index triggers full per-item re-extraction
- `"skip"`: discard unassignable claims, never re-extract
- `"raise"`: raise an exception on extraction failure (for cost-sensitive callers)

## 6. CLI and Tool Schemas

### CLI (`python -m code_claim_verifier`)

Three subcommands:

```bash
# Single finding
python -m code_claim_verifier verify \
    --repo /path/to/repo \
    --reasoning "torch.load() is called at model.py:42" \
    --finding-file model.py \
    --domain-context "security triage"

# Batch (JSONL input)
python -m code_claim_verifier verify-batch \
    --repo /path/to/repo \
    --input findings.jsonl \
    --domain-context "code review"

# Taxonomy listing
python -m code_claim_verifier list-types
```

- `verify`: reads reasoning from `--reasoning` or stdin (max 100KB). Outputs JSON report to stdout.
- `verify-batch`: reads JSONL from file or stdin, processed as a stream. Configurable `--max-items` (default 10000) to cap batch size and prevent unbounded API costs. Each line: `{"reasoning": "...", "evidence": {...}, "finding_file": "..."}`. Outputs one JSON report per line.
- `list-types`: prints claim taxonomy with parameter schemas.

### LLM Provider (Optional Dependencies)

CLI needs a concrete LLM implementation. Accepts `--llm-provider anthropic|openai` with `--model` flag.

Provider implementations in `code_claim_verifier/providers/`. If the SDK isn't installed, clear error: "pip install code-claim-verifier[anthropic]".

Base library stays zero-dependency. Providers are optional extras in pyproject.toml:

```toml
[project.optional-dependencies]
anthropic = ["anthropic>=0.20"]
openai = ["openai>=1.0"]
```

**API key handling**: Keys are read exclusively from environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`). Never accepted via CLI flags (avoids shell history and process listing exposure). Provider implementations must not log request headers or include API keys in error messages.

### Tool Schemas (`.as_tools()`)

```python
tools = verifier.as_tools()  # instance method, reflects registered custom types
```

Returns list of dicts in standard tool-use format:

```python
[
    {"name": "extract_claims", "description": "...", "input_schema": {...}},
    {"name": "verify_claim", "description": "...", "input_schema": {...}},
    {"name": "verify_all", "description": "...", "input_schema": {...}},
    {"name": "list_claim_types", "description": "...", "input_schema": {...}},
]
```

Instance method (not classmethod) so it includes custom registered types in `list_claim_types` schema. A classmethod `default_tools()` is also provided for the built-in-only schema.

### File Changes

- New: `code_claim_verifier/__main__.py` (CLI entry point)
- New: `code_claim_verifier/cli.py` (argument parsing, subcommands)
- New: `code_claim_verifier/providers/__init__.py`
- New: `code_claim_verifier/providers/anthropic.py`
- New: `code_claim_verifier/providers/openai.py`
- New: `code_claim_verifier/tools.py` (as_tools() implementation)
- Modified: `pyproject.toml` (optional dependencies, console_scripts entry point)

## 7. Evaluation Framework (ccv-eval)

### Command

```bash
python -m code_claim_verifier eval \
    --dataset eval/dataset.jsonl \
    --fixtures eval/fixtures/ \
    --output eval/report.json
```

### Dataset Format (JSONL)

Each line:

```json
{
    "id": "sample_001",
    "reasoning": "torch.load() is called at model.py:42...",
    "evidence": {},
    "finding_file": "model.py",
    "fixture_repo": "python_repo",
    "ground_truth_claims": [
        {
            "claim_type": "FUNCTION_CALLED",
            "parameters": {"name": "torch.load", "expected": true},
            "expected_verdict": "VERIFIED"
        }
    ]
}
```

### Three Evaluation Stages

**Stage 1: Extraction quality.** Run extraction on each sample, compare against ground truth claims. Metrics:
- Precision: extracted claims matching ground truth / total extracted
- Recall: ground truth claims that were extracted / total ground truth
- Matching criteria: a predicted claim matches a ground truth claim if (a) `claim_type` is identical, and (b) all ground truth parameter keys exist in the predicted claim with equal values (predicted claims may have extra keys). This is strict enough to avoid false matches but tolerant of LLM-added metadata.

**Stage 2: Verification accuracy.** For each ground truth claim with expected verdict, run verifier against fixture repo. Metrics:
- Accuracy: correct verdicts / total, broken down by claim type
- False REFUTED rate (most dangerous: could override correct triage)
- False VERIFIED rate (less dangerous but inflates confidence)
- Confusion matrix: 3x3 (VERIFIED/REFUTED/UNVERIFIABLE predicted vs actual)

**Stage 3: Per-type accuracy and confidence analysis.** Since existing verifiers use discrete hardcoded `method_confidence` values (0.60 for ABSENCE, 0.65 for FUNCTION_CALLED, 0.85 for FUNCTION_EXISTS, 0.99 for FILE_EXISTS, etc.), a traditional calibration curve would be a step function with ~8 points, not a smooth curve. Instead:

- **Per-type accuracy table**: for each claim type, report predicted confidence vs actual correctness rate. This directly answers "is FILE_EXISTS's 0.99 confidence justified?"
- **Confidence adjustment recommendations**: if a type's actual accuracy diverges from its hardcoded confidence, recommend a new value
- **Aggregate reliability**: a single ECE (Expected Calibration Error) score across all types, useful for paper reporting

If future work introduces continuous confidence values (e.g., based on match quality), the framework can switch to bucketed calibration curves. The eval infrastructure supports both modes.

### Report Output

```json
{
    "extraction": {
        "precision": 0.87,
        "recall": 0.72,
        "f1": 0.79,
        "per_type": {"FILE_EXISTS": {"precision": 0.95, "recall": 0.90}, "...": "..."}
    },
    "verification": {
        "accuracy": 0.91,
        "per_type": {"FILE_EXISTS": {"accuracy": 0.99}, "...": "..."},
        "confusion_matrix": {
            "VERIFIED": {"VERIFIED": 120, "REFUTED": 3, "UNVERIFIABLE": 2},
            "REFUTED": {"VERIFIED": 5, "REFUTED": 45, "UNVERIFIABLE": 1},
            "UNVERIFIABLE": {"VERIFIED": 0, "REFUTED": 1, "UNVERIFIABLE": 15}
        },
        "false_refuted_rate": 0.04,
        "false_verified_rate": 0.02
    },
    "calibration": {
        "per_type_accuracy": {
            "FILE_EXISTS": {"predicted_confidence": 0.99, "actual_accuracy": 0.97, "count": 19},
            "FUNCTION_EXISTS": {"predicted_confidence": 0.85, "actual_accuracy": 0.83, "count": 52},
            "FUNCTION_CALLED": {"predicted_confidence": 0.65, "actual_accuracy": 0.62, "count": 31},
            "ABSENCE": {"predicted_confidence": 0.60, "actual_accuracy": 0.55, "count": 23}
        },
        "ece": 0.028,
        "confidence_adjustments": {
            "ABSENCE": {"current": 0.60, "recommended": 0.55}
        }
    }
}
```

### Fixture Repos

Small synthetic repos under `eval/fixtures/`:
- `python_repo/`: Python project with known functions, imports, lockfile
- `go_repo/`: Go project with known functions, go.mod, go.sum
- `ts_repo/`: TypeScript project with known functions, package-lock.json

These ship with the library and provide deterministic ground truth for verification tests.

### Mock vs Real LLM

- Verification-only tests: mock LLM returns pre-canned extraction from `ground_truth_claims`, isolating verification accuracy from extraction quality
- End-to-end tests: real LLM call for extraction, measuring the full pipeline
- Controlled via `--mock-extraction` flag

### File Changes

- New: `code_claim_verifier/eval/__init__.py`
- New: `code_claim_verifier/eval/runner.py` (orchestrates the three stages)
- New: `code_claim_verifier/eval/extraction_eval.py` (stage 1)
- New: `code_claim_verifier/eval/verification_eval.py` (stage 2)
- New: `code_claim_verifier/eval/calibration_eval.py` (stage 3: per-type accuracy and ECE)
- New: `code_claim_verifier/eval/report.py` (report generation)
- New: `eval/dataset.jsonl` (evaluation dataset)
- New: `eval/fixtures/python_repo/` (fixture repos)
- New: `eval/fixtures/go_repo/`
- New: `eval/fixtures/ts_repo/`
- Modified: `code_claim_verifier/cli.py` (add eval subcommand)

## Summary of All New/Modified Files

### New Files
| File | Purpose |
|------|---------|
| `code_claim_verifier/engine.py` | VerificationEngine class |
| `code_claim_verifier/grep.py` | Extracted grep with cache support |
| `code_claim_verifier/__main__.py` | CLI entry point |
| `code_claim_verifier/cli.py` | CLI argument parsing and subcommands |
| `code_claim_verifier/tools.py` | `.as_tools()` tool schema generation |
| `code_claim_verifier/providers/__init__.py` | Provider base |
| `code_claim_verifier/providers/anthropic.py` | Anthropic LLM provider |
| `code_claim_verifier/providers/openai.py` | OpenAI LLM provider |
| `code_claim_verifier/eval/__init__.py` | Eval package |
| `code_claim_verifier/eval/runner.py` | Eval orchestrator |
| `code_claim_verifier/eval/extraction_eval.py` | Extraction quality metrics |
| `code_claim_verifier/eval/verification_eval.py` | Verification accuracy metrics |
| `code_claim_verifier/eval/calibration_eval.py` | Per-type accuracy, ECE, confidence adjustment |
| `code_claim_verifier/eval/report.py` | Report generation |
| `eval/dataset.jsonl` | Evaluation dataset |
| `eval/fixtures/python_repo/` | Python fixture repo |
| `eval/fixtures/go_repo/` | Go fixture repo |
| `eval/fixtures/ts_repo/` | TypeScript fixture repo |

### Modified Files
| File | Change |
|------|--------|
| `code_claim_verifier/__init__.py` | CodeClaimVerifier uses engine, adds register/verify_batch/as_tools |
| `code_claim_verifier/types.py` | VerifiedClaim gains `suspect_reason` and `synthesized` fields; `to_dict()` updated to include both |
| `code_claim_verifier/calibrator.py` | Filter synthesized claims, asymmetric SUSPECT weighting |
| `code_claim_verifier/extractor.py` | Batch extraction support, dynamic claim type validation |
| `code_claim_verifier/verifiers/__init__.py` | VERIFIER_REGISTRY stays as default, safe_verify updated |
| `code_claim_verifier/verifiers/symbol_claims.py` | Import grep from grep.py |
| `code_claim_verifier/verifiers/import_claims.py` | Import grep from grep.py; fix lockfile substring matching (`package in parts[0]` to exact match) |
| `code_claim_verifier/verifiers/security_claims.py` | Import grep from grep.py |
| `pyproject.toml` | Optional deps, console_scripts, eval extras |
