# Batch Verification

When you need to verify many findings at once (e.g., processing a security scan report with hundreds of items), use `verify_batch()` instead of calling `verify()` in a loop. It's faster because it shares caches and groups LLM calls.

## Basic usage

```python
from code_claim_verifier import CodeClaimVerifier

verifier = CodeClaimVerifier(llm_function=my_llm, repo_path="/path/to/repo")

items = [
    {
        "reasoning": "The file src/auth.py uses md5 for password hashing.",
        "evidence": {"tool": "semgrep", "rule": "insecure-hash"},
        "finding_file": "src/auth.py",
    },
    {
        "reasoning": "The function parse_config in config.go calls yaml.Unmarshal without validation.",
        "evidence": {},
        "finding_file": "config.go",
    },
    {
        "reasoning": "The dependency lodash@4.17.15 has a known prototype pollution vulnerability.",
        "evidence": {"cve": "CVE-2020-8203"},
        "finding_file": "package.json",
    },
]

reports = verifier.verify_batch(
    items=items,
    domain_context="security triage",
)

for i, report in enumerate(reports):
    print(f"Item {i}: {report.action} ({report.verified}/{report.verifiable_claims} verified)")
```

## How batching works

### Adaptive batch grouping

`verify_batch()` groups items by cumulative reasoning length, controlled by `max_chars_per_batch` (default: 6000 characters).

```
Items:     [A=1000] [B=2000] [C=5000] [D=1500] [E=800]
Batches:   [A, B]   [C]              [D, E]
            3000     5000              2300
```

The algorithm:

- Accumulates items into a batch until adding the next item would exceed the character budget
- Items whose reasoning exceeds the budget on their own become single-item batches
- Single-item batches use `extract_claims()` (one LLM call)
- Multi-item batches use `extract_claims_batch()` (one LLM call for the whole batch)

This reduces the total number of LLM calls from N (one per item) to roughly N / batch_size.

### Shared grep cache

During batch verification, a single grep cache is active across all items. This means if item A and item C both trigger a `FUNCTION_EXISTS("parse_config")` check, the grep subprocess runs once and the result is reused.

The cache is a `contextvars.ContextVar` dictionary, keyed by `(pattern, path, fixed)`. It's activated at the start of `verify_batch()` and reset when it completes.

### Per-finding dependency graphs

While the grep cache is shared, dependency graphs are per-finding. Each item gets its own synthesis, topological sort, and SUSPECT propagation. This prevents cross-contamination between unrelated findings.

### Verifier result cache

In addition to the grep cache, the verification engine maintains a verifier result cache keyed by `(claim_type, frozen_parameters, repo_path, language)`. If two items produce structurally identical claims, the verifier function runs once.

## API reference

```python
def verify_batch(
    self,
    items: list[dict],
    domain_context: str = "",
    max_chars_per_batch: int = 6000,
    batch_fallback: str = "partial",
) -> list[VerificationReport]
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `items` | `list[dict]` | (required) | List of dicts with keys: `reasoning` (str), `evidence` (dict, optional), `finding_file` (str, optional) |
| `domain_context` | `str` | `""` | Domain-specific extraction context, applied to all items |
| `max_chars_per_batch` | `int` | `6000` | Maximum characters of reasoning per extraction batch |
| `batch_fallback` | `str` | `"partial"` | Fallback strategy for batch extraction failures |

**Returns:** list of `VerificationReport` objects, one per input item, in the same order.

### Fallback strategies

The `batch_fallback` parameter controls what happens when the LLM's batch extraction output can't be properly assigned to individual items:

- `"partial"` (default): if fewer than 50% of extracted claims can be assigned to their originating item (via `finding_index`), discard the entire batch result and return empty claims for all items in that batch. This prevents misattribution.
- `"skip"`: silently drop any claims that lack a valid `finding_index`. Items whose claims were properly indexed still get their results.

## Example with custom batch size

For large repos where each finding involves complex reasoning:

```python
reports = verifier.verify_batch(
    items=items,
    domain_context="security triage for a Go microservice",
    max_chars_per_batch=3000,  # smaller batches, more LLM calls, but more reliable extraction
    batch_fallback="partial",
)
```

For simple findings with short reasoning:

```python
reports = verifier.verify_batch(
    items=items,
    max_chars_per_batch=10000,  # larger batches, fewer LLM calls
)
```
