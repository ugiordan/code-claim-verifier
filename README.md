# CodeClaimVerifier

Deterministic verification of LLM claims about source code.

## The Problem

LLMs make specific assertions about code: "function X has no callers," "package version is 2.4.1," "this file is auto-generated." These claims drive decisions in security triage, code review, refactoring, migration, and documentation. But LLMs hallucinate.

**CodeClaimVerifier extracts typed claims from LLM reasoning and verifies each one deterministically against the actual source code.** Use LLMs for extraction, use code for truth.

## How It Works

```
LLM Reasoning -> [Extract Claims] -> TypedClaims -> [Deterministic Verify] -> Report
                  (1 LLM call)                      (grep, read, parse)
                                                    (0 LLM calls)
```

1. **Extract**: One structured-output LLM call decomposes reasoning into typed claims
2. **Verify**: Each claim dispatches to a type-specific deterministic verifier
3. **Chain**: Dependency graph detects when prerequisite claims fail (e.g., file doesn't exist, so line content is suspect)
4. **Calibrate**: Verification rate determines action (BOOST / FLAG / OVERRIDE)

## Quick Start

```python
from code_claim_verifier import CodeClaimVerifier

verifier = CodeClaimVerifier(
    llm_function=my_llm_call,   # (system_prompt, user_prompt) -> str
    repo_path="/path/to/repo",
)

report = verifier.verify(
    reasoning="torch.load() at model.py:42 has no callers in the codebase...",
    evidence={"call_chain": [], "mitigations_found": ["sanitizer at util.py:15"]},
    finding_file="model.py",
    domain_context="Security vulnerability triage",
)

print(report.verification_rate)   # 0.75
print(report.action)              # "FLAG"
print(report.hallucination_rate)  # 0.25
```

## Batch Verification

Verify multiple findings with shared caches and adaptive batching:

```python
reports = verifier.verify_batch(
    items=[
        {"reasoning": "...", "evidence": {}, "finding_file": "model.py"},
        {"reasoning": "...", "evidence": {}, "finding_file": "util.go"},
    ],
    domain_context="security triage",
    max_chars_per_batch=6000,
)
```

Multi-item batches share a grep cache and use a single LLM call for extraction. Dependency graphs are per-finding (no cross-contamination).

## Custom Claim Types

Register domain-specific verifiers:

```python
from code_claim_verifier.types import TypedClaim, VerifiedClaim

def verify_database_query(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    # your verification logic
    ...

verifier.register(
    claim_type="DATABASE_QUERY",
    verifier_fn=verify_database_query,
    extraction_hint="DATABASE_QUERY: {pattern: str, engine: str} - checks SQL patterns",
    depends_on=[("FILE_EXISTS", "file", "path")],
)
```

Custom types get the same caching, chaining, and calibration as built-ins.

## CLI

```bash
# Verify a single finding
python -m code_claim_verifier verify \
    --repo /path/to/repo \
    --reasoning "torch.load() is called at model.py:42" \
    --llm-provider anthropic

# Batch verify from JSONL
python -m code_claim_verifier verify-batch \
    --repo /path/to/repo \
    --input findings.jsonl

# List claim taxonomy
python -m code_claim_verifier list-types

# Run evaluation
python -m code_claim_verifier eval \
    --dataset eval/dataset.jsonl \
    --fixtures eval/fixtures/
```

## Tool Schemas for Agent Integration

Expose CCV as tools for any LLM agent framework:

```python
# Instance method (includes custom types)
tools = verifier.as_tools()

# Class method (built-in types only)
tools = CodeClaimVerifier.default_tools()
```

Returns standard tool-use format with `extract_claims`, `verify_claim`, `verify_all`, `list_claim_types`.

## 14 Claim Types

| Category | Types | Verification Method |
|----------|-------|-------------------|
| File/Path | FILE_EXISTS, LINE_CONTENT, FILE_CLASSIFICATION, GENERATED_OR_VENDORED | os.path, file read, path regex |
| Function | FUNCTION_EXISTS, FUNCTION_CALLED, HAS_CALLERS | Language-aware grep (Python, Go, TS, Java, C, Rust) |
| Dependency | IMPORT_EXISTS, PACKAGE_VERSION, DEPENDENCY_TYPE, CVE_AFFECTS_VERSION | Grep, lockfile parse |
| Code | ABSENCE, MITIGATION_EXISTS, ENTRY_POINT | Grep with scope, file read |

## Claim Chaining

When claim B depends on claim A (e.g., LINE_CONTENT depends on FILE_EXISTS), CCV:
- Infers dependencies from shared parameters
- Synthesizes missing prerequisite claims
- Verifies in topological order
- Marks dependents as SUSPECT when all prerequisites of a type are REFUTED
- Uses ANY-match semantics: one VERIFIED prerequisite is enough

## Verification Actions

| Rate | Action | Meaning |
|------|--------|---------|
| 80-100% | BOOST | Claims check out. Increase confidence. |
| 50-79% | FLAG | Some claims failed. Flag for review. |
| <50% | OVERRIDE | Majority wrong. Override the LLM's conclusion. |

## Key Design Principles

- **Zero LLM calls for verification.** Grep doesn't hallucinate.
- **Language-aware.** Function/import patterns for Python, Go, TypeScript, Java, C/C++, Rust.
- **Absence claims are first-class.** "No callers exist" is verifiable via grep.
- **Claim chaining.** Dependency graph catches cascading failures.
- **Thread-safe caching.** contextvars-based grep cache, per-call verifier cache.
- **Path traversal prevention.** Claims referencing `../../etc/passwd` are blocked.
- **Domain-agnostic.** Works with security triage, code review, refactoring, or any LLM-about-code output.

## Installation

```bash
pip install code-claim-verifier
```

With LLM providers for CLI:

```bash
pip install code-claim-verifier[anthropic]
pip install code-claim-verifier[openai]
```

Or from source:

```bash
git clone https://github.com/ugiordan/code-claim-verifier
cd code-claim-verifier
pip install -e ".[test]"
```

## Evaluation Framework

Built-in evaluation for measuring extraction and verification quality:

```bash
python -m code_claim_verifier eval \
    --dataset eval/dataset.jsonl \
    --fixtures eval/fixtures/ \
    --output report.json
```

Three stages: extraction precision/recall, verification accuracy with confusion matrix, per-type calibration analysis with ECE.

## Dependencies

Core: none (stdlib only). Optional: `anthropic` or `openai` for CLI providers.

## Research

This tool accompanies the paper: "CodeClaimVerifier: Deterministic Verification of LLM Claims About Source Code" (targeting ICSE 2027).

Inspired by [Claimify](https://arxiv.org/abs/2502.10855) (ACL 2025), extended to the code domain with deterministic verification. Key differences:
- Claimify is extraction-only. CCV adds deterministic verification.
- Claimify filters out absence claims. CCV makes them first-class.
- Claimify verifies against text. CCV verifies against source code.
- Claimify uses LLM-as-judge. CCV uses zero LLM calls for verification.

## License

Apache 2.0

## Copyright

Copyright (c) Red Hat, Inc.
