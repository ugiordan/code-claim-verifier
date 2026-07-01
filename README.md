# CodeClaimVerifier

Deterministic verification of LLM claims about source code. Zero LLM calls for verification.

## The Problem

LLMs reason about code and make factual assertions: "function X has no callers," "package version is 2.4.1," "this file is auto-generated." These assertions drive real decisions: triage verdicts, review approvals, migration plans. But LLMs hallucinate, and nobody checks whether their claims about the code are actually true.

**Without CCV**, an LLM can dismiss a real vulnerability by hallucinating "no callers" for a function that is called in three places. Or it can escalate a non-issue by claiming a dangerous function is used when it isn't. Both cost time and create risk.

**With CCV**, every factual claim the LLM makes about code is extracted, typed, and verified against the actual codebase using grep, file reads, and lockfile parsing. Grep doesn't hallucinate.

## What It Actually Does

```
LLM says: "torch.load() at model.py:42 has no callers.
           The vulnerability is dead code."

CCV extracts 3 claims:
  FILE_EXISTS(path=model.py)           -> VERIFIED  (file exists)
  FUNCTION_CALLED(name=torch.load)     -> VERIFIED  (call sites found)
  HAS_CALLERS(name=torch.load, false)  -> REFUTED   (grep found 2 callers)

Result: 67% verified, action=FLAG
  "The LLM claimed torch.load has no callers, but grep found 2 call sites.
   Re-triage this finding."
```

The LLM was wrong about the callers. Without CCV, this vulnerability would have been dismissed as dead code. With CCV, it gets flagged for human review.

## Where It Helps

### Catching false negatives (missed vulnerabilities)

An LLM triaging a CVE says: "The vulnerable function `yaml.load()` is not imported anywhere in the codebase. This CVE doesn't affect us."

CCV extracts `IMPORT_EXISTS(module=yaml)`, greps the repo, finds `import yaml` in `config/parser.py`. The LLM's "not imported" claim is REFUTED. The CVE stays open instead of being incorrectly closed.

### Catching false positives (false alarms)

An LLM reviewing code says: "The function `process_input()` is called without sanitization. This is an injection vulnerability."

CCV extracts `FUNCTION_CALLED(name=process_input, expected=true)`. Grep finds zero call sites (the function was removed last sprint). The LLM's claim is REFUTED. The security team doesn't waste time investigating a non-existent call path.

### Calibrating confidence

An LLM produces a triage with 5 factual claims. CCV verifies 4 out of 5 (80% verification rate). Action: BOOST. The triage is reliable.

Another LLM triage has 3 claims, 1 verified, 2 refuted (33% rate). Action: OVERRIDE. The LLM is hallucinating. Don't trust this triage, re-run it or escalate to a human.

| Verification Rate | Action | What It Means |
|---|---|---|
| 80-100% | BOOST | Claims check out. Trust the LLM's conclusion. |
| 50-79% | FLAG | Some claims failed. Human should review. |
| <50% | OVERRIDE | Majority wrong. Don't trust this output. |

## How It Works

```
LLM Reasoning (text)
    |
    v
[1. Extract Claims]     -- 1 LLM call, structured output
    |                       "torch.load has no callers" -> HAS_CALLERS(name=torch.load, expected=false)
    v
[2. Build Dependencies]  -- 0 LLM calls
    |                       HAS_CALLERS depends on FUNCTION_EXISTS
    |                       synthesize missing prerequisites
    v
[3. Verify Each Claim]   -- 0 LLM calls
    |                       grep, os.path.exists, lockfile parse
    |                       language-aware patterns (Python, Go, TS, Java, C, Rust)
    v
[4. Propagate Failures]  -- 0 LLM calls
    |                       if FILE_EXISTS is REFUTED, flag all dependent claims as SUSPECT
    v
[5. Calibrate]           -- 0 LLM calls
    |                       weighted verification rate -> action (BOOST/FLAG/OVERRIDE)
    v
VerificationReport
```

One LLM call for extraction. Zero LLM calls for verification. The verification step uses the same tools a developer would use to check: does this file exist? Is this function defined? Is this package at this version?

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
)

print(report.verification_rate)   # 0.67
print(report.action)              # "FLAG"
print(report.hallucination_rate)  # 0.33

# Inspect individual claims
for claim in report.per_claim:
    print(f"  {claim.claim.claim_type}: {claim.verdict} ({claim.evidence[:80]})")
```

## 17 Claim Types

| Category | Types | How It Verifies |
|---|---|---|
| **File/Path** | FILE_EXISTS, LINE_CONTENT, FILE_CLASSIFICATION, GENERATED_OR_VENDORED | `os.path.isfile()`, file read, path regex, header markers |
| **Function** | FUNCTION_EXISTS, FUNCTION_CALLED, HAS_CALLERS | Language-aware grep for definitions and call sites |
| **Dependency** | IMPORT_EXISTS, PACKAGE_VERSION, DEPENDENCY_TYPE, CVE_AFFECTS_VERSION | Import grep, lockfile parse (requirements.txt, go.sum, package-lock.json) |
| **Code** | ABSENCE, MITIGATION_EXISTS, ENTRY_POINT | Scoped grep (negated), file read, framework pattern grep |
| **Auth Chain** | CALL_CHAIN, DEFAULT_VALUE, CONFIG_FLAG | Multi-hop call path grep, default value/nil checks, config flag grep |

Each type has a documented confidence level (0.60 for absence claims up to 0.99 for file existence) reflecting the verification method's precision.

## Claim Chaining

LLM claims have implicit dependencies. "Line 42 contains `torch.load()`" is meaningless if the file doesn't exist.

CCV infers these dependencies automatically:
- LINE_CONTENT depends on FILE_EXISTS (same path)
- FUNCTION_CALLED depends on FUNCTION_EXISTS (same name)
- CALL_CHAIN depends on FUNCTION_EXISTS (each function in the chain)
- IMPORT_EXISTS depends on FILE_EXISTS (same file)

If the file doesn't exist, all claims about its contents are marked SUSPECT with reduced confidence. If the function doesn't exist, claims about it being called are flagged.

This catches cascading hallucinations: the LLM invents a file, then makes detailed claims about what's in it. CCV refutes the file existence and flags everything downstream.

## Batch Verification

Verify multiple findings with shared caches and adaptive batching:

```python
reports = verifier.verify_batch(
    items=[
        {"reasoning": "...", "evidence": {}, "finding_file": "model.py"},
        {"reasoning": "...", "evidence": {}, "finding_file": "util.go"},
    ],
    domain_context="security triage",
)
```

Multi-item batches share a grep cache (same pattern searched once) and use fewer LLM calls for extraction. Dependency graphs are per-finding (no cross-contamination).

## Custom Claim Types

Register domain-specific verifiers for claims CCV doesn't cover out of the box:

```python
from code_claim_verifier.types import TypedClaim, VerifiedClaim

def verify_has_decorator(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    from code_claim_verifier.grep import grep
    pattern = f"@{claim.parameters['decorator']}\\s*\\ndef\\s+{claim.parameters['function']}"
    matches = grep(pattern, repo_path)
    return VerifiedClaim(
        claim=claim,
        verdict="VERIFIED" if matches else "REFUTED",
        method_confidence=0.85,
        evidence=matches[0][:200] if matches else "no match",
        method="grep_decorator",
    )

verifier.register(
    claim_type="HAS_DECORATOR",
    verifier_fn=verify_has_decorator,
    extraction_hint="HAS_DECORATOR: {function: str, decorator: str} - checks if a function has a specific decorator",
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

# Batch verify from JSON
python -m code_claim_verifier verify-batch \
    --repo /path/to/repo \
    --input findings.json

# List all claim types with parameter schemas
python -m code_claim_verifier list-types

# Run evaluation against fixture repos
python -m code_claim_verifier eval \
    --dataset eval/dataset.jsonl \
    --fixtures eval/fixtures/
```

## Tool Schemas for Agent Integration

Expose CCV as tools for any LLM agent framework:

```python
tools = verifier.as_tools()       # includes custom types
tools = CodeClaimVerifier.default_tools()  # built-in types only
```

Returns `extract_claims`, `verify_claim`, `verify_all`, `list_claim_types` in standard tool-use format.

## Evaluation Framework

Built-in evaluation for measuring verification quality:

```bash
python -m code_claim_verifier eval \
    --dataset eval/dataset.jsonl \
    --fixtures eval/fixtures/ \
    --output report.json
```

Three stages:
1. **Extraction quality**: precision/recall of claim extraction against ground truth
2. **Verification accuracy**: correct verdicts by claim type, confusion matrix, false-refuted/verified rates
3. **Calibration analysis**: per-type predicted confidence vs actual accuracy, ECE score

## Installation

```bash
pip install code-claim-verifier
```

With LLM providers for CLI:

```bash
pip install code-claim-verifier[anthropic]
pip install code-claim-verifier[openai]
```

From source:

```bash
git clone https://github.com/ugiordan/code-claim-verifier
cd code-claim-verifier
pip install -e ".[test]"
```

## Key Design Principles

- **Zero LLM calls for verification.** Grep doesn't hallucinate. `os.path.exists()` doesn't hallucinate.
- **Language-aware.** Function/import patterns for Python, Go, TypeScript, Java, C/C++, Rust.
- **Absence is first-class.** "No callers exist" is the most important claim in security triage, and CCV verifies it.
- **Claim chaining.** Cascading hallucinations caught by dependency propagation.
- **Thread-safe.** contextvars-based caching, safe for concurrent use in agent frameworks.
- **Zero dependencies.** Core library is stdlib only. Optional providers for CLI.
- **Domain-agnostic.** Security triage, code review, refactoring, migration, documentation, architecture assessment.

## Background

Inspired by [Claimify](https://arxiv.org/abs/2502.10855) (ACL 2025), extended to the code domain with deterministic verification:

- Claimify is extraction-only. CCV adds deterministic verification.
- Claimify filters out absence claims. CCV makes them first-class.
- Claimify verifies against text. CCV verifies against source code.
- Claimify uses LLM-as-judge. CCV uses zero LLM calls for verification.

## License

Apache 2.0

## Copyright

Copyright (c) Red Hat, Inc.
