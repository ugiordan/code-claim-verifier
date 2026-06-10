# CodeClaimVerifier

Deterministic verification of LLM security triage claims against source code.

## The Problem

LLM agents performing security triage make specific claims about code: "function X has no callers," "package version is 2.4.1," "the file is a test fixture." These claims drive triage verdicts. But LLMs hallucinate.

**CodeClaimVerifier extracts typed claims from agent reasoning and verifies each one deterministically against the actual source code.** Use LLMs for extraction, use code for truth.

## How It Works

```
Agent Reasoning → [Extract Claims] → TypedClaims → [Deterministic Verify] → Report
                   (1 LLM call)                     (grep, read, parse)
                                                    (0 LLM calls)
```

1. **Extract**: One structured-output LLM call decomposes reasoning into typed claims
2. **Verify**: Each claim dispatches to a type-specific deterministic verifier
3. **Calibrate**: Verification rate determines action (BOOST / FLAG / OVERRIDE)

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

print(report.verification_rate)   # 0.75
print(report.action)              # "FLAG"
print(report.hallucination_rate)  # 0.25
```

## 14 Claim Types

| Category | Types | Verification Method |
|----------|-------|-------------------|
| File/Path | FILE_EXISTS, LINE_CONTENT, FILE_CLASSIFICATION, GENERATED_OR_VENDORED | os.path, file read, path regex |
| Function | FUNCTION_EXISTS, FUNCTION_CALLED, HAS_CALLERS | Language-aware grep (Python, Go, TS, Java, C, Rust) |
| Dependency | IMPORT_EXISTS, PACKAGE_VERSION, DEPENDENCY_TYPE, CVE_AFFECTS_VERSION | Grep, lockfile parse |
| Security | ABSENCE, MITIGATION_EXISTS, ENTRY_POINT | Grep with scope, file read |

## Verification Actions

| Rate | Action | Effect |
|------|--------|--------|
| 80-100% | BOOST | Keep classification, increase confidence |
| 50-79% | FLAG | Keep classification, lower confidence, flag for review |
| <50% | OVERRIDE | Force uncertain, block downstream actions |

## Key Features

- **Zero LLM calls for verification.** Grep doesn't hallucinate.
- **Language-aware.** Function/import patterns for Python, Go, TypeScript, Java, C/C++, Rust.
- **Absence claims are first-class.** "No callers exist" is verifiable via grep.
- **Path traversal prevention.** Claims referencing `../../etc/passwd` are blocked.
- **Confidence tiers.** Each verification method has a documented confidence level (60-99%).

## Installation

```bash
pip install code-claim-verifier
```

Or from source:

```bash
git clone https://github.com/ugiordan/code-claim-verifier
cd code-claim-verifier
pip install -e .
```

## Dependencies

None. Standard library only (os, re, subprocess, json, dataclasses). The LLM function is provided by the caller.

## Research

This tool accompanies the paper: "CodeClaimVerifier: Deterministic Verification of LLM Security Triage Claims Against Source Code" (targeting ICSE 2027).

Inspired by [Claimify](https://arxiv.org/abs/2502.10855) (ACL 2025), extended to the code domain with deterministic verification.

## License

Apache 2.0
