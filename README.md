# CodeClaimVerifier

Deterministic verification of LLM claims about source code.

## The Problem

LLMs make specific assertions about code: "function X has no callers," "package version is 2.4.1," "this file is auto-generated." These claims drive decisions in security triage, code review, refactoring, migration, and documentation. But LLMs hallucinate.

**CodeClaimVerifier extracts typed claims from LLM reasoning and verifies each one deterministically against the actual source code.** Use LLMs for extraction, use code for truth.

## How It Works

```
LLM Reasoning → [Extract Claims] → TypedClaims → [Deterministic Verify] → Report
                  (1 LLM call)                     (grep, read, parse)
                                                   (0 LLM calls)
```

1. **Extract**: One structured-output LLM call decomposes reasoning into typed claims
2. **Verify**: Each claim dispatches to a type-specific deterministic verifier
3. **Calibrate**: Verification rate determines action (BOOST / FLAG / OVERRIDE)

## Use Cases

| Domain | What It Verifies |
|--------|-----------------|
| **Security triage** | "The vulnerable function has no callers" (grep), "Package is version 2.4.1" (lockfile) |
| **Code review** | "Error handling exists at line 42" (file read), "All tests pass" (file check) |
| **Refactoring** | "All usages of deprecated API were updated" (absence grep) |
| **Migration** | "Package X upgraded from 1.0 to 2.0" (lockfile parse) |
| **Documentation** | "Function accepts parameter Y" (function grep), "File exists at path Z" (os.path) |
| **Architecture** | "Service exposes gRPC endpoint" (entry point grep), "Module imports library X" (import grep) |

## Quick Start

```python
from code_claim_verifier import CodeClaimVerifier

verifier = CodeClaimVerifier(
    llm_function=my_llm_call,   # (system_prompt, user_prompt) -> str
    repo_path="/path/to/repo",
)

# Verify any LLM reasoning about code
report = verifier.verify(
    reasoning="torch.load() at model.py:42 has no callers in the codebase...",
    evidence={"call_chain": [], "mitigations_found": ["sanitizer at util.py:15"]},
    finding_file="model.py",
    domain_context="Security vulnerability triage",  # optional
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
| Code | ABSENCE, MITIGATION_EXISTS, ENTRY_POINT | Grep with scope, file read |

## Verification Actions

| Rate | Action | Meaning |
|------|--------|---------|
| 80-100% | BOOST | Claims check out. Increase confidence in the LLM's conclusion. |
| 50-79% | FLAG | Some claims failed. Flag for human review. |
| <50% | OVERRIDE | Majority of claims are wrong. The LLM is hallucinating. Override its conclusion. |

## Key Design Principles

- **Zero LLM calls for verification.** Grep doesn't hallucinate. `os.path.exists()` doesn't hallucinate.
- **Language-aware.** Function/import patterns for Python, Go, TypeScript, Java, C/C++, Rust.
- **Absence claims are first-class.** "No callers exist" is verifiable via grep.
- **Path traversal prevention.** Claims referencing `../../etc/passwd` are blocked.
- **Confidence tiers.** Each verification method has a documented confidence level (60-99%).
- **Domain-agnostic.** Works with security triage, code review, refactoring, or any LLM-about-code output.

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
