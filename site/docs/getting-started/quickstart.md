# Quick Start

This guide walks through verifying LLM claims against a real codebase using the Python API.

## 1. Define your LLM function

CCV needs a function with the signature `(system_prompt: str, user_prompt: str) -> str`. This is the only LLM call in the entire pipeline. It's used for claim extraction, not verification.

```python
def my_llm(system: str, user: str) -> str:
    """Your LLM wrapper. CCV calls this once per verify()."""
    import anthropic
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return response.content[0].text
```

You can use any LLM backend. The function just needs to accept two strings and return a string.

## 2. Create the verifier

```python
from code_claim_verifier import CodeClaimVerifier

verifier = CodeClaimVerifier(
    llm_function=my_llm,
    repo_path="/path/to/your/repo",
)
```

## 3. Verify some reasoning

Pass the LLM's reasoning text (any natural language that makes assertions about code) to `verify()`:

```python
reasoning = """
The vulnerability in CVE-2024-1234 affects the parse_config() function
in src/config.py. This function calls yaml.load() without specifying
a safe loader, which allows arbitrary code execution. The function is
called from the main entry point in app.py.
"""

report = verifier.verify(
    reasoning=reasoning,
    finding_file="src/config.py",
    domain_context="security triage",
)
```

## 4. Read the report

```python
# Top-level verdict
print(f"Action: {report.action}")
# BOOST   = high confidence, LLM reasoning is well-grounded (rate >= 0.8)
# FLAG    = medium confidence, some claims unverified (rate >= 0.5)
# OVERRIDE = low confidence, significant hallucination detected (rate < 0.5)

# Numeric scores
print(f"Verification rate: {report.verification_rate}")
print(f"Hallucination rate: {report.hallucination_rate}")
print(f"Claims: {report.verified}/{report.verifiable_claims} verified, "
      f"{report.refuted} refuted, {report.unverifiable} unverifiable")

# Per-claim details
for vc in report.per_claim:
    print(f"  [{vc.verdict}] {vc.claim.claim_type}: {vc.claim.parameters}")
    print(f"    method={vc.method}, confidence={vc.method_confidence}")
    print(f"    evidence: {vc.evidence[:100]}")
    if vc.suspect_reason:
        print(f"    SUSPECT: {vc.suspect_reason}")
```

Example output:

```
Action: FLAG
Verification rate: 0.67
Hallucination rate: 0.33
Claims: 2/3 verified, 1 refuted, 0 unverifiable
  [VERIFIED] FILE_EXISTS: {'path': 'src/config.py'}
    method=os.path.isfile, confidence=0.99
    evidence: exists: src/config.py
  [VERIFIED] FUNCTION_EXISTS: {'name': 'parse_config', 'file': 'src/config.py'}
    method=grep_function_def, confidence=0.85
    evidence: src/config.py:15:def parse_config(path):
  [REFUTED] FUNCTION_CALLED: {'name': 'yaml.load', 'expected': True}
    method=grep_call_site, confidence=0.65
    evidence: No call sites (0 matches).
```

## 5. Use the dict output

For serialization or downstream processing:

```python
import json

data = report.to_dict()
print(json.dumps(data, indent=2))
```

The `to_dict()` method returns a plain dict with all fields, including a `claims` list with per-claim details (evidence truncated to 500 chars).

## What happens under the hood

When you call `verify()`, CCV:

1. Sends the reasoning text to your LLM function, asking it to extract structured claims
2. Parses the LLM response into `TypedClaim` objects (e.g., `FILE_EXISTS(path="src/config.py")`)
3. Builds a dependency graph and synthesizes missing prerequisites
4. Verifies each claim using deterministic tools (grep, file read, lockfile parse)
5. Propagates SUSPECT flags when prerequisites are refuted
6. Calibrates the results into a confidence score and action

The LLM is only involved in step 1. Steps 2-6 are entirely deterministic.
