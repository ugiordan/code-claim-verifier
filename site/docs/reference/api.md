# API Reference

## CodeClaimVerifier

The main entry point. Wraps the extraction, verification, and calibration pipeline.

```python
from code_claim_verifier import CodeClaimVerifier
```

### Constructor

```python
CodeClaimVerifier(
    llm_function: Callable[[str, str], str],
    repo_path: str,
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `llm_function` | `Callable[[str, str], str]` | Function that takes `(system_prompt, user_prompt)` and returns the LLM's response string. Called once per `verify()` for claim extraction. |
| `repo_path` | `str` | Absolute or relative path to the repository root. All file paths in claims are resolved relative to this. |

### verify()

```python
def verify(
    self,
    reasoning: str,
    evidence: dict | None = None,
    finding_file: str = "",
    domain_context: str = "",
) -> VerificationReport
```

Verify claims in LLM reasoning against the actual codebase. This is the primary method for single-item verification.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `reasoning` | `str` | (required) | The LLM's natural language reasoning about code |
| `evidence` | `dict \| None` | `None` | Optional structured evidence dict (tool output, triage results, etc.) |
| `finding_file` | `str` | `""` | File path used for language detection. If provided, the verifier uses language-specific patterns for that file's extension. |
| `domain_context` | `str` | `""` | Domain-specific instructions appended to the extraction prompt (e.g., "This is a security triage context" or "This is a code review for a Go microservice") |

**Returns:** `VerificationReport`

**Pipeline:** Calls `extract_claims()` with the LLM function, builds a dependency graph, verifies claims with chaining, and calibrates the results.

### verify_batch()

```python
def verify_batch(
    self,
    items: list[dict],
    domain_context: str = "",
    max_chars_per_batch: int = 6000,
    batch_fallback: str = "partial",
) -> list[VerificationReport]
```

Verify multiple items with adaptive batching and shared caches.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `items` | `list[dict]` | (required) | List of dicts with keys: `reasoning` (str), `evidence` (dict), `finding_file` (str) |
| `domain_context` | `str` | `""` | Domain-specific extraction context, applied to all items |
| `max_chars_per_batch` | `int` | `6000` | Maximum characters of reasoning per extraction batch |
| `batch_fallback` | `str` | `"partial"` | `"partial"` or `"skip"` for batch extraction failures |

**Returns:** `list[VerificationReport]`, one per input item, in the same order.

See [Batch Verification](../guides/batch-verify.md) for details on batching behavior.

### register()

```python
def register(
    self,
    claim_type: str,
    verifier_fn: Callable[[TypedClaim, str, str], VerifiedClaim],
    extraction_hint: str,
    depends_on: list[tuple[str, str, str]] | None = None,
)
```

Register a custom claim type with its verifier function.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `claim_type` | `str` | (required) | Unique identifier. Must not collide with the 14 built-in types. |
| `verifier_fn` | `Callable` | (required) | Function `(claim, repo_path, language) -> VerifiedClaim` |
| `extraction_hint` | `str` | (required) | Description for the extraction prompt. Max 500 characters. |
| `depends_on` | `list[tuple] \| None` | `None` | List of `(prereq_type, source_param, target_param)` dependency rules |

**Raises:** `ValueError` if the claim type is already registered or the hint exceeds 500 characters.

### register_dependency()

```python
def register_dependency(
    self,
    claim_type: str,
    depends_on: str,
    source_param: str,
    target_param: str,
)
```

Register a dependency rule between claim types.

| Parameter | Type | Description |
|-----------|------|-------------|
| `claim_type` | `str` | The dependent claim type |
| `depends_on` | `str` | The prerequisite claim type |
| `source_param` | `str` | Parameter key in the dependent claim's parameters |
| `target_param` | `str` | Parameter key in the prerequisite claim's parameters |

**Raises:** `ValueError` if adding the rule would create a dependency cycle.

### as_tools()

```python
def as_tools(self) -> list[dict]
```

Return tool definitions including any custom-registered claim types. Produces four tool dicts (`extract_claims`, `verify_claim`, `verify_all`, `list_claim_types`) with schemas that include both built-in and custom types. Useful for LLM tool-use integrations.

**Returns:** `list[dict]` of tool definitions compatible with Anthropic/OpenAI tool-use format.

### default_tools() (classmethod)

```python
@classmethod
def default_tools(cls) -> list[dict]
```

Return tool definitions for all built-in claim types only (no custom types). Does not require an instance.

**Returns:** `list[dict]` of tool definitions.

---

## Data Types

### TypedClaim

```python
from code_claim_verifier import TypedClaim

@dataclass
class TypedClaim:
    claim_type: str                    # e.g., "FILE_EXISTS", "FUNCTION_CALLED"
    parameters: dict[str, Any]         # type-specific parameters
    source_sentence: str               # the original text this was extracted from
    id: str                            # auto-generated 8-char UUID prefix
    extraction_confidence: float       # 1.0 by default
```

### VerifiedClaim

```python
from code_claim_verifier import VerifiedClaim

@dataclass
class VerifiedClaim:
    claim: TypedClaim                  # the claim that was verified
    verdict: Verdict                   # "VERIFIED", "REFUTED", or "UNVERIFIABLE"
    method_confidence: float           # 0.0 to 1.0, how reliable the method is
    evidence: str                      # what the verifier found
    method: str                        # e.g., "os.path.isfile", "grep_function_def"
    error: str | None                  # internal error message, if any
    suspect_reason: str | None         # set by SUSPECT propagation
    synthesized: bool                  # True if this was a synthesized prerequisite
```

### VerificationReport

```python
from code_claim_verifier import VerificationReport

@dataclass
class VerificationReport:
    total_claims: int                  # number of real (non-synthesized) claims
    verifiable_claims: int             # claims with VERIFIED or REFUTED verdict
    verified: int                      # number of VERIFIED claims
    refuted: int                       # number of REFUTED claims
    unverifiable: int                  # number of UNVERIFIABLE claims
    errored: int                       # claims with error field set
    verification_rate: float           # weighted verified / weighted total
    hallucination_rate: float          # 1 - verification_rate
    calibrated_confidence: float       # same as verification_rate
    action: Action                     # "BOOST", "FLAG", "OVERRIDE", or "NO_CHANGE"
    reason: str                        # human-readable summary
    per_claim: list[VerifiedClaim]     # all claims (including synthesized)
```

**Action thresholds:**

| Action | Condition |
|--------|-----------|
| `BOOST` | `verification_rate >= 0.8` |
| `FLAG` | `0.5 <= verification_rate < 0.8` |
| `OVERRIDE` | `verification_rate < 0.5` |
| `NO_CHANGE` | No verifiable claims extracted |

The `to_dict()` method returns a plain dict suitable for JSON serialization. Evidence strings in per-claim output are truncated to 500 characters.

### Type aliases

```python
Verdict = Literal["VERIFIED", "REFUTED", "UNVERIFIABLE"]
Action = Literal["BOOST", "FLAG", "OVERRIDE", "NO_CHANGE"]
LLMFunction = Callable[[str, str], str]
VerifierFunction = Callable[[TypedClaim, str, str], VerifiedClaim]
```

---

## Module-level functions

These are available from `code_claim_verifier` directly:

```python
from code_claim_verifier import extract_claims, calibrate, CLAIM_TYPES
```

### extract_claims()

```python
def extract_claims(
    reasoning: str,
    evidence: dict[str, Any],
    llm_function: LLMFunction,
    domain_context: str = "",
    custom_hints: list[str] | None = None,
    valid_types: frozenset[str] = CLAIM_TYPES,
) -> list[TypedClaim]
```

Low-level extraction function. Called internally by `CodeClaimVerifier.verify()`, but available for direct use if you want to inspect extracted claims before verification.

### calibrate()

```python
def calibrate(verified_claims: list[VerifiedClaim]) -> VerificationReport
```

Compute the verification report from a list of verified claims. Excludes synthesized claims from metrics. Computes weighted verification rate using method confidence, with a 0.5 penalty for suspect claims.

### CLAIM_TYPES

```python
CLAIM_TYPES: frozenset[str]
```

The set of 14 built-in claim type identifiers.
