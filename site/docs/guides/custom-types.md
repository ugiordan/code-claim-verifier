# Custom Claim Types

The 14 built-in types cover common assertions about files, functions, dependencies, and code patterns. When you need domain-specific verification, you can register custom claim types.

## The register() API

```python
verifier.register(
    claim_type="MY_CUSTOM_TYPE",
    verifier_fn=my_verifier_function,
    extraction_hint="MY_CUSTOM_TYPE: description of what this claim verifies and when to extract it",
    depends_on=[("PREREQUISITE_TYPE", "source_param", "target_param")],  # optional
)
```

**Parameters:**

- `claim_type` (str): unique identifier for the claim type. Must not collide with any built-in type.
- `verifier_fn`: a function with the signature `(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim`.
- `extraction_hint` (str): description appended to the extraction prompt so the LLM knows to extract this claim type. Max 500 characters.
- `depends_on` (optional): list of `(prerequisite_type, source_param, target_param)` tuples that define dependency rules for claim chaining.

## Writing a verifier function

A verifier receives a `TypedClaim`, the repo path, and the detected language. It must return a `VerifiedClaim`.

```python
from code_claim_verifier.types import TypedClaim, VerifiedClaim

def verify_has_decorator(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    """Verify that a function has a specific decorator."""
    function_name = claim.parameters.get("function", "")
    decorator = claim.parameters.get("decorator", "")

    if not function_name or not decorator:
        return VerifiedClaim(
            claim=claim,
            verdict="UNVERIFIABLE",
            method_confidence=0.0,
            evidence="Missing required parameters",
            method="error",
            error="missing_params",
        )

    from code_claim_verifier.grep import grep

    # Search for the decorator immediately above the function definition
    pattern = f"@{decorator}"
    matches = grep(pattern, repo_path, fixed=True)

    # Check if any match is near a definition of the target function
    from code_claim_verifier.language import get_function_pattern
    func_pattern = get_function_pattern(function_name, language)
    func_matches = grep(func_pattern, repo_path)

    if not func_matches:
        return VerifiedClaim(
            claim=claim,
            verdict="REFUTED",
            method_confidence=0.80,
            evidence=f"Function {function_name} not found",
            method="grep_decorator",
        )

    # Simple heuristic: check if decorator and function are in the same file
    decorator_files = {m.split(":")[0] for m in matches}
    function_files = {m.split(":")[0] for m in func_matches}
    overlap = decorator_files & function_files

    found = len(overlap) > 0
    return VerifiedClaim(
        claim=claim,
        verdict="VERIFIED" if found else "REFUTED",
        method_confidence=0.75,
        evidence=f"{'Found' if found else 'No'} @{decorator} near {function_name} "
                 f"in {overlap if found else 'any file'}",
        method="grep_decorator",
    )
```

Key rules for verifier functions:

- Always return a `VerifiedClaim`, never raise exceptions (the engine catches them, but it's better to handle errors yourself)
- Set `method_confidence` to reflect how reliable the verification method is (0.0 to 1.0)
- Use the `method` field to identify what tool was used (for debugging and eval)
- Use `error` for internal failures, not for REFUTED claims
- Use `code_claim_verifier.grep.grep()` instead of calling subprocess directly, so you benefit from the grep cache

## Registering the custom type

```python
from code_claim_verifier import CodeClaimVerifier

verifier = CodeClaimVerifier(llm_function=my_llm, repo_path="/path/to/repo")

verifier.register(
    claim_type="HAS_DECORATOR",
    verifier_fn=verify_has_decorator,
    extraction_hint=(
        "HAS_DECORATOR: Assert that a function has a specific decorator. "
        "Parameters: function (string), decorator (string). "
        "Example: @login_required on the delete_user function."
    ),
)
```

Now when you call `verifier.verify()`, the extraction prompt will include your custom type, and the LLM can produce claims like:

```json
{
    "claim_type": "HAS_DECORATOR",
    "parameters": {"function": "delete_user", "decorator": "login_required"},
    "source_sentence": "The delete_user endpoint requires authentication via @login_required"
}
```

## Adding dependencies

If your custom type depends on a prerequisite (e.g., the function must exist before checking its decorator), register a dependency:

```python
verifier.register(
    claim_type="HAS_DECORATOR",
    verifier_fn=verify_has_decorator,
    extraction_hint="HAS_DECORATOR: ...",
    depends_on=[("FUNCTION_EXISTS", "function", "name")],
)
```

This means: before verifying a `HAS_DECORATOR` claim, ensure there's a `FUNCTION_EXISTS` claim for the same function. The mapping `("FUNCTION_EXISTS", "function", "name")` says: take the `function` parameter from the `HAS_DECORATOR` claim and use it as the `name` parameter in a synthesized `FUNCTION_EXISTS` claim.

If no matching `FUNCTION_EXISTS` claim was extracted, the engine synthesizes one automatically. If that synthesized prerequisite is REFUTED (function doesn't exist), the dependent claim gets a `suspect_reason` flag.

You can also add dependencies after registration:

```python
verifier.register_dependency(
    claim_type="HAS_DECORATOR",
    depends_on="FILE_EXISTS",
    source_param="file",
    target_param="path",
)
```

The engine prevents cycles. If adding a dependency would create a circular chain, `register_dependency()` raises `ValueError`.

## Tool-use integration

Custom types are automatically included when you call `verifier.as_tools()`:

```python
tools = verifier.as_tools()
# Returns tool definitions that include HAS_DECORATOR
# alongside the 14 built-in types
```

This is useful when integrating CCV into an LLM tool-use loop where the LLM can invoke verification tools directly.
