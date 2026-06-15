from __future__ import annotations

from code_claim_verifier.cli import CLAIM_SCHEMAS


def _generate_tools(claim_types: dict[str, dict]) -> list[dict]:
    """Generate tool definitions for LLM tool-use integration.

    Returns four tool dicts: extract_claims, verify_claim, verify_all,
    and list_claim_types. The claim_types parameter determines which
    types appear in schema descriptions and enums.

    Args:
        claim_types: Mapping of claim type name to its parameter schema.

    Returns:
        List of tool definitions compatible with Anthropic/OpenAI tool-use format.
    """
    type_names = sorted(claim_types.keys())
    type_descriptions = "\n".join(
        f"- {name}: {schema['description']}"
        for name, schema in sorted(claim_types.items())
    )

    return [
        {
            "name": "extract_claims",
            "description": (
                "Extract verifiable code claims from LLM reasoning text. "
                "Returns a list of typed claims that can be checked against "
                "the actual codebase. Each claim has a type, parameters, and "
                "the source sentence it was extracted from."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "The LLM's natural language reasoning about code",
                    },
                    "evidence": {
                        "type": "object",
                        "description": "Optional structured evidence (tool output, triage results)",
                    },
                    "domain_context": {
                        "type": "string",
                        "description": (
                            "Optional domain context for extraction "
                            "(e.g., 'security triage', 'code review')"
                        ),
                    },
                },
                "required": ["reasoning"],
            },
        },
        {
            "name": "verify_claim",
            "description": (
                "Verify a single typed claim against the codebase. "
                "Returns the verdict (VERIFIED, REFUTED, UNVERIFIABLE), "
                "confidence, evidence, and method used."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "claim_type": {
                        "type": "string",
                        "enum": type_names,
                        "description": "The type of claim to verify",
                    },
                    "parameters": {
                        "type": "object",
                        "description": "Claim parameters (type-specific)",
                    },
                    "source_sentence": {
                        "type": "string",
                        "description": "The original sentence this claim was extracted from",
                    },
                },
                "required": ["claim_type", "parameters"],
            },
        },
        {
            "name": "verify_all",
            "description": (
                "Verify all claims in LLM reasoning text end-to-end. "
                "Extracts claims, verifies each one, and returns a "
                "calibrated report with confidence, hallucination rate, "
                "and recommended action."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "The LLM's natural language reasoning about code",
                    },
                    "evidence": {
                        "type": "object",
                        "description": "Optional structured evidence",
                    },
                    "finding_file": {
                        "type": "string",
                        "description": "File path for per-finding language detection",
                    },
                    "domain_context": {
                        "type": "string",
                        "description": "Optional domain context for extraction",
                    },
                },
                "required": ["reasoning"],
            },
        },
        {
            "name": "list_claim_types",
            "description": (
                "List all supported claim types with their parameter schemas.\n\n"
                "Available types:\n" + type_descriptions
            ),
            "input_schema": {
                "type": "object",
                "properties": {},
            },
        },
    ]


def default_tools() -> list[dict]:
    """Return tool definitions for all built-in claim types."""
    return _generate_tools(CLAIM_SCHEMAS)


def instance_tools(extra_types: dict[str, str] | None = None) -> list[dict]:
    """Return tool definitions including custom claim types.

    Args:
        extra_types: Mapping of custom type name to its extraction hint.
            These are converted into simple schemas and merged with builtins.
    """
    schemas = dict(CLAIM_SCHEMAS)
    if extra_types:
        for name, hint in extra_types.items():
            schemas[name] = {
                "description": hint,
                "parameters": {"custom": {"type": "object", "description": "Custom parameters"}},
                "required": [],
            }
    return _generate_tools(schemas)
