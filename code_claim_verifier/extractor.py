from __future__ import annotations

import json
import logging
from typing import Any, Callable

from code_claim_verifier.types import TypedClaim, CLAIM_TYPES

logger = logging.getLogger(__name__)

LLMFunction = Callable[[str, str], str]

_EXTRACTION_SYSTEM = """You are a claim extractor that identifies verifiable factual assertions about source code.

Given an LLM's reasoning about a codebase, extract every factual claim it makes that can be checked against the actual code. Each claim must be one of these types:

FILE CLAIMS: FILE_EXISTS, LINE_CONTENT, FILE_CLASSIFICATION, GENERATED_OR_VENDORED
FUNCTION CLAIMS: FUNCTION_EXISTS, FUNCTION_CALLED, HAS_CALLERS
DEPENDENCY CLAIMS: IMPORT_EXISTS, PACKAGE_VERSION, DEPENDENCY_TYPE, CVE_AFFECTS_VERSION
CODE CLAIMS: ABSENCE, MITIGATION_EXISTS, ENTRY_POINT

Output a JSON array of claims:
[{{"claim_type": "FUNCTION_CALLED", "parameters": {{"name": "torch.load", "expected": true}}, "source_sentence": "torch.load() is called at model.py:42"}}]

Rules:
- Extract ABSENCE claims when the LLM says something does NOT exist
- Do NOT extract opinions, recommendations, or quality judgments
- Do NOT extract claims about what SHOULD be done
- Each claim must be independently verifiable against the codebase
- For HAS_CALLERS/FUNCTION_CALLED, set expected=true if the LLM claims it IS called, false if NOT called

{domain_context}"""

_EXTRACTION_USER = """LLM reasoning:
{reasoning}

Structured evidence:
{evidence}

Extract all verifiable code claims as a JSON array:"""


def extract_claims(
    reasoning: str,
    evidence: dict[str, Any],
    llm_function: LLMFunction,
    domain_context: str = "",
    custom_hints: list[str] | None = None,
    valid_types: frozenset[str] = CLAIM_TYPES,
) -> list[TypedClaim]:
    """Extract typed claims from LLM reasoning using an LLM.

    Args:
        reasoning: The LLM's natural language reasoning about code.
        evidence: Structured evidence dict (tool output, triage results, etc.)
        llm_function: Callable(system_prompt, user_prompt) -> response string.
        domain_context: Optional domain-specific instructions appended to the
                        extraction prompt (e.g., "Focus on security claims"
                        or "This is a code review context").
        custom_hints: Optional list of custom claim type descriptions to include
                      in the extraction prompt.
        valid_types: Set of valid claim types. Defaults to CLAIM_TYPES.
    """
    if not reasoning and not evidence:
        return []

    system = _EXTRACTION_SYSTEM.format(domain_context=domain_context)
    if custom_hints:
        system += "\n\nCUSTOM CLAIM TYPES:\n" + "\n".join(f"- {h}" for h in custom_hints)
    evidence_str = json.dumps(evidence, indent=2, default=str)[:3000]
    user_prompt = _EXTRACTION_USER.format(
        reasoning=reasoning[:4000],
        evidence=evidence_str,
    )

    try:
        raw = llm_function(system, user_prompt)
    except Exception as e:
        logger.warning("Claim extraction LLM call failed: %s", e)
        return []

    return _parse_extraction_output(raw, valid_types=valid_types)


def _parse_extraction_output(raw: str, valid_types: frozenset[str] = CLAIM_TYPES) -> list[TypedClaim]:
    """Parse LLM output into TypedClaim objects."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1:
        return []

    try:
        items = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []

    claims = []
    for item in items:
        if not isinstance(item, dict):
            continue
        claim_type = item.get("claim_type", "")
        if claim_type not in valid_types:
            continue
        claims.append(TypedClaim(
            claim_type=claim_type,
            parameters=item.get("parameters", {}),
            source_sentence=item.get("source_sentence", "")[:500],
        ))

    return claims


_BATCH_EXTRACTION_SYSTEM = _EXTRACTION_SYSTEM.replace(
    "{domain_context}",
    """
Multiple findings are provided, each delimited by <<<FINDING_N:filename>>>.
Include "finding_index": N in each extracted claim to indicate which finding it belongs to.

{domain_context}"""
)


def _build_batch_prompt(items: list[dict]) -> str:
    parts = []
    for i, item in enumerate(items):
        finding_file = item.get("finding_file", "unknown")
        reasoning = item.get("reasoning", "")[:4000]
        evidence_str = json.dumps(item.get("evidence", {}), indent=2, default=str)[:3000]
        parts.append(f"<<<FINDING_{i}:{finding_file}>>>\nReasoning: {reasoning}\nEvidence: {evidence_str}")
    return "\n\n".join(parts)


def extract_claims_batch(
    items: list[dict],
    llm_function: LLMFunction,
    domain_context: str = "",
    custom_hints: list[str] | None = None,
    valid_types: frozenset[str] = CLAIM_TYPES,
    fallback: str = "partial",
) -> dict[int, list[TypedClaim]]:
    if not items:
        return {}

    system = _BATCH_EXTRACTION_SYSTEM.format(domain_context=domain_context)
    if custom_hints:
        system += "\n\nCUSTOM CLAIM TYPES:\n" + "\n".join(f"- {h}" for h in custom_hints)

    user_prompt = _build_batch_prompt(items)

    try:
        raw = llm_function(system, user_prompt)
    except Exception as e:
        logger.warning("Batch extraction LLM call failed: %s", e)
        return {i: [] for i in range(len(items))}

    return _parse_batch_output(raw, len(items), valid_types, fallback)


def _parse_batch_output(
    raw: str, num_items: int,
    valid_types: frozenset[str],
    fallback: str,
) -> dict[int, list[TypedClaim]]:
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1:
        return {i: [] for i in range(num_items)}

    try:
        items_parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {i: [] for i in range(num_items)}

    result: dict[int, list[TypedClaim]] = {i: [] for i in range(num_items)}
    assigned = 0
    total = 0

    for item in items_parsed:
        if not isinstance(item, dict):
            continue
        claim_type = item.get("claim_type", "")
        if claim_type not in valid_types:
            continue
        total += 1

        finding_index = item.get("finding_index")
        if finding_index is not None:
            try:
                finding_index = int(finding_index)
            except (ValueError, TypeError):
                finding_index = None

        if finding_index is not None and 0 <= finding_index < num_items:
            claim = TypedClaim(
                claim_type=claim_type,
                parameters=item.get("parameters", {}),
                source_sentence=item.get("source_sentence", "")[:500],
            )
            result[finding_index].append(claim)
            assigned += 1
        elif fallback == "skip":
            continue

    if total > 0 and assigned < total * 0.5 and fallback == "partial":
        return {i: [] for i in range(num_items)}

    return result
