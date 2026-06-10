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
) -> list[TypedClaim]:
    """Extract typed claims from LLM reasoning using an LLM.

    Args:
        reasoning: The LLM's natural language reasoning about code.
        evidence: Structured evidence dict (tool output, triage results, etc.)
        llm_function: Callable(system_prompt, user_prompt) -> response string.
        domain_context: Optional domain-specific instructions appended to the
                        extraction prompt (e.g., "Focus on security claims"
                        or "This is a code review context").
    """
    if not reasoning and not evidence:
        return []

    system = _EXTRACTION_SYSTEM.format(domain_context=domain_context)
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

    return _parse_extraction_output(raw)


def _parse_extraction_output(raw: str) -> list[TypedClaim]:
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
        if claim_type not in CLAIM_TYPES:
            continue
        claims.append(TypedClaim(
            claim_type=claim_type,
            parameters=item.get("parameters", {}),
            source_sentence=item.get("source_sentence", "")[:500],
        ))

    return claims
