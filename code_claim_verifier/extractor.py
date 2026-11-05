from __future__ import annotations

import json
import logging
from typing import Any, Callable

from code_claim_verifier.types import TypedClaim, CLAIM_TYPES

logger = logging.getLogger(__name__)

LLMFunction = Callable[[str, str], str]
EXTRACTION_VERSION = "typed-claims-v1"

_EXTRACTION_SYSTEM = """You are a claim extractor that identifies verifiable factual assertions about source code.

Given an LLM's reasoning about a codebase, extract every factual claim it makes that can be checked against the actual code. Each claim must be one of these types:

FILE CLAIMS: FILE_EXISTS, LINE_CONTENT, FILE_CLASSIFICATION, GENERATED_OR_VENDORED
FUNCTION CLAIMS: FUNCTION_EXISTS, FUNCTION_CALLED, HAS_CALLERS, VULNERABLE_SYMBOL_CALLED
DEPENDENCY CLAIMS: IMPORT_EXISTS, PACKAGE_VERSION, PACKAGE_ABSENT, DEPENDENCY_TYPE, CVE_AFFECTS_VERSION, VERSION_IN_RANGE, UPGRADE_FIXES, REDHAT_VEX_STATUS
CODE CLAIMS: ABSENCE, MITIGATION_EXISTS, ENTRY_POINT
AUTH/CONFIG CLAIMS: CALL_CHAIN, DEFAULT_VALUE, CONFIG_FLAG

Output a JSON array of claims:
[{{"claim_type": "FUNCTION_CALLED", "parameters": {{"name": "torch.load", "expected": true}}, "source_sentence": "torch.load() is called at model.py:42"}}]

Examples of AUTH/CONFIG claims:
[{{"claim_type": "CALL_CHAIN", "parameters": {{"chain": ["getAuthenticatedSession", "k8sTokenSession", "validateToken"]}}, "source_sentence": "getAuthenticatedSession calls k8sTokenSession which calls validateToken"}}]
[{{"claim_type": "DEFAULT_VALUE", "parameters": {{"variable": "audiences", "file": "tokenreview.go", "default_behavior": "allow"}}, "source_sentence": "empty audiences defaults to accepting any token"}}]
[{{"claim_type": "CONFIG_FLAG", "parameters": {{"flag": "enable-k8s-token-validation", "value": "true"}}, "source_sentence": "k8s token validation is enabled by default"}}]

Rules:
- Extract ABSENCE claims when the LLM says something does NOT exist
- Extract PACKAGE_ABSENT when the LLM says a package is NOT a dependency of the project ("we don't use X", "X was removed")
- Extract VERSION_IN_RANGE when the LLM claims a version is inside or outside an advisory's affected range; include "version", "range", and "ecosystem"
- Extract UPGRADE_FIXES when the LLM claims upgrading to a version fixes a CVE; include "upgrade" and "fixed_in"
- Extract VULNERABLE_SYMBOL_CALLED when the LLM claims a specific vulnerable function in a package is (or is not) called from shipped code; include "function" and "package"
- Extract REDHAT_VEX_STATUS when the LLM cites a Red Hat Product Security assessment; include "cve_id", "expected_status", "product_prefix", and "component"
- Extract CALL_CHAIN when the LLM traces a multi-file function call path (authentication chains, request handling pipelines)
- Extract DEFAULT_VALUE when the LLM claims a config/variable defaults to permissive or restrictive behavior when empty/nil
- Extract CONFIG_FLAG when the LLM claims a specific flag is set to a specific value
- For MITIGATION_EXISTS, include a concrete source-code string in "pattern" and
  the containing relative "file". Put a prose explanation in "mitigation" only
  as optional context; prose alone is not executable evidence.
- Do NOT extract opinions, recommendations, or quality judgments
- Do NOT extract claims about what SHOULD be done
- Each claim must be independently verifiable against the codebase
- For HAS_CALLERS/FUNCTION_CALLED, set expected=true if the LLM claims it IS called, false if NOT called

{domain_context}"""

_CLAIMIFY_SYSTEM = """You are a claim extractor that identifies verifiable factual assertions about source code.

Given an LLM's reasoning about a codebase, extract every factual assertion that could be checked against the actual code. For each assertion, output:
- "assertion": the factual claim as a clear statement
- "source_sentence": the original sentence it came from

Do NOT extract opinions, recommendations, or quality judgments.
Only extract claims that are objectively verifiable by reading the code.

Output a JSON array:
[{{"assertion": "The file main.py exists in the repository", "source_sentence": "The vulnerability is in main.py..."}}]

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

    system, user_prompt = build_extraction_prompts(reasoning, evidence, domain_context)
    if custom_hints:
        system += "\n\nCUSTOM CLAIM TYPES:\n" + "\n".join(f"- {h}" for h in custom_hints)

    try:
        raw = llm_function(system, user_prompt)
    except Exception as e:
        logger.warning("Claim extraction LLM call failed: %s", e)
        return []

    return _parse_extraction_output(raw, valid_types=valid_types)


def build_extraction_prompts(
    reasoning: str, evidence: dict[str, Any], domain_context: str = "",
) -> tuple[str, str]:
    """Build the exact default extraction prompts for provenance hashing."""
    system = _EXTRACTION_SYSTEM.format(domain_context=domain_context)
    evidence_str = json.dumps(evidence, indent=2, default=str)[:3000]
    user_prompt = _EXTRACTION_USER.format(
        reasoning=reasoning[:8000],
        evidence=evidence_str,
    )
    return system, user_prompt


def extract_claims_claimify(
    reasoning: str,
    evidence: dict[str, Any],
    llm_function: LLMFunction,
    domain_context: str = "",
) -> list[TypedClaim]:
    """Extract claims using Claimify-style generic extraction (no typed taxonomy).

    Returns TypedClaim objects with claim_type="GENERIC" and the assertion
    text in parameters["assertion"]. These cannot be verified by CCV's
    typed verifiers, which is the point of the ablation.
    """
    if not reasoning and not evidence:
        return []

    system = _CLAIMIFY_SYSTEM.format(domain_context=domain_context)
    evidence_str = json.dumps(evidence, indent=2, default=str)[:3000]
    user_prompt = _EXTRACTION_USER.format(
        reasoning=reasoning[:4000],
        evidence=evidence_str,
    )

    try:
        raw = llm_function(system, user_prompt)
    except Exception as e:
        logger.warning("Claimify extraction failed: %s", e)
        return []

    return _parse_claimify_output(raw)


def _parse_claimify_output(raw: str) -> list[TypedClaim]:
    """Parse Claimify-style output into TypedClaim objects with type GENERIC."""
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
        assertion = item.get("assertion", "")
        source = item.get("source_sentence", "")
        if assertion:
            claims.append(TypedClaim(
                claim_type="GENERIC",
                parameters={"assertion": assertion},
                source_sentence=source[:500],
            ))
    return claims


def _parse_extraction_output(raw: str, valid_types: frozenset[str] = CLAIM_TYPES) -> list[TypedClaim]:
    """Parse LLM output into TypedClaim objects.

    Handles truncated JSON from token-limited responses by finding complete
    JSON objects within a potentially incomplete array.
    """
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    start = text.find("[")
    if start == -1:
        return []

    json_str = text[start:]
    items = None

    try:
        items = json.loads(json_str)
    except json.JSONDecodeError:
        # Try closing the array (truncated response)
        for repair in ("]", "}]", "\"}]", "\": \"\"}]"):
            try:
                items = json.loads(json_str + repair)
                break
            except json.JSONDecodeError:
                continue

    if items is None:
        # Last resort: extract complete JSON objects individually
        items = []
        depth = 0
        obj_start = -1
        for i, ch in enumerate(json_str):
            if ch == "{" and depth == 0:
                obj_start = i
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and obj_start >= 0:
                    try:
                        obj = json.loads(json_str[obj_start:i + 1])
                        items.append(obj)
                    except json.JSONDecodeError:
                        pass
                    obj_start = -1

    claims = []
    for item in items:
        if not isinstance(item, dict):
            continue
        claim_type = item.get("claim_type", "")
        if claim_type not in valid_types:
            continue
        parameters = item.get("parameters", {})
        if not isinstance(parameters, dict):
            continue
        claims.append(TypedClaim(
            claim_type=claim_type,
            parameters=parameters,
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
        parameters = item.get("parameters", {})
        if not isinstance(parameters, dict):
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
                parameters=parameters,
                source_sentence=item.get("source_sentence", "")[:500],
            )
            result[finding_index].append(claim)
            assigned += 1
        elif fallback == "skip":
            continue

    if total > 0 and assigned < total * 0.5 and fallback == "partial":
        return {i: [] for i in range(num_items)}

    return result
