from __future__ import annotations

import json

CONDITION_A = """You are a security analyst triaging a vulnerability in a {language} project.

VULNERABILITY DESCRIPTION:
{description}

The vulnerable source code is available for analysis.

Analyze this vulnerability:
1. Identify which files contain the vulnerable code
2. Identify the vulnerable function(s) and whether they are defined in the codebase
3. Determine if the vulnerable functions are called elsewhere, and by what callers
4. Check what imports or dependencies are involved
5. Look for any existing mitigations or input sanitization
6. Assess whether the vulnerable code is reachable via entry points

Provide detailed reasoning with specific file paths, function names, and line numbers."""

CONDITION_B = """You are a security analyst reviewing a {language} project called {project}.

The source code is available for analysis. Perform a security review:
1. Identify the main source files and their purpose
2. Identify key functions and their callers
3. Look for potential security issues (buffer overflows, injection, etc.)
4. Check for missing input validation or sanitization

Provide detailed reasoning with specific file paths, function names, and line numbers."""

JUDGE_PROMPT = """You are verifying a factual claim about source code.

CLAIM: {claim_type}
PARAMETERS: {parameters}

{context}

Based ONLY on the information provided above, is this claim:
- VERIFIED: the claim is factually correct
- REFUTED: the claim is factually incorrect
- UNVERIFIABLE: cannot determine from available information

Respond with exactly one of: VERIFIED, REFUTED, UNVERIFIABLE
Then provide a one-sentence justification."""


def build_reasoning_prompt(condition: str, language: str, project: str,
                            description: str = "") -> str:
    if condition == "informed":
        return CONDITION_A.format(
            language=language,
            description=description or "No description available.",
        )
    elif condition == "blind":
        return CONDITION_B.format(language=language, project=project)
    else:
        raise ValueError(f"Unknown condition: {condition}")


def build_judge_prompt(claim_type: str, parameters: dict, context: str) -> str:
    return JUDGE_PROMPT.format(
        claim_type=claim_type,
        parameters=json.dumps(parameters),
        context=context,
    )
