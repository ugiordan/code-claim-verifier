# Claude Code Skill Integration

CCV can be integrated as a Claude Code skill (slash command) so that Claude automatically verifies factual claims whenever it reasons about your codebase. This catches hallucinations before they reach code reviews, security triages, or architecture assessments.

## How it works

1. You create a skill file (`.md`) in your project's `.claude/commands/` directory
2. When invoked via `/verify` (or whatever you name it), Claude runs CCV against the repo
3. CCV extracts typed claims from the LLM reasoning and verifies each one deterministically
4. Claude reports which claims are verified, refuted, or unverifiable

No LLM calls are used for verification. The only LLM call is for claim extraction.

## Option A: Project-level skill (single repo)

Create `.claude/commands/verify-claims.md` in your project:

```markdown
---
description: Verify factual claims in LLM reasoning about this codebase
allowed-tools: Bash(ccv *), Bash(pip install *)
---

# Verify Claims

When the user provides LLM reasoning (a code review comment, security triage,
architecture assessment, or any text that makes assertions about code), verify
it against the actual codebase using CCV.

## Steps

1. Make sure CCV is installed:
   ```bash
   pip install code-claim-verifier
   ```

2. Run CCV on the provided reasoning:
   ```bash
   ccv verify --repo . --reasoning "<the reasoning text>"
   ```

3. Report the results clearly:
   - List each claim with its verdict (VERIFIED, REFUTED, UNVERIFIABLE)
   - Highlight any REFUTED claims as potential hallucinations
   - Show the evidence for each verdict
   - Report the overall verification rate and action (BOOST/FLAG/OVERRIDE)

## Notes

- If the user doesn't provide reasoning text, ask for it
- For security contexts, add `--domain-context "security triage"`
- For code review contexts, add `--domain-context "code review"`
- The `--finding-file` flag improves accuracy by enabling language-specific patterns
```

Then invoke it with `/verify-claims` followed by the reasoning text.

## Option B: Inline verification in CLAUDE.md

Add verification instructions directly to your project's `CLAUDE.md` so Claude
automatically verifies its own reasoning:

```markdown
## Self-verification

Before presenting any analysis that makes factual claims about this codebase
(function existence, file locations, import usage, call chains), verify your
claims using CCV:

    ccv verify --repo . --reasoning "<your analysis>"

If the verification rate is below 80%, revise your analysis before presenting it.
Do not present REFUTED claims as facts.
```

This makes verification automatic for every interaction, not just when `/verify` is invoked.

## Option C: Plugin skill (shared across projects)

For teams that want CCV verification available in all projects, create a
Claude Code plugin with a `commands/` directory.

### Plugin structure

```
ccv-skill/
  plugin.json
  commands/
    verify.md
    verify-review.md
  hooks/
    post-tool.sh       # optional: auto-verify after code review tools
```

### plugin.json

```json
{
  "name": "ccv-skill",
  "version": "1.0.0",
  "description": "Verify LLM claims against source code using CodeClaimVerifier",
  "skills": ["commands/verify.md", "commands/verify-review.md"]
}
```

### commands/verify.md

```markdown
---
description: Verify factual claims in text against the current codebase
allowed-tools: Bash(ccv *), Bash(pip install code-claim-verifier)
---

Verify the claims in the provided reasoning text against the current repository.

1. Ensure CCV is installed: `pip install code-claim-verifier`
2. Run: `ccv verify --repo . --reasoning "$REASONING"`
3. Parse the JSON output and present results as a table:
   - Claim type, parameters, verdict, evidence
4. Summarize: total claims, verification rate, recommended action

If no reasoning text is provided, ask the user to paste the text they want verified.
```

### commands/verify-review.md

```markdown
---
description: Verify claims in a GitHub PR review comment
allowed-tools: Bash(ccv *), Bash(gh pr *), Bash(pip install code-claim-verifier)
---

Fetch the latest review comments from the current PR and verify each one.

1. Get the current PR number: `gh pr view --json number -q .number`
2. Fetch review comments: `gh pr view --json reviews -q '.reviews[].body'`
3. For each review comment with substantive code claims:
   ```bash
   ccv verify --repo . --reasoning "$COMMENT" --domain-context "code review"
   ```
4. Present a summary of which review comments contain verified vs refuted claims
5. Flag any reviewer comments that contain hallucinations
```

## Option D: Hook-based automatic verification

Use Claude Code hooks to automatically verify claims after certain tool calls.
Create `.claude/hooks.json`:

```json
{
  "hooks": {
    "post-tool": [
      {
        "matcher": "Bash",
        "command": "python3 -c \"import sys; print('CCV: consider running /verify-claims on the output')\" >&2",
        "description": "Remind to verify claims after code analysis"
      }
    ]
  }
}
```

## Using CCV as an MCP tool

CCV also provides tool schemas compatible with LLM tool-use. You can expose
CCV as tools that Claude can call directly during conversation:

```python
from code_claim_verifier import CodeClaimVerifier

# Get tool definitions for all 17 built-in claim types
tools = CodeClaimVerifier.default_tools()

# Or get tools including custom claim types
verifier = CodeClaimVerifier(llm_function=my_llm, repo_path="/repo")
tools = verifier.as_tools()
```

Each tool corresponds to a claim type (FILE_EXISTS, FUNCTION_EXISTS, etc.)
and can be called with the appropriate parameters. This is useful for building
custom MCP servers or agent loops that use CCV for verification.

## CLI reference for skills

The key CLI commands for skill integration:

```bash
# Verify a single piece of reasoning
ccv verify --repo /path/to/repo --reasoning "text..."

# Verify with domain context
ccv verify --repo . --reasoning "text..." --domain-context "security triage"

# Verify with language hint
ccv verify --repo . --reasoning "text..." --finding-file "src/main.go"

# List all available claim types
ccv list-types

# Batch verify multiple items from a JSON file
ccv verify-batch --repo . --input findings.json
```

### Output format

CCV outputs JSON with the verification report:

```json
{
  "total_claims": 8,
  "verified": 6,
  "refuted": 2,
  "unverifiable": 0,
  "verification_rate": 0.75,
  "action": "FLAG",
  "claims": [
    {
      "claim_type": "FUNCTION_EXISTS",
      "parameters": {"name": "parseConfig", "file": "src/config.go"},
      "verdict": "VERIFIED",
      "evidence": "grep: parseConfig at src/config.go:42",
      "confidence": 0.85
    }
  ]
}
```

## Example: security triage skill

A more complete skill for security triage contexts:

```markdown
---
description: Verify security findings against the codebase
allowed-tools: Bash(ccv *), Bash(pip install code-claim-verifier), Agent
---

# Verify Security Findings

Verify LLM-generated security findings against the actual source code.

## Steps

1. Install CCV if needed: `pip install code-claim-verifier`

2. For each security finding provided:
   a. Extract the reasoning text
   b. Identify the relevant file (for language detection)
   c. Run verification:
      ```bash
      ccv verify --repo . \
        --reasoning "$FINDING_TEXT" \
        --finding-file "$FILE" \
        --domain-context "security vulnerability triage"
      ```

3. Classify each finding based on CCV results:
   - BOOST (verification_rate >= 80%): finding is well-supported
   - FLAG (50-80%): finding has some unverified claims, needs review
   - OVERRIDE (< 50%): finding contains significant hallucinations

4. Present results as a table with finding ID, claim count, verification rate,
   and recommended action.

5. For any REFUTED claims, explain what CCV found vs what was claimed.
```
