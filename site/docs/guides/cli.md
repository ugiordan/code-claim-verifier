# CLI Usage

CCV installs a `ccv` command-line tool with four subcommands: `verify`, `verify-batch`, `list-types`, and `eval`.

## ccv verify

Verify claims in a single piece of LLM reasoning against a repository.

```bash
ccv verify --repo /path/to/repo --reasoning "The file src/config.py calls yaml.load() on line 42"
```

Or pipe reasoning from stdin:

```bash
echo "The function parseConfig in config.go uses unsafe deserialization" | ccv verify --repo /path/to/repo
```

### Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--repo` | yes | | Path to the repository to verify against |
| `--reasoning` | no | stdin | LLM reasoning text |
| `--finding-file` | no | `""` | File path for language detection (e.g., `src/config.py`) |
| `--domain-context` | no | `""` | Domain-specific extraction context |
| `--llm-provider` | no | `anthropic` | LLM provider: `anthropic` or `openai` |
| `--model` | no | provider default | Model name override |

### Output

JSON object with the verification report:

```json
{
  "total_claims": 3,
  "verifiable_claims": 3,
  "verified": 2,
  "refuted": 1,
  "unverifiable": 0,
  "errored": 0,
  "verification_rate": 0.67,
  "hallucination_rate": 0.33,
  "calibrated_confidence": 0.67,
  "action": "FLAG",
  "reason": "2/3 claims verified",
  "claims": [
    {
      "type": "FILE_EXISTS",
      "params": {"path": "src/config.py"},
      "source": "The file src/config.py calls yaml.load()",
      "verdict": "VERIFIED",
      "confidence": 0.99,
      "evidence": "exists: src/config.py",
      "method": "os.path.isfile",
      "suspect_reason": null,
      "synthesized": false
    }
  ]
}
```

## ccv verify-batch

Verify claims across multiple items in batch mode.

```bash
ccv verify-batch --repo /path/to/repo --input findings.json
```

Or pipe JSON from stdin:

```bash
cat findings.json | ccv verify-batch --repo /path/to/repo
```

The input must be a JSON array of objects with keys: `reasoning`, `evidence` (optional), `finding_file` (optional).

```json
[
  {
    "reasoning": "The file uses eval() to process user input",
    "evidence": {"rule": "dangerous-eval"},
    "finding_file": "src/handler.py"
  },
  {
    "reasoning": "The dependency lodash@4.17.15 has prototype pollution",
    "finding_file": "package.json"
  }
]
```

### Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--repo` | yes | | Path to the repository |
| `--input` | no | stdin | Path to JSON file with items |
| `--domain-context` | no | `""` | Domain-specific extraction context |
| `--max-items` | no | `10000` | Maximum number of items to process |
| `--llm-provider` | no | `anthropic` | LLM provider |
| `--model` | no | provider default | Model name override |

### Output

JSON array of verification reports (one per input item):

```json
[
  {
    "total_claims": 2,
    "verified": 1,
    "refuted": 1,
    "action": "FLAG",
    "claims": [...]
  },
  {
    "total_claims": 1,
    "verified": 0,
    "refuted": 0,
    "unverifiable": 1,
    "action": "NO_CHANGE",
    "claims": [...]
  }
]
```

## ccv list-types

Output JSON schemas for all 14 built-in claim types. No API key required.

```bash
ccv list-types
```

Output (truncated):

```json
{
  "FILE_EXISTS": {
    "description": "Assert that a file exists at a given path",
    "parameters": {
      "path": {"type": "string", "description": "Relative file path"}
    },
    "required": ["path"]
  },
  "LINE_CONTENT": {
    "description": "Assert that a file contains specific content at or near a line",
    "parameters": {
      "path": {"type": "string", "description": "Relative file path"},
      "line": {"type": "integer", "description": "Expected line number (approximate)"},
      "content": {"type": "string", "description": "Expected content substring"}
    },
    "required": ["path", "content"]
  }
}
```

Useful for understanding what parameters each claim type expects, or for generating tooling that feeds into CCV.

## ccv eval

Run the evaluation framework against fixture repos.

```bash
ccv eval --dataset tests/eval/dataset.jsonl --fixtures tests/eval/fixtures/
```

### Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--dataset` | yes | | Path to JSONL dataset file |
| `--fixtures` | yes | | Path to directory containing fixture repos |
| `--output` | no | stdout | Optional path to write JSON report file |
| `--no-mock-extraction` | no | (mock enabled) | Disable mock extraction and use real LLM extraction |

By default, `eval` uses mock extraction: ground truth claims from the dataset are fed directly to the verifiers, bypassing the LLM extraction step. This isolates verification accuracy from extraction quality.

### Output

JSON report with three evaluation stages:

```json
{
  "extraction": {
    "precision": 1.0,
    "recall": 1.0,
    "f1": 1.0,
    "matched": 15,
    "gt_total": 15,
    "pred_total": 15
  },
  "verification": {
    "accuracy": 0.9333,
    "false_refuted_rate": 0.0667,
    "false_verified_rate": 0.0,
    "total": 15,
    "confusion_matrix": {...},
    "per_type": {...}
  },
  "calibration": {
    "per_type_accuracy": {...},
    "ece": 0.05,
    "confidence_adjustments": {...}
  },
  "summary": {
    "extraction_f1": 1.0,
    "verification_accuracy": 0.9333,
    "calibration_ece": 0.05,
    "overall_score": 0.9611
  }
}
```

## LLM provider configuration

Both `verify` and `verify-batch` require an LLM provider for claim extraction.

### Anthropic (default)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
ccv verify --repo . --reasoning "..."
```

### OpenAI

```bash
export OPENAI_API_KEY=sk-...
ccv verify --repo . --reasoning "..." --llm-provider openai
```

### Model override

To use a specific model instead of the provider's default:

```bash
ccv verify --repo . --reasoning "..." --model claude-sonnet-4-20250514
ccv verify --repo . --reasoning "..." --llm-provider openai --model gpt-4o
```
