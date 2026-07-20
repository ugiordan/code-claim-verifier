# Experiments

Real evaluation results from running CCV against the [CyberGym](https://github.com/sunblaze-ucb/cybergym) benchmark (ICLR 2026).

## Setup

- **Benchmark**: 201 CyberGym vulnerability repositories (60 unique C/C++ projects from OSS-Fuzz/ARVO)
- **Models**: 7 models across 3 providers (5 Red Hat models-corp, 2 Anthropic Vertex AI)
- **Extraction**: Claude Sonnet 4 for all claim extraction (isolates extraction quality from reasoning quality)
- **Verification backends**: grep + cymbal (tree-sitter) with fallback. No LLM calls for verification.
- **Ground truth**: Auto-generated from source (function definitions, file existence, imports) with manual validation

## Key Results

!!! success "Headline findings"
    - **25.5% of LLM claims about code are hallucinated** (aggregate across 7 models)
    - CCV achieves **99.2% accuracy** against ground truth (4,864/4,905 correct)
    - **100% precision**: CCV never confirmed a hallucination as correct
    - **99.7% coverage**: only 0.3% of claims are unverifiable
    - Best model: Llama 3.3 70B at **15.4%** hallucination
    - Worst models: Claude Sonnet 4 and Haiku 4.5 at **35-37%**

### Hallucination Rate by Model

| Model | Repos | Claims | Verified | Refuted | Unverifiable | Hall. Rate |
|---|---|---|---|---|---|---|
| Llama 3.3 70B | 201 | 4,963 | 4,198 | 763 | 2 | **15.4%** |
| Granite 3.3 8B | 201 | 3,204 | 2,620 | 579 | 5 | **18.1%** |
| Mistral 7B | 201 | 2,380 | 1,863 | 511 | 6 | **21.5%** |
| Qwen3 14B | 201 | 2,949 | 2,205 | 742 | 2 | **25.2%** |
| GPT-OSS 20B | 201 | 4,222 | 3,125 | 1,081 | 16 | **25.7%** |
| Claude Haiku 4.5 | 201 | 4,165 | 2,682 | 1,464 | 19 | **35.3%** |
| Claude Sonnet 4 | 201 | 3,867 | 2,429 | 1,405 | 33 | **36.6%** |
| **Aggregate** | **1,407** | **25,750** | **19,122** | **6,545** | **83** | **25.5%** |

Hallucination rate = Refuted / (Verified + Refuted). UNVERIFIABLE claims are excluded from the denominator.

### CCV Tool Performance

| Metric | Value |
|---|---|
| GT-matched claims | 4,905 |
| Correct verdicts | 4,864 (99.2%) |
| Precision (VERIFIED) | **100%** (0 false positives) |
| Recall (VERIFIED) | **99.2%** (41 false negatives) |
| Coverage (verifiable) | **99.7%** |
| False negatives | 41 (all FUNCTION_EXISTS in C repos) |

CCV's zero false-positive rate is by construction: grep, `os.path.isfile()`, and tree-sitter don't hallucinate. When CCV says VERIFIED, it found deterministic evidence.

### Verification Method Distribution

| Method | Claims | % | Description |
|---|---|---|---|
| grep_import | 5,456 | 21.2% | Import/include pattern matching |
| cymbal_function | 4,378 | 17.0% | Tree-sitter function lookup |
| cymbal_callers | 3,756 | 14.6% | Tree-sitter call-site analysis |
| os.path.isfile | 2,888 | 11.2% | File existence check |
| file_read | 2,754 | 10.7% | Line content verification |
| grep_absent | 1,197 | 4.6% | Absence verification |
| grep_entry_point | 675 | 2.6% | Entry point grep |
| path_regex | 637 | 2.5% | File classification |
| path_check | 542 | 2.1% | Path validation |
| os.walk_fuzzy | 387 | 1.5% | Fuzzy file lookup |
| cymbal_call_chain | 329 | 1.3% | Call chain verification |
| Other | 101 | 0.4% | manifest_parse, default_value, osv_api |

~37% of verifications use cymbal (tree-sitter AST), ~47% use grep, and ~16% use filesystem checks.

### Claim Type Distribution

| Claim Type | Claims | Refute Rate | Description |
|---|---|---|---|
| IMPORT_EXISTS | 5,456 | 12.7% | Import/include statements |
| FUNCTION_EXISTS | 4,378 | 36.9% | Function definitions |
| FILE_EXISTS | 3,817 | 16.8% | Source file paths |
| FUNCTION_CALLED | 3,347 | 11.5% | Function call sites |
| LINE_CONTENT | 2,587 | 91.1% | Specific line content |
| ABSENCE | 1,197 | 5.1% | Negative claims |
| ENTRY_POINT | 675 | 24.7% | API/handler entry points |
| FILE_CLASSIFICATION | 637 | 15.7% | File type classification |
| HAS_CALLERS | 409 | 30.1% | Caller existence |
| CALL_CHAIN | 329 | 100% | Multi-hop call chains |
| Other | 918 | varied | MITIGATION, DEPENDENCY, DEFAULT_VALUE, CVE |

LINE_CONTENT has a 91.1% refute rate because LLMs frequently fabricate exact line content. CALL_CHAIN has 100% because multi-hop call relationships are almost never accurate without actual code analysis.

### Action Distribution

| Action | Count | % | Meaning |
|---|---|---|---|
| BOOST | 488 | 35.4% | Verification rate >= 80%, trust the analysis |
| FLAG | 440 | 31.9% | 50-80% verified, human review recommended |
| OVERRIDE | 453 | 32.8% | < 50% verified, analysis unreliable |

About one-third of vulnerability analyses are overridden by CCV because more than half the LLM's factual claims were wrong.

## Observations

1. **Model size doesn't predict accuracy**: Llama 3.3 70B (15.4%) outperforms both larger Claude models (35-37%). Granite 3.3 8B (18.1%) beats models 2-4x its size. Architecture and training data matter more than parameter count.

2. **Hallucination is claim-type dependent**: LINE_CONTENT (91% refuted) and CALL_CHAIN (100%) are almost always wrong. FILE_EXISTS (17%) and IMPORT_EXISTS (13%) are mostly correct. Models are better at structural claims than content-level ones.

3. **Coverage is near-complete**: Only 83 out of 25,750 claims (0.3%) are unverifiable. CCV can make a judgment on almost everything an LLM says about code.

4. **Zero false-verified is the safety guarantee**: CCV never confirmed a hallucination as correct across 25,750 claims. When CCV says VERIFIED, it is always right. This is by construction: deterministic tools don't hallucinate.

5. **Tree-sitter fallback matters**: The cymbal/CPG "not found" fallback to grep (instead of immediately refuting) recovered 215 false negatives. Tree-sitter indexes miss C functions defined via macros, so grep serves as a safety net.

## Reproducing

```bash
# Stage 1: Build manifest from CyberGym repos
python eval/cybergym/run_pipeline.py prepare \
    --cybergym-repos ~/workdir/rhoai/cybergym-repos/

# Stage 2: Generate reasoning (needs model API access)
python eval/cybergym/run_pipeline.py generate \
    --model granite-3.3-8b \
    --manifest eval/cybergym/manifest.jsonl

# Stage 3: Verify with CCV
python eval/cybergym/run_pipeline.py verify \
    --manifest eval/cybergym/manifest.jsonl

# Stage 4: Analyze
python eval/cybergym/run_pipeline.py analyze \
    --output-dir eval/cybergym/analysis
```

All reasoning outputs and verification results are committed in the repository under `eval/cybergym/reasoning/` and `eval/cybergym/results/`.
