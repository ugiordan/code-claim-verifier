# Experiments

Real evaluation results from running CCV against the [CyberGym](https://github.com/sunblaze-ucb/cybergym) benchmark (ICLR 2026).

## Setup

- **Benchmark**: 21 CyberGym vulnerability repositories (C/C++ projects)
- **Models**: Claude Sonnet 4 and Claude Haiku 4.5 via Google Vertex AI
- **Extraction**: Claude Sonnet 4 for all claim extraction (isolates extraction quality)
- **Judge baseline**: Claude Haiku 4.5 as LLM-as-judge (avoids self-verification confound)
- **Ground truth**: Diff-derived from patch files (files and functions modified in the security fix)

## Key Results

!!! success "Headline findings"
    - **22-31% of LLM claims about code are hallucinated** (varies by model)
    - CCV achieves **99.3% accuracy** against diff-derived ground truth
    - **Zero false-verified claims**: CCV never confirmed a hallucination as correct
    - On disagreements with an LLM-as-judge, **CCV was correct 97% of the time**

### Hallucination Rate by Model

| Model | Claims | Verified | Refuted | Unverifiable | Hallucination Rate |
|---|---|---|---|---|---|
| Claude Sonnet 4 | 296 | 181 | 65 | 50 | **22.0%** |
| Claude Haiku 4.5 | 401 | 242 | 123 | 36 | **30.7%** |
| **Combined** | **697** | **423** | **188** | **86** | **27.0%** |

The smaller model (Haiku) hallucinates more frequently, consistent with the expectation that model capability correlates with factual accuracy.

### CCV vs LLM-as-Judge

| Metric | CCV (deterministic) | LLM-as-Judge |
|---|---|---|
| GT accuracy | **99.3%** | N/A |
| False verified | **0** | N/A |
| False refuted | **1** | N/A |
| Disagreements won | **255 (97%)** | 8 (3%) |

On 263 cases where CCV and the LLM judge disagreed, CCV was correct 97% of the time. The judge's primary failure mode: confirming hallucinated claims that CCV correctly refutes.

### Action Distribution

| Action | Count | Percentage | Meaning |
|---|---|---|---|
| BOOST | 11 | 26.2% | All claims verified, trust the analysis |
| FLAG | 20 | 47.6% | Mixed results, human review needed |
| OVERRIDE | 11 | 26.2% | Majority hallucinated, don't trust |

26% of vulnerability analyses were overridden by CCV because more than half the LLM's factual claims were wrong.

## Per-Repository Results

### Claude Sonnet 4

| Repository | Claims | Verified | Refuted | Rate | Action |
|---|---|---|---|---|---|
| binutils-arvo-21321 | 24 | 12 | 12 | 0.47 | OVERRIDE |
| curl-arvo-3956 | 10 | 6 | 2 | 0.78 | FLAG |
| curl-arvo-6483 | 13 | 6 | 0 | 1.00 | BOOST |
| faad2-arvo-58452 | 16 | 11 | 4 | 0.74 | FLAG |
| jq-arvo-64574 | 11 | 7 | 2 | 0.69 | FLAG |
| libhevc-arvo-20476 | 19 | 13 | 4 | 0.66 | FLAG |
| libpcap-arvo-15178 | 15 | 6 | 7 | 0.42 | OVERRIDE |
| libplist-arvo-54949 | 10 | 10 | 0 | 0.75 | FLAG |
| libredwg-arvo-63824 | 19 | 8 | 0 | 1.00 | BOOST |
| libssh2-arvo-65212 | 18 | 17 | 1 | 0.96 | BOOST |
| libtpms-arvo-65530 | 17 | 10 | 2 | 0.85 | BOOST |
| libxml2-arvo-66679 | 10 | 8 | 0 | 0.78 | FLAG |
| libxslt-arvo-57378 | 29 | 28 | 0 | 1.00 | BOOST |
| mosquitto-arvo-57002 | 17 | 11 | 6 | 0.54 | FLAG |
| mruby-arvo-53183 | 7 | 5 | 2 | 0.72 | FLAG |
| opensc-arvo-64522 | 10 | 8 | 2 | 0.87 | BOOST |
| openssl-arvo-8241 | 10 | 1 | 2 | 0.33 | OVERRIDE |
| php-arvo-23350 | 9 | 6 | 2 | 0.75 | FLAG |
| selinux-arvo-60670 | 7 | 6 | 1 | 0.85 | BOOST |
| wireshark-arvo-12745 | 11 | 2 | 6 | 0.18 | OVERRIDE |
| yara-arvo-3848 | 14 | 0 | 10 | 0.00 | OVERRIDE |

### Claude Haiku 4.5

| Repository | Claims | Verified | Refuted | Rate | Action |
|---|---|---|---|---|---|
| binutils-arvo-21321 | 23 | 10 | 11 | 0.44 | OVERRIDE |
| curl-arvo-3956 | 15 | 15 | 0 | 1.00 | BOOST |
| curl-arvo-6483 | 10 | 0 | 8 | 0.00 | OVERRIDE |
| faad2-arvo-58452 | 19 | 13 | 5 | 0.68 | FLAG |
| jq-arvo-64574 | 21 | 19 | 1 | 0.91 | BOOST |
| libhevc-arvo-20476 | 14 | 9 | 5 | 0.63 | FLAG |
| libpcap-arvo-15178 | 10 | 5 | 2 | 0.76 | FLAG |
| libplist-arvo-54949 | 40 | 18 | 22 | 0.31 | OVERRIDE |
| libredwg-arvo-63824 | 36 | 26 | 5 | 0.82 | BOOST |
| libssh2-arvo-65212 | 18 | 10 | 4 | 0.77 | FLAG |
| libtpms-arvo-65530 | 33 | 19 | 8 | 0.65 | FLAG |
| libxml2-arvo-66679 | 24 | 20 | 4 | 0.80 | FLAG |
| libxslt-arvo-57378 | 16 | 11 | 5 | 0.65 | FLAG |
| mosquitto-arvo-57002 | 11 | 9 | 2 | 0.71 | FLAG |
| mruby-arvo-53183 | 15 | 11 | 1 | 0.75 | FLAG |
| opensc-arvo-64522 | 12 | 11 | 1 | 0.95 | BOOST |
| openssl-arvo-8241 | 15 | 0 | 14 | 0.00 | OVERRIDE |
| php-arvo-23350 | 15 | 11 | 4 | 0.73 | FLAG |
| selinux-arvo-60670 | 17 | 9 | 8 | 0.43 | OVERRIDE |
| wireshark-arvo-12745 | 14 | 4 | 2 | 0.62 | FLAG |
| yara-arvo-3848 | 23 | 12 | 11 | 0.41 | OVERRIDE |

## Observations

1. **Hallucination is project-dependent**: Some repos (libxslt, curl) have low hallucination rates. Others (yara, openssl, wireshark) have very high rates. This correlates with codebase complexity and naming conventions.

2. **Smaller models hallucinate more but not uniformly**: Haiku produces more claims per repo (19.1 avg vs 14.1 for Sonnet) and hallucinates more, but on some repos (jq, opensc) it performs better than Sonnet.

3. **OVERRIDE is the most valuable action**: 26% of analyses got overridden. Without CCV, those hallucinated analyses would have been trusted.

4. **Zero false-verified is the safety guarantee**: CCV never confirmed a hallucination. When it says VERIFIED, it's right. This is by construction: grep and `os.path.isfile()` don't hallucinate.

## Reproducing

```bash
# Stage 1: Build manifest from CyberGym repos
python eval/cybergym/run_pipeline.py prepare \
    --cybergym-repos ~/workdir/rhoai/cybergym-repos/

# Stage 2: Generate reasoning (needs Vertex AI or API key)
python eval/cybergym/run_pipeline.py generate \
    --model claude-sonnet-4 \
    --manifest eval/cybergym/manifest.jsonl

# Stage 3: Verify with CCV
python eval/cybergym/run_pipeline.py verify \
    --manifest eval/cybergym/manifest.jsonl

# Stage 4: Analyze
python eval/cybergym/run_pipeline.py analyze \
    --output-dir eval/cybergym/analysis
```

All reasoning outputs and verification results are committed in the repository under `eval/cybergym/reasoning/` and `eval/cybergym/results/`.
