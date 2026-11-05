# Experiments

## Evaluation Status

The collected CyberGym and Multi-SWE-bench runs are retained as raw material,
but they are **not currently valid evidence for headline accuracy or
hallucination claims**. An audit found missing provenance, incomplete
claim-to-ground-truth matching, malformed extractor parameters, and mutable
Multi-SWE checkouts.

The old numbers previously shown on this page have been removed from the
current evidence set. They must not be cited as validated results.

The controlled fixture evaluation is a regression test only. It currently
contains 50 claims, uses mocked extraction by default, and is too small to
support a research claim about LLM behavior.

## Manual Spot Checks

Exploratory checks on clean current-main checkouts exposed extractor and
verifier limitations that are not included in benchmark metrics. ODH Operator
produced no claims, so CCV verified nothing. kube-auth-proxy produced 9 claims,
of which 3 were verified and 6 refuted; manual review found false refutations
from line `0`, descriptive function names, and broad absence descriptions.
The same review confirmed real detections for the outbound
`InsecureSkipVerify` path and the server `MaxVersion: TLS1.3` setting.

## Legacy Data Audit

| Dataset | Raw artifacts | Audit result |
|---|---:|---|
| CyberGym | 1,809 result files, 37,187 claims | 1,809 missing provenance records; 13,481 malformed or underspecified claims |
| Multi-SWE-bench | 2,264 result files, 283 instances | 18 repository paths reused for multiple base commits; no provenance-valid result files |

The raw reasoning and result files are useful for debugging and reprocessing,
but the legacy reports use the term `hallucination rate` for a verifier
refutation rate. Those terms are not interchangeable without independent
ground-truth adjudication.

## Reproducible Pipeline

Prepare CyberGym with a pinned description file and dataset revision:

```bash
python -m eval.cybergym.run_pipeline prepare \
    --cybergym-repos /path/to/cybergym-repos \
    --descriptions /path/to/cybergym-descriptions.jsonl \
    --dataset-revision <40-character-dataset-commit> \
    --output eval/cybergym/manifest.jsonl
```

Generate reasoning with a fixed model configuration:

```bash
python -m eval.cybergym.run_pipeline generate \
    --model granite-3.3-8b \
    --manifest eval/cybergym/manifest.jsonl
```

Verify with the read-only default backend. The optional Cymbal backend is
explicit and requires an existing Git checkout:

```bash
python -m eval.cybergym.run_pipeline verify \
    --manifest eval/cybergym/manifest.jsonl \
    --force
```

Audit before analyzing:

```bash
python -m eval.audit_results \
    --cybergym-manifest eval/cybergym/manifest.jsonl \
    --cybergym-results eval/cybergym/results \
    --multiswe-manifest eval/multiswe/manifest-full.jsonl
```

The paper's quantitative tables will only be generated from a manifest and
result set that passes this audit.

## Ground Truth Policy

Source-derived positives and synthetic negatives are useful for regression
testing, but they do not by themselves establish that an LLM claim is false.
The canonical study must add an independently validated, stratified sample of
claims, including unmatched predictions, with blinded human adjudication or a
separate trusted analysis oracle.
