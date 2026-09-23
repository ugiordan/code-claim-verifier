# Evaluation Validity

This file is the gate for quantitative claims made about CCV. A result is
headline-eligible only when the run records the dataset revision, source
snapshot, prompt digests, model configuration, verifier backend, and complete
claim-to-ground-truth accounting.

## Legacy Runs

The collected runs currently in the working tree are useful raw material, but
they are not valid evidence for the paper's accuracy or hallucination claims.

| Dataset | Raw results | Main validity failures |
|---|---:|---|
| CyberGym | 1,809 results, 37,187 claims | No provenance metadata, legacy matching that drops unmatched claims, 13,481 malformed or underspecified claims |
| Multi-SWE-bench | 2,264 result files, 283 manifest entries | 18 shared checkout paths contain multiple base SHAs, only 20 current checkouts match their manifest SHA, no provenance metadata |

The old reports must therefore be described as exploratory refutation rates,
not verified hallucination rates or verifier accuracy.

## Manual Clean-Main Spot Checks

These observations are useful for debugging the verifier and extractor, but are
not benchmark measurements because the runs used current-main checkouts and
manual source validation rather than a pinned, independently adjudicated run:

- ODH Operator: extraction returned no claims, so CCV performed no verification. The manually checked immutable source links are evidence about the repository, not evidence that CCV verified the finding.
- kube-auth-proxy: extraction returned 9 claims, with 3 verified and 6 refuted. Manual review found false refutations caused by line `0`, descriptive phrases treated as function names, and overly broad absence claims. Two useful positive checks were real: the outbound `InsecureSkipVerify` path and the server `MaxVersion: TLS1.3` setting.

The implementation treats these failure modes conservatively: line `0` can no
longer produce a false refutation, prose is not accepted as a function symbol,
and broad absence descriptions are `UNVERIFIABLE` instead of literal searches.

The controlled fixture evaluation is also not a model evaluation. Its current
50 claims achieve 98% verification accuracy, but extraction is mocked and the
fixture set is small. It is a regression test, not a paper headline result.

## Canonical Run Requirements

1. Pin the upstream dataset revision.
2. Check out each benchmark instance in an immutable, instance-specific path.
3. Record the source snapshot digest and, where available, the Git commit.
4. Record model ID, provider, temperature, token limit, prompt digests, and extraction version.
5. Normalize claim parameter aliases before verification and reject underspecified claims as `UNVERIFIABLE`.
6. Keep unmatched predictions and unmatched ground-truth claims in the report.
7. Use independent ground truth for accuracy. Source-derived GT must not reuse the same matcher as the verifier without an independent validation sample.
8. Report claim-level and case-level results with project-clustered confidence intervals.
9. Exclude patch-file context from the primary Multi-SWE condition.
10. Recompute all tables and figures from one immutable run manifest.

## Audit Command

```bash
python -m eval.audit_results \
    --cybergym-manifest eval/cybergym/manifest.jsonl \
    --cybergym-results eval/cybergym/results \
    --multiswe-manifest eval/multiswe/manifest-full.jsonl
```

Do not restore the paper's headline numbers until the audit reports
`valid_for_headline_accuracy: true` for the exact run used by the manuscript.
