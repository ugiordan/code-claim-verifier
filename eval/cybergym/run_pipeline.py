#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import sys


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="CyberGym evaluation pipeline for CCV")
    subparsers = parser.add_subparsers(dest="stage", required=True)

    p_prepare = subparsers.add_parser("prepare", help="Stage 1: scan repos, generate GT")
    p_prepare.add_argument("--cybergym-repos", required=True, help="Path to cybergym-repos directory")
    p_prepare.add_argument("--output", default="eval/cybergym/manifest.jsonl", help="Output manifest path")

    p_generate = subparsers.add_parser("generate", help="Stage 2: generate LLM reasoning")
    p_generate.add_argument("--manifest", required=True, help="Path to manifest.jsonl")
    p_generate.add_argument("--model", required=True, help="Model name (e.g., claude-sonnet-4)")
    p_generate.add_argument("--condition", default="informed", choices=["informed", "blind"])
    p_generate.add_argument("--output-dir", default="eval/cybergym/reasoning")

    p_verify = subparsers.add_parser("verify", help="Stage 3: CCV verification")
    p_verify.add_argument("--manifest", required=True, help="Path to manifest.jsonl")
    p_verify.add_argument("--reasoning-dir", default="eval/cybergym/reasoning")
    p_verify.add_argument("--output-dir", default="eval/cybergym/results")
    p_verify.add_argument("--extraction-llm", default="claude-sonnet-4")
    p_verify.add_argument("--with-judge", action="store_true")

    p_analyze = subparsers.add_parser("analyze", help="Stage 4: compute metrics")
    p_analyze.add_argument("--results-dir", default="eval/cybergym/results")
    p_analyze.add_argument("--output-dir", default="eval/cybergym/analysis")

    args = parser.parse_args()

    if args.stage == "prepare":
        from eval.cybergym.prepare import run_prepare
        run_prepare(args.cybergym_repos, args.output)
    elif args.stage == "generate":
        from eval.cybergym.generate import run_generate
        run_generate(args.manifest, args.model, args.condition, args.output_dir)
    elif args.stage == "verify":
        from eval.cybergym.verify import run_verify
        run_verify(args.manifest, args.reasoning_dir, args.output_dir,
                   args.extraction_llm, args.with_judge)
    elif args.stage == "analyze":
        from eval.cybergym.analyze import run_analyze
        run_analyze(args.results_dir, args.output_dir)


if __name__ == "__main__":
    main()
