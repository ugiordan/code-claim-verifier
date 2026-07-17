from __future__ import annotations

import argparse
import logging
import os
import sys


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="PolyVuln benchmark preparation pipeline")
    subparsers = parser.add_subparsers(dest="stage", required=True)

    p_query = subparsers.add_parser("query", help="Stage 1: query OSV for candidates")
    p_query.add_argument("--output", default="eval/multilang/candidates.jsonl")
    p_query.add_argument("--ecosystems", nargs="*", help="Ecosystems to query (default: all)")
    p_query.add_argument("--min-stars", type=int, default=100)

    p_clone = subparsers.add_parser("clone", help="Stage 2: clone repos and checkout pre-fix")
    p_clone.add_argument("--candidates", default="eval/multilang/candidates.jsonl")
    p_clone.add_argument("--repos-dir", default="eval/multilang/repos")

    p_build = subparsers.add_parser("build", help="Stage 3: build in Podman containers")
    p_build.add_argument("--candidates", default="eval/multilang/candidates.jsonl")
    p_build.add_argument("--containerfiles-dir", default="eval/multilang/containerfiles")
    p_build.add_argument("--base-dir", default="eval/multilang")
    p_build.add_argument("--max-builds", type=int, default=0)
    p_build.add_argument("--retry-failed", action="store_true")

    p_verify = subparsers.add_parser("verify-vuln", help="Stage 4: verify vulnerabilities via CCV")
    p_verify.add_argument("--candidates", default="eval/multilang/candidates.jsonl")
    p_verify.add_argument("--base-dir", default="eval/multilang")

    p_gt = subparsers.add_parser("generate-gt", help="Stage 5: generate ground truth claims")
    p_gt.add_argument("--candidates", default="eval/multilang/candidates.jsonl")
    p_gt.add_argument("--base-dir", default="eval/multilang")

    p_manifest = subparsers.add_parser("manifest", help="Stage 6: build final manifest")
    p_manifest.add_argument("--candidates", default="eval/multilang/candidates.jsonl")
    p_manifest.add_argument("--output", default="eval/multilang/manifest.jsonl")
    p_manifest.add_argument("--per-language", type=int, default=50)

    p_all = subparsers.add_parser("all", help="Run all stages sequentially")
    p_all.add_argument("--output-dir", default="eval/multilang")
    p_all.add_argument("--ecosystems", nargs="*")
    p_all.add_argument("--min-stars", type=int, default=100)
    p_all.add_argument("--per-language", type=int, default=50)
    p_all.add_argument("--max-builds", type=int, default=0)

    args = parser.parse_args()

    if args.stage == "query":
        from eval.multilang.query_osv import run_query
        run_query(args.output, args.ecosystems, args.min_stars)

    elif args.stage == "clone":
        from eval.multilang.clone_repos import run_clone
        run_clone(args.candidates, args.repos_dir)

    elif args.stage == "build":
        from eval.multilang.build_verify import run_build
        run_build(args.candidates, args.containerfiles_dir, args.base_dir,
                  args.max_builds, args.retry_failed)

    elif args.stage == "verify-vuln":
        from eval.multilang.verify_vuln import run_verify_vuln
        run_verify_vuln(args.candidates, args.base_dir)

    elif args.stage == "generate-gt":
        from eval.multilang.generate_gt import run_generate_gt
        run_generate_gt(args.candidates, args.base_dir)

    elif args.stage == "manifest":
        from eval.multilang.build_manifest import build_manifest
        build_manifest(args.candidates, args.output, args.per_language)

    elif args.stage == "all":
        d = args.output_dir
        candidates = os.path.join(d, "candidates.jsonl")
        repos_dir = os.path.join(d, "repos")
        containerfiles_dir = os.path.join(d, "containerfiles")
        manifest = os.path.join(d, "manifest.jsonl")

        from eval.multilang.query_osv import run_query
        run_query(candidates, args.ecosystems, args.min_stars)

        from eval.multilang.clone_repos import run_clone
        run_clone(candidates, repos_dir)

        from eval.multilang.build_verify import run_build
        run_build(candidates, containerfiles_dir, d, args.max_builds)

        from eval.multilang.verify_vuln import run_verify_vuln
        run_verify_vuln(candidates, d)

        from eval.multilang.generate_gt import run_generate_gt
        run_generate_gt(candidates, d)

        from eval.multilang.build_manifest import build_manifest
        build_manifest(candidates, manifest, args.per_language)


if __name__ == "__main__":
    main()
