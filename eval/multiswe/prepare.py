#!/usr/bin/env python3
"""Prepare Multi-SWE-bench dataset for CCV evaluation.

Downloads the dataset from HuggingFace, clones repos at the base commit,
and generates a manifest.jsonl compatible with the CCV eval pipeline.

Usage:
    python eval/multiswe/prepare.py --repos-dir /path/to/repos --output eval/multiswe/manifest.jsonl
    python eval/multiswe/prepare.py --repos-dir /path/to/repos --languages go,rust,java --max-per-lang 30
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from code_claim_verifier.language import detect_language

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

LANG_MAP = {
    "c": "c", "cpp": "cpp", "go": "go", "java": "java",
    "js": "javascript", "ts": "typescript", "rust": "rust",
    "kotlin": "kotlin", "python": "python",
}


def download_dataset(languages: list[str] | None = None) -> list[dict]:
    """Download Multi-SWE-bench JSONL files from HuggingFace."""
    from huggingface_hub import hf_hub_download, list_repo_files

    files = [f for f in list_repo_files("ByteDance-Seed/Multi-SWE-bench", repo_type="dataset")
             if f.endswith(".jsonl")]

    if languages:
        files = [f for f in files if f.split("/")[0] in languages]

    instances = []
    for fpath in files:
        lang = fpath.split("/")[0]
        local = hf_hub_download("ByteDance-Seed/Multi-SWE-bench", fpath, repo_type="dataset")
        with open(local) as f:
            for line in f:
                entry = json.loads(line)
                entry["_lang"] = lang
                instances.append(entry)

    logger.info("Downloaded %d instances from %d files", len(instances), len(files))
    return instances


def clone_repo(org: str, repo: str, sha: str, repos_dir: str) -> str | None:
    """Clone a repo and checkout at the specified commit. Returns repo path or None."""
    repo_dir = os.path.join(repos_dir, f"{org}__{repo}")

    if os.path.isdir(repo_dir):
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir, capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip().startswith(sha[:7]):
            return repo_dir

    if not os.path.isdir(repo_dir):
        result = subprocess.run(
            ["git", "clone", "--depth=1", f"https://github.com/{org}/{repo}.git", repo_dir],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            logger.warning("Clone failed for %s/%s: %s", org, repo, result.stderr[:200])
            return None

        subprocess.run(
            ["git", "fetch", "--depth=100", "origin", sha],
            cwd=repo_dir, capture_output=True, text=True, timeout=120,
        )

    result = subprocess.run(
        ["git", "checkout", sha],
        cwd=repo_dir, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        subprocess.run(
            ["git", "fetch", "--unshallow"],
            cwd=repo_dir, capture_output=True, text=True, timeout=600,
        )
        result = subprocess.run(
            ["git", "checkout", sha],
            cwd=repo_dir, capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            logger.warning("Checkout failed for %s/%s@%s", org, repo, sha[:8])
            return None

    return repo_dir


def build_description(entry: dict) -> str:
    """Build a bug/issue description from the Multi-SWE-bench entry."""
    parts = []
    parts.append(f"Issue: {entry.get('title', 'Unknown')}")

    for issue in entry.get("resolved_issues", []):
        title = issue.get("title", "")
        body = issue.get("body", "")
        if title:
            parts.append(f"\n### {title}")
        if body:
            parts.append(body[:2000])

    return "\n".join(parts)


def build_manifest(instances: list[dict], repos_dir: str,
                    max_per_lang: int = 0) -> list[dict]:
    """Clone repos, build manifest entries."""
    by_lang: dict[str, list[dict]] = {}
    for inst in instances:
        lang = inst["_lang"]
        by_lang.setdefault(lang, []).append(inst)

    manifest = []
    for lang, entries in sorted(by_lang.items()):
        if max_per_lang > 0:
            entries = entries[:max_per_lang]

        logger.info("Processing %s: %d instances", lang, len(entries))
        repos_cache: dict[str, str | None] = {}

        for i, entry in enumerate(entries):
            org = entry["org"]
            repo = entry["repo"]
            base_sha = entry["base"]["sha"]
            instance_id = entry.get("instance_id", f"{org}__{repo}-{entry.get('number', i)}")

            cache_key = f"{org}/{repo}@{base_sha}"
            if cache_key not in repos_cache:
                repos_cache[cache_key] = clone_repo(org, repo, base_sha, repos_dir)

            repo_path = repos_cache[cache_key]
            if not repo_path:
                continue

            description = build_description(entry)
            ccv_lang = LANG_MAP.get(lang, lang)

            manifest.append({
                "vuln_id": instance_id,
                "instance_id": instance_id,
                "source_root": os.path.abspath(repo_path),
                "language": ccv_lang,
                "project": f"{org}/{repo}",
                "description": description,
                "base_sha": base_sha,
                "fix_patch_files": _extract_patch_files(entry.get("fix_patch", "")),
            })

            if (i + 1) % 20 == 0:
                logger.info("  %s: %d/%d", lang, i + 1, len(entries))

    logger.info("Manifest: %d entries across %d languages", len(manifest), len(by_lang))
    return manifest


def _extract_patch_files(patch: str) -> list[str]:
    """Extract file paths from a unified diff."""
    files = []
    for line in patch.split("\n"):
        if line.startswith("+++ b/"):
            files.append(line[6:])
    return files


def main():
    parser = argparse.ArgumentParser(description="Prepare Multi-SWE-bench for CCV")
    parser.add_argument("--repos-dir", required=True, help="Directory to clone repos into")
    parser.add_argument("--output", default="eval/multiswe/manifest.jsonl", help="Output manifest")
    parser.add_argument("--languages", default="", help="Comma-separated languages (empty=all)")
    parser.add_argument("--max-per-lang", type=int, default=0, help="Max instances per language (0=all)")
    args = parser.parse_args()

    languages = [l.strip() for l in args.languages.split(",") if l.strip()] or None

    instances = download_dataset(languages)
    manifest = build_manifest(instances, args.repos_dir, args.max_per_lang)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        for entry in manifest:
            f.write(json.dumps(entry) + "\n")

    logger.info("Written %d entries to %s", len(manifest), args.output)


if __name__ == "__main__":
    main()
