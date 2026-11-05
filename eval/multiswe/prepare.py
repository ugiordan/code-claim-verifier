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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval.provenance import git_head, git_is_clean, is_immutable_revision, snapshot_digest

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

LANG_MAP = {
    "c": "c", "cpp": "cpp", "go": "go", "java": "java",
    "js": "javascript", "ts": "typescript", "rust": "rust",
    "kotlin": "kotlin", "python": "python",
}


def download_dataset(
    languages: list[str] | None = None,
    revision: str = "",
) -> list[dict]:
    """Download Multi-SWE-bench JSONL files from HuggingFace."""
    if not is_immutable_revision(revision):
        raise ValueError("revision must be a 40-character commit or sha256 digest")
    from huggingface_hub import hf_hub_download, list_repo_files

    files = [f for f in list_repo_files(
        "ByteDance-Seed/Multi-SWE-bench",
        repo_type="dataset",
        revision=revision,
    )
             if f.endswith(".jsonl")]

    if languages:
        files = [f for f in files if f.split("/")[0] in languages]

    instances = []
    for fpath in files:
        lang = fpath.split("/")[0]
        local = hf_hub_download(
            "ByteDance-Seed/Multi-SWE-bench",
            fpath,
            repo_type="dataset",
            revision=revision,
        )
        with open(local) as f:
            for line in f:
                entry = json.loads(line)
                entry["_lang"] = lang
                instances.append(entry)

    logger.info("Downloaded %d instances from %d files", len(instances), len(files))
    return instances


def clone_repo(org: str, repo: str, sha: str, repos_dir: str) -> str | None:
    """Clone a repo and checkout at the specified commit. Returns repo path or None."""
    # A checkout is immutable for one benchmark base revision. Sharing a
    # directory across SHAs makes earlier manifest entries silently point at
    # whichever revision was checked out last.
    repo_dir = os.path.join(repos_dir, f"{org}__{repo}__{sha[:12]}")

    if os.path.isdir(repo_dir):
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_dir, capture_output=True, text=True, timeout=10,
        )
        if (
            result.returncode == 0
            and result.stdout.strip().startswith(sha[:7])
            and git_is_clean(repo_dir)
        ):
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
                    max_per_lang: int = 0,
                    dataset_revision: str = "") -> list[dict]:
    """Clone repos, build manifest entries."""
    if not is_immutable_revision(dataset_revision):
        raise ValueError("dataset_revision must be a 40-character commit or sha256 digest")
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
                "source_head": git_head(repo_path),
                "source_digest": snapshot_digest(repo_path),
                "dataset_revision": dataset_revision,
                "manifest_schema": 2,
                "ground_truth_validation": "unavailable",
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
    parser.add_argument(
        "--dataset-revision",
        required=True,
        help="40-character Hugging Face dataset commit or sha256 digest",
    )
    args = parser.parse_args()

    languages = [language.strip() for language in args.languages.split(",") if language.strip()] or None

    instances = download_dataset(languages, revision=args.dataset_revision)
    manifest = build_manifest(
        instances,
        args.repos_dir,
        args.max_per_lang,
        dataset_revision=args.dataset_revision,
    )

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        for entry in manifest:
            f.write(json.dumps(entry) + "\n")

    logger.info("Written %d entries to %s", len(manifest), args.output)


if __name__ == "__main__":
    main()
