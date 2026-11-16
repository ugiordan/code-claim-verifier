"""Pre-index manifest repos for the backend-ablation verification runs.

Two conditions need preparation beyond the grep baseline:

- cpg: arch-analyzer quick-index per repo, producing the
  quick-index.json that the CPG backend loads.
- cymbal: a Git checkout per repo (tarball-sourced CyberGym
  instances have no .git; cymbal refuses to index without one).

Both are derived data, keyed to the pinned source snapshots in the
manifest; re-running against a different revision rebuilds them.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess

from eval.cybergym.utils import load_jsonl

logger = logging.getLogger(__name__)


def _quick_index(source_root: str) -> bool:
    if not shutil.which("arch-analyzer"):
        logger.warning("arch-analyzer not on PATH; CPG pre-index skipped")
        return False
    result = subprocess.run(
        ["arch-analyzer", "quick-index", source_root,
         "-output", os.path.join(source_root, "quick-index.json")],
        capture_output=True, text=True, timeout=600,
    )
    if result.returncode != 0:
        logger.warning(
            "quick-index failed for %s: %s", source_root, result.stderr[:150],
        )
        return False
    return True


def _ensure_git(source_root: str) -> bool:
    git_dir = os.path.join(source_root, ".git")
    if os.path.isdir(git_dir):
        return True
    result = subprocess.run(
        ["git", "init", "-q", source_root],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        logger.warning("git init failed for %s: %s", source_root, result.stderr[:120])
        return False
    return True


def run_preindex(manifest_path: str) -> None:
    """Index every manifest repo for quick-index and prepare git checkouts."""
    manifest = load_jsonl(manifest_path)
    indexed = git_ok = failed = 0
    for i, entry in enumerate(manifest, 1):
        source_root = entry.get("source_root", "")
        if not source_root or not os.path.isdir(source_root):
            logger.warning("missing source root for %s", entry.get("vuln_id"))
            failed += 1
            continue
        if not os.path.isfile(os.path.join(source_root, "quick-index.json")):
            if _quick_index(source_root):
                indexed += 1
            else:
                failed += 1
        else:
            indexed += 1
        if _ensure_git(source_root):
            git_ok += 1
        else:
            failed += 1
        if i % 10 == 0:
            logger.info("pre-indexed %d/%d", i, len(manifest))
    logger.info(
        "pre-index done: %d quick-indexed, %d git-ready, %d failed",
        indexed, git_ok, failed,
    )
