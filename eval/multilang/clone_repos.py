from __future__ import annotations

import logging
import os
import subprocess

from code_claim_verifier.language import detect_language
from eval.cybergym.utils import load_jsonl, save_jsonl, SOURCE_EXTENSIONS
from eval.multilang.constants import CandidateStatus, ECOSYSTEM_TO_LANG

logger = logging.getLogger(__name__)


def _repo_dir_name(repo_url: str, osv_id: str) -> str:
    return osv_id


def _count_source_files(path: str) -> int:
    count = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in SOURCE_EXTENSIONS:
                count += 1
    return count


def _checkout_pre_fix(repo_path: str, fix_commit: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "checkout", f"{fix_commit}~1"],
            cwd=repo_path, capture_output=True, text=True, timeout=60,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _detect_primary_language(repo_path: str, ecosystem: str) -> str:
    fallback = ECOSYSTEM_TO_LANG.get(ecosystem, "unknown")
    for root, _dirs, files in os.walk(repo_path):
        # Bug #8 fix: Check for .git as basename not substring
        if os.path.basename(root) == ".git" or "/.git/" in root:
            continue
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in SOURCE_EXTENSIONS and ext != ".h":
                return detect_language(f)
    return fallback


def _get_commit_date(repo_path: str) -> str:
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%aI"],
            cwd=repo_path, capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()[:10]
    except subprocess.TimeoutExpired:
        pass
    return ""


def clone_and_checkout(candidate: dict, repos_dir: str) -> dict:
    osv_id = candidate["osv_id"]
    ecosystem = candidate["ecosystem"]
    lang_dir = ECOSYSTEM_TO_LANG.get(ecosystem, "unknown")
    dir_name = _repo_dir_name(candidate["repo_url"], osv_id)
    dest = os.path.join(repos_dir, lang_dir, dir_name)

    if os.path.isdir(dest) and candidate.get("status") == CandidateStatus.CLONED:
        logger.debug("Already cloned: %s", osv_id)
        return candidate

    repo_url = candidate["repo_url"]
    fix_commit = candidate["fix_commit"]

    os.makedirs(os.path.dirname(dest), exist_ok=True)

    if not os.path.isdir(dest):
        try:
            result = subprocess.run(
                ["git", "clone", "--filter=blob:none", repo_url, dest],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                candidate["status"] = CandidateStatus.FAILED
                candidate["failure_reason"] = f"clone failed: {result.stderr[:200]}"
                candidate["failure_stage"] = "clone"
                return candidate
        except subprocess.TimeoutExpired:
            # Bug #15 fix: Clean up partial clone on timeout
            if os.path.isdir(dest):
                import shutil
                shutil.rmtree(dest, ignore_errors=True)
            candidate["status"] = CandidateStatus.FAILED
            candidate["failure_reason"] = "clone timed out"
            candidate["failure_stage"] = "clone"
            return candidate

    if not _checkout_pre_fix(dest, fix_commit):
        candidate["status"] = CandidateStatus.FAILED
        candidate["failure_reason"] = "checkout pre-fix commit failed"
        candidate["failure_stage"] = "clone"
        return candidate

    file_count = _count_source_files(dest)
    if file_count == 0:
        candidate["status"] = CandidateStatus.FAILED
        candidate["failure_reason"] = "no source files found"
        candidate["failure_stage"] = "clone"
        return candidate

    language = _detect_primary_language(dest, ecosystem)
    commit_date = _get_commit_date(dest)

    # Compute source_root relative to base_dir (parent of repos_dir)
    base_dir = os.path.dirname(repos_dir)
    candidate["source_root"] = os.path.relpath(dest, base_dir)
    candidate["language"] = language
    candidate["file_count"] = file_count
    candidate["commit_date"] = commit_date
    candidate["status"] = CandidateStatus.CLONED
    return candidate


def run_clone(candidates_path: str, repos_dir: str) -> None:
    candidates = load_jsonl(candidates_path)
    updated: list[dict] = []
    clone_count = 0
    _SAVE_INTERVAL = 50

    for i, c in enumerate(candidates):
        status = c.get("status")
        if status in (CandidateStatus.BUILD_OK, CandidateStatus.VERIFIED, CandidateStatus.READY):
            updated.append(c)
            continue
        if status == CandidateStatus.FAILED:
            updated.append(c)
            continue
        logger.info("[%d/%d] Cloning %s", i + 1, len(candidates), c["osv_id"])
        updated.append(clone_and_checkout(c, repos_dir))
        clone_count += 1

        if clone_count % _SAVE_INTERVAL == 0:
            save_jsonl(updated, candidates_path)
            cloned_so_far = sum(1 for x in updated if x.get("status") == CandidateStatus.CLONED)
            logger.info("Checkpoint: %d cloned so far (%d attempted)", cloned_so_far, clone_count)

    save_jsonl(updated, candidates_path)
    cloned = sum(1 for c in updated if c.get("status") == CandidateStatus.CLONED)
    logger.info("Cloned: %d / %d", cloned, len(updated))
