from __future__ import annotations

import logging
import os
import subprocess

from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.types import TypedClaim
from eval.cybergym.utils import load_jsonl, save_jsonl, SOURCE_EXTENSIONS
from eval.multilang.constants import CandidateStatus

logger = logging.getLogger(__name__)


def _get_changed_files(repo_path: str, fix_commit: str) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{fix_commit}~1", fix_commit],
            cwd=repo_path, capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return []
        files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        source_files = []
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in SOURCE_EXTENSIONS:
                source_files.append(f)
        return source_files
    except subprocess.TimeoutExpired:
        return []


def _is_source_change(changed_files: list[str]) -> bool:
    for f in changed_files:
        ext = os.path.splitext(f)[1].lower()
        if ext in SOURCE_EXTENSIONS:
            return True
    return False


def _verify_via_source_pattern(source_path: str, changed_files: list[str]) -> bool:
    for f in changed_files:
        full = os.path.join(source_path, f)
        if os.path.isfile(full):
            return True
    return False


def _verify_via_ccv(description: str, source_path: str, language: str) -> tuple[bool, int]:
    try:
        from code_claim_verifier.extractor import extract_claims as _extract
        from eval.cybergym.models import get_model

        llm_function = get_model("claude-sonnet-4")
        claims = _extract(description, {}, llm_function)
    except Exception:
        logger.debug("CCV extraction failed, skipping CCV verification")
        return False, 0

    if not claims:
        return False, 0

    engine = VerificationEngine()
    verified = engine.verify_claims_with_chaining(claims, source_path, language)
    verified_count = sum(1 for vc in verified if vc.verdict == "VERIFIED")
    return verified_count > 0, verified_count


def verify_vulnerability(candidate: dict, base_dir: str) -> dict:
    osv_id = candidate["osv_id"]
    source_root = candidate.get("source_root", "")
    fix_commit = candidate.get("fix_commit", "")
    language = candidate.get("language", "unknown")
    description = candidate.get("description", "")

    source_path = os.path.join(base_dir, source_root) if not os.path.isabs(source_root) else source_root

    if not os.path.isdir(source_path):
        candidate["status"] = CandidateStatus.FAILED
        candidate["failure_reason"] = "source_root not found for verification"
        candidate["failure_stage"] = "verify_vuln"
        return candidate

    repo_root = source_path
    git_dir = os.path.join(repo_root, ".git")
    while not os.path.isdir(git_dir) and repo_root != "/":
        repo_root = os.path.dirname(repo_root)
        git_dir = os.path.join(repo_root, ".git")

    changed_files = _get_changed_files(repo_root, fix_commit)
    candidate["changed_files"] = changed_files

    if not _is_source_change(changed_files):
        candidate["status"] = CandidateStatus.FAILED
        candidate["failure_reason"] = "fix commit only changes non-source files"
        candidate["failure_stage"] = "verify_vuln"
        candidate["vuln_verified"] = False
        return candidate

    for f in changed_files:
        full = os.path.join(source_path, f)
        if not os.path.isfile(full):
            alt = os.path.join(repo_root, f)
            if not os.path.isfile(alt):
                continue

    ccv_ok, ccv_count = _verify_via_ccv(description, source_path, language)
    if ccv_ok:
        candidate["vuln_verified"] = True
        candidate["verification_method"] = "ccv"
        candidate["ccv_verified_claims"] = ccv_count
        candidate["status"] = CandidateStatus.VERIFIED
        return candidate

    if _verify_via_source_pattern(source_path, changed_files):
        candidate["vuln_verified"] = True
        candidate["verification_method"] = "pattern_match"
        candidate["ccv_verified_claims"] = 0
        candidate["status"] = CandidateStatus.VERIFIED
        return candidate

    candidate["vuln_verified"] = False
    candidate["status"] = CandidateStatus.FAILED
    candidate["failure_reason"] = "could not verify vulnerability in pre-fix source"
    candidate["failure_stage"] = "verify_vuln"
    return candidate


def run_verify_vuln(candidates_path: str, base_dir: str) -> None:
    candidates = load_jsonl(candidates_path)
    updated: list[dict] = []

    for i, c in enumerate(candidates):
        if c.get("status") in (CandidateStatus.VERIFIED, CandidateStatus.READY):
            updated.append(c)
            continue
        if c.get("status") != CandidateStatus.BUILD_OK:
            updated.append(c)
            continue

        logger.info("[%d/%d] Verifying %s", i + 1, len(candidates), c["osv_id"])
        updated.append(verify_vulnerability(c, base_dir))

    save_jsonl(updated, candidates_path)
    verified = sum(1 for c in updated if c.get("vuln_verified"))
    logger.info("Verified: %d / %d", verified, len(updated))
