from __future__ import annotations

import logging
import os

from code_claim_verifier.language import detect_language
from eval.cybergym.gt import generate_verified_gt, generate_refuted_gt, validate_negatives
from eval.cybergym.utils import find_source_root, save_jsonl

logger = logging.getLogger(__name__)

_SOURCE_EXTENSIONS = frozenset((".c", ".cpp", ".py", ".go", ".ts", ".js", ".java", ".rs", ".h"))


def scan_repo(repo_path: str, vuln_id: str) -> dict | None:
    source_root = find_source_root(repo_path)
    if source_root is None:
        logger.warning("No src-vul/ found in %s, skipping", repo_path)
        return None

    project = os.path.basename(source_root)
    src_files: list[str] = []
    for root, _dirs, files in os.walk(source_root):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in _SOURCE_EXTENSIONS:
                rel = os.path.relpath(os.path.join(root, f), source_root)
                src_files.append(rel)

    lang_files = [f for f in src_files if not f.endswith(".h")]
    language = detect_language(lang_files[0]) if lang_files else "c"

    verified_gt = generate_verified_gt(source_root, language)
    func_names = [c["parameters"]["name"] for c in verified_gt
                  if c["claim_type"] == "FUNCTION_EXISTS"]
    refuted_gt = generate_refuted_gt(src_files, func_names, language)
    refuted_gt = validate_negatives(refuted_gt, source_root, language)

    all_gt = verified_gt + refuted_gt

    return {
        "vuln_id": vuln_id,
        "project": project,
        "repo_path": os.path.abspath(repo_path),
        "source_root": os.path.abspath(source_root),
        "language": language,
        "source_files": src_files[:100],
        "source_functions": func_names[:50],
        "gt_claims": all_gt,
    }


def build_manifest(cybergym_repos_dir: str) -> list[dict]:
    manifest: list[dict] = []
    for entry_name in sorted(os.listdir(cybergym_repos_dir)):
        repo_path = os.path.join(cybergym_repos_dir, entry_name)
        if not os.path.isdir(repo_path):
            continue
        result = scan_repo(repo_path, entry_name)
        if result:
            manifest.append(result)
        else:
            logger.warning("Skipped %s", entry_name)
    return manifest


def run_prepare(cybergym_repos_dir: str, output_path: str) -> None:
    manifest = build_manifest(cybergym_repos_dir)
    save_jsonl(manifest, output_path)
    logger.info("Manifest written: %d entries to %s", len(manifest), output_path)
