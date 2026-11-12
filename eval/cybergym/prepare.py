from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone

from code_claim_verifier.language import detect_language
from eval.cybergym.gt import (
    generate_verified_gt,
    generate_refuted_gt,
    validate_negatives,
    generate_patch_gt,
)
from eval.cybergym.utils import find_source_root, save_jsonl, SOURCE_EXTENSIONS
from eval.provenance import git_head, is_immutable_revision, snapshot_digest

logger = logging.getLogger(__name__)

INSTANCE_ARTIFACTS = ("patch.diff", "description.txt", "repo-vul.tar.gz")


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def scan_repo(
    repo_path: str, vuln_id: str, description: str = "",
    language_hint: str = "",
) -> dict | None:
    source_root = find_source_root(repo_path)
    if source_root is None:
        logger.warning("No src-vul/ found in %s, skipping", repo_path)
        return None

    if not description:
        desc_path = os.path.join(repo_path, "description.txt")
        if os.path.isfile(desc_path):
            try:
                with open(desc_path, encoding="utf-8", errors="replace") as handle:
                    description = handle.read(4000).strip()
            except OSError:
                description = ""

    project = os.path.basename(source_root)
    src_files: list[str] = []
    for root, _dirs, files in os.walk(source_root):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in SOURCE_EXTENSIONS:
                rel = os.path.relpath(os.path.join(root, f), source_root)
                src_files.append(rel)

    lang_files = [f for f in src_files if not f.endswith(".h")]
    detected = detect_language(lang_files[0]) if lang_files else "c"
    # Dataset metadata outranks the file-extension heuristic: repos
    # with mixed-language subdirectories (e.g. python bindings in a
    # C project) otherwise get the wrong definition patterns.
    language = language_hint or detected

    verified_gt = generate_verified_gt(source_root, language)
    func_names = [c["parameters"]["name"] for c in verified_gt
                  if c["claim_type"] == "FUNCTION_EXISTS"]
    refuted_gt = generate_refuted_gt(src_files, func_names, language)
    refuted_gt = validate_negatives(refuted_gt, source_root, language)

    patch_path = os.path.join(repo_path, "patch.diff")
    patch_gt: list[dict] = []
    if os.path.isfile(patch_path):
        patch_gt = generate_patch_gt(source_root, patch_path, language)

    all_gt = verified_gt + refuted_gt + patch_gt

    artifact_digests = {}
    for fname in INSTANCE_ARTIFACTS:
        fpath = os.path.join(repo_path, fname)
        if os.path.isfile(fpath):
            artifact_digests[fname] = _file_sha256(fpath)

    return {
        "vuln_id": vuln_id,
        "project": project,
        "description": description,
        "repo_path": os.path.abspath(repo_path),
        "source_root": os.path.abspath(source_root),
        "source_head": git_head(source_root),
        "source_digest": snapshot_digest(source_root),
        "language": language,
        "source_files": src_files[:100],
        "source_functions": func_names[:50],
        "gt_claims": all_gt,
        "patch_gt_count": len(patch_gt),
        "ground_truth_validation": "patch-derived" if patch_gt else "source-derived-unvalidated",
        "artifact_digests": artifact_digests,
    }


def build_manifest(
    cybergym_repos_dir: str,
    descriptions: dict[str, str] | None = None,
    dataset_revision: str = "",
    language_hints: dict[str, str] | None = None,
) -> list[dict]:
    if not is_immutable_revision(dataset_revision):
        raise ValueError("dataset_revision must be a 40-character commit or sha256 digest")
    manifest: list[dict] = []
    descriptions = descriptions or {}
    hints = language_hints or {}
    for entry_name in sorted(os.listdir(cybergym_repos_dir)):
        repo_path = os.path.join(cybergym_repos_dir, entry_name)
        if not os.path.isdir(repo_path):
            continue
        result = scan_repo(
            repo_path,
            entry_name,
            descriptions.get(entry_name, ""),
            hints.get(entry_name, ""),
        )
        if result:
            result["dataset_revision"] = dataset_revision
            result["manifest_schema"] = 3 if result["patch_gt_count"] else 2
            result["prepared_at"] = datetime.now(timezone.utc).isoformat()
            manifest.append(result)
        else:
            logger.warning("Skipped %s", entry_name)
    return manifest


def run_prepare(
    cybergym_repos_dir: str,
    output_path: str,
    descriptions_path: str | None = None,
    dataset_revision: str = "",
) -> None:
    if not is_immutable_revision(dataset_revision):
        raise ValueError("dataset_revision must be a 40-character commit or sha256 digest")
    descriptions: dict[str, str] = {}
    language_hints: dict[str, str] = {}
    if descriptions_path:
        from eval.cybergym.utils import load_jsonl

        for item in load_jsonl(descriptions_path):
            if not item.get("vuln_id"):
                continue
            descriptions[item["vuln_id"]] = item.get("description", "")
            if item.get("language"):
                language_hints[item["vuln_id"]] = item["language"]

    manifest = build_manifest(
        cybergym_repos_dir,
        descriptions=descriptions,
        dataset_revision=dataset_revision,
        language_hints=language_hints,
    )
    save_jsonl(manifest, output_path)
    logger.info("Manifest written: %d entries to %s", len(manifest), output_path)
