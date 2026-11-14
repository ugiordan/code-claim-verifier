"""Selective fetch of the CyberGym dataset (sunblaze-ucb) from HuggingFace.

The full dataset ships 1,507 repo snapshots and does not fit a
workstation's free space; the benchmark needs a stratified subset.
This module downloads only the per-instance artifacts the CCV
pipeline consumes: the pre-patch repo tarball, the vulnerability
description, and the fix patch. The patch is the ground-truth
adjudication source, independent of CCV's matchers; repo-fix.tar.gz
is skipped because PoC validation is not part of this benchmark.

Instances land in immutable per-instance directories named
``<project>-arvo-<id>`` containing ``src-vul/`` plus the three
artifacts, so the existing prepare stage scans them unchanged.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import shutil
import tarfile

from eval.cybergym.utils import save_jsonl
from eval.provenance import is_immutable_revision

logger = logging.getLogger(__name__)

DATASET_REPO = "sunblaze-ucb/cybergym"
PINNED_REVISION = "bde190ded494e52bc684b66073b436c9d992c7c6"
INSTANCE_FILES = ("repo-vul.tar.gz", "description.txt", "patch.diff")
DEFAULT_SAMPLE_COUNT = 200
DEFAULT_MAX_PER_PROJECT = 5
DEFAULT_SEED = 20261111

LANGUAGE_MAP = {
    "c": "c",
    "c++": "cpp",
    "rust": "rust",
    "swift": "swift",
}


def download_tasks(revision: str = PINNED_REVISION) -> list[dict]:
    """Fetch tasks.json at a pinned, immutable dataset revision."""
    if not is_immutable_revision(revision):
        raise ValueError("revision must be a 40-character commit or sha256 digest")
    from huggingface_hub import hf_hub_download

    local = hf_hub_download(
        DATASET_REPO, "tasks.json", repo_type="dataset", revision=revision,
    )
    with open(local) as handle:
        tasks = json.load(handle)
    logger.info("Downloaded %d CyberGym tasks at revision %s", len(tasks), revision)
    return tasks


def stratified_sample(
    tasks: list[dict],
    count: int = DEFAULT_SAMPLE_COUNT,
    max_per_project: int = DEFAULT_MAX_PER_PROJECT,
    seed: int = DEFAULT_SEED,
) -> list[dict]:
    """Deterministically sample tasks with a per-project cap.

    The task order is shuffled with a fixed seed before selection so
    the sample does not favor lexicographically early ARVO ids; the
    result is fully reproducible for a given seed.
    """
    rng = random.Random(seed)
    ordered = sorted(tasks, key=lambda task: task.get("task_id", ""))
    rng.shuffle(ordered)
    selected: list[dict] = []
    per_project: dict[str, int] = {}
    for task in ordered:
        project = task.get("project_name", "")
        if per_project.get(project, 0) >= max_per_project:
            continue
        selected.append(task)
        per_project[project] = per_project.get(project, 0) + 1
        if len(selected) >= count:
            break
    return selected


def _safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    """Extract a tarball rejecting path traversal, skipping unsafe links.

    Symlinks and hardlinks are legitimate repo content (test fixtures,
    man pages) and are allowed when their targets resolve inside the
    extraction destination. Absolute or escaping targets (build
    scripts pointing at system paths) cannot be materialized safely
    and are skipped rather than failing the whole instance.
    """
    dest_real = os.path.realpath(dest)
    safe_members = []
    for member in tar.getmembers():
        target = os.path.realpath(os.path.join(dest, member.name))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            raise ValueError(f"unsafe path in tarball: {member.name!r}")
        if member.issym() or member.islnk():
            link = member.linkname or ""
            # Symlink targets resolve against the link's directory;
            # hardlink targets are archive-root relative.
            base = (
                os.path.dirname(os.path.join(dest, member.name))
                if member.issym() else dest
            )
            resolved = os.path.realpath(os.path.join(base, link))
            if os.path.isabs(link) or (
                resolved != dest_real and not resolved.startswith(dest_real + os.sep)
            ):
                logger.warning("skipping unsafe link %r -> %r", member.name, link)
                continue
        safe_members.append(member)
    try:
        tar.extractall(dest, members=safe_members, filter="data")
    except TypeError:
        # Without the data filter, link chains created during
        # extraction can escape the destination; only plain files,
        # whose names preflight validated, are safe to extract.
        if any(m.issym() or m.islnk() for m in safe_members):
            raise ValueError(
                "tarball contains link members and this Python lacks "
                "the tar extraction filter"
            )
        tar.extractall(dest, members=safe_members)


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _instance_dir(dest_root: str, task: dict) -> tuple[str, str, str, str]:
    task_id = task.get("task_id", "")
    if ":" not in task_id:
        raise ValueError(f"malformed task_id: {task_id!r}")
    prefix, arvo_id = task_id.split(":", 1)
    project = re.sub(r"[^A-Za-z0-9._-]+", "-", task.get("project_name", "unknown"))
    return (
        os.path.join(dest_root, f"{project}-{prefix}-{arvo_id}"),
        project,
        arvo_id,
        prefix,
    )


def fetch_instance(
    task: dict, dest_root: str, revision: str = PINNED_REVISION,
) -> dict | None:
    """Download and unpack one benchmark instance.

    Idempotent: an instance directory that already contains src-vul/
    is not re-downloaded, but digests are always recomputed so the
    returned record reflects the on-disk artifacts.
    """
    inst_dir, project, arvo_id, prefix = _instance_dir(dest_root, task)
    receipt_path = os.path.join(inst_dir, ".fetch-receipt")
    try:
        os.makedirs(inst_dir, exist_ok=True)
        receipt_ok = False
        if os.path.isfile(receipt_path):
            try:
                with open(receipt_path, encoding="utf-8") as handle:
                    receipt_ok = handle.read().strip() == revision
            except OSError:
                receipt_ok = False
        if not receipt_ok:
            # No completion receipt, or one from a different dataset
            # revision: the directory may hold partial artifacts, so
            # re-fetch from scratch.
            shutil.rmtree(inst_dir, ignore_errors=True)
            os.makedirs(inst_dir, exist_ok=True)
        if not os.path.isfile(receipt_path):
            from huggingface_hub import hf_hub_download

            for fname in INSTANCE_FILES:
                local = hf_hub_download(
                    DATASET_REPO,
                    f"data/{prefix}/{arvo_id}/{fname}",
                    repo_type="dataset",
                    revision=revision,
                )
                shutil.copyfile(local, os.path.join(inst_dir, fname))
            with tarfile.open(os.path.join(inst_dir, "repo-vul.tar.gz")) as tar:
                _safe_extract(tar, inst_dir)
            with open(receipt_path, "w", encoding="utf-8") as handle:
                handle.write(revision)
    except (OSError, ValueError, tarfile.TarError) as exc:
        # Remove the partial instance so a re-run retries it instead of
        # mistaking a half-extracted src-vul/ for a complete one.
        shutil.rmtree(inst_dir, ignore_errors=True)
        logger.warning("Fetch failed for %s: %s", task.get("task_id"), exc)
        return None

    description = ""
    desc_path = os.path.join(inst_dir, "description.txt")
    if os.path.isfile(desc_path):
        try:
            with open(desc_path, encoding="utf-8", errors="replace") as handle:
                description = handle.read(4000).strip()
        except OSError:
            description = ""

    digests = {}
    for fname in INSTANCE_FILES:
        fpath = os.path.join(inst_dir, fname)
        if os.path.isfile(fpath):
            digests[fname] = _sha256(fpath)

    return {
        "vuln_id": os.path.basename(inst_dir),
        "project": project,
        "task_id": task.get("task_id", ""),
        "description": description,
        "language": LANGUAGE_MAP.get(task.get("project_language", ""), "c"),
        "instance_dir": os.path.abspath(inst_dir),
        "artifact_digests": digests,
        "dataset_revision": revision,
    }


def run_fetch(
    dest_root: str,
    revision: str = PINNED_REVISION,
    count: int = DEFAULT_SAMPLE_COUNT,
    max_per_project: int = DEFAULT_MAX_PER_PROJECT,
    seed: int = DEFAULT_SEED,
    output_path: str | None = None,
) -> list[dict]:
    """Fetch a stratified sample of instances and record provenance."""
    if not is_immutable_revision(revision):
        raise ValueError("revision must be a 40-character commit or sha256 digest")
    os.makedirs(dest_root, exist_ok=True)
    tasks = download_tasks(revision)
    selected = stratified_sample(tasks, count, max_per_project, seed)
    logger.info("Fetching %d of %d tasks", len(selected), len(tasks))

    records: list[dict] = []
    for index, task in enumerate(selected, 1):
        record = fetch_instance(task, dest_root, revision)
        if record is None:
            continue
        records.append(record)
        if index % 10 == 0:
            logger.info("Fetched %d/%d", index, len(selected))

    if output_path is None:
        output_path = os.path.join(dest_root, "fetch-manifest.jsonl")
    save_jsonl(records, output_path)
    logger.info("Fetch manifest written: %d entries to %s", len(records), output_path)
    return records
