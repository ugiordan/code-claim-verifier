from __future__ import annotations

import argparse
import hashlib
import logging
import os

from eval.cybergym.utils import load_jsonl, save_jsonl
from eval.multilang.constants import CandidateStatus
from eval.provenance import git_head, snapshot_digest

logger = logging.getLogger(__name__)

_MANIFEST_FIELDS = [
    "vuln_id", "osv_id", "cve_id", "ecosystem", "package", "repo_url",
    "fix_commit", "source_root", "language", "description", "severity",
    "published_date", "source_files", "source_functions", "gt_claims",
    "build_success", "vuln_verified", "verification_method",
]

_PROVENANCE_FIELDS = ("manifest_schema", "dataset_revision", "source_digest", "source_head")


def _file_digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _provenance_for_entry(entry: dict, dataset_revision: str) -> dict:
    """Attach reproducibility metadata to one manifest entry."""
    source_root = entry.get("source_root", "")
    enriched = dict(entry)
    enriched["manifest_schema"] = 2
    enriched["dataset_revision"] = dataset_revision
    if source_root and os.path.isdir(source_root):
        enriched["source_digest"] = snapshot_digest(source_root)
        head = git_head(source_root)
        if head:
            enriched["source_head"] = head
    return enriched


def _validate_manifest_entry(candidate: dict) -> bool:
    if len(candidate.get("description", "")) < 50:
        return False
    if not candidate.get("build_success"):
        return False
    if not candidate.get("vuln_verified"):
        return False
    gt = candidate.get("gt_claims", [])
    verified_count = sum(1 for c in gt if c.get("expected_verdict") == "VERIFIED")
    refuted_count = sum(1 for c in gt if c.get("expected_verdict") == "REFUTED")
    if verified_count < 5 or refuted_count < 3:
        return False
    return True


def _select_top_cases(candidates: list[dict], per_language: int = 50) -> list[dict]:
    ready = [c for c in candidates if c.get("status") == CandidateStatus.READY]
    ready.sort(key=lambda c: (not c.get("test_success", False), c.get("osv_id", "")))

    by_lang: dict[str, list[dict]] = {}
    for c in ready:
        lang = c.get("language", "unknown")
        by_lang.setdefault(lang, []).append(c)

    selected: list[dict] = []
    for lang, cases in by_lang.items():
        selected.extend(cases[:per_language])

    return selected


def _to_manifest_entry(candidate: dict, dataset_revision: str) -> dict:
    entry = {}
    for field in _MANIFEST_FIELDS:
        if field in candidate:
            entry[field] = candidate[field]
    entry["vuln_id"] = candidate.get("osv_id", candidate.get("vuln_id", ""))
    if "container_image_tag" in candidate:
        entry["container_image"] = candidate["container_image_tag"]
    return _provenance_for_entry(entry, dataset_revision)


def build_manifest(candidates_path: str, output_path: str,
                   per_language: int = 50) -> None:
    candidates = load_jsonl(candidates_path)
    selected = _select_top_cases(candidates, per_language)
    dataset_revision = _file_digest(candidates_path)

    manifest: list[dict] = []
    for c in selected:
        if _validate_manifest_entry(c):
            manifest.append(_to_manifest_entry(c, dataset_revision))

    save_jsonl(manifest, output_path)

    by_lang: dict[str, int] = {}
    for entry in manifest:
        lang = entry.get("language", "unknown")
        by_lang[lang] = by_lang.get(lang, 0) + 1
    logger.info("Manifest written: %d entries to %s", len(manifest), output_path)
    for lang, count in sorted(by_lang.items()):
        logger.info("  %s: %d", lang, count)


def enrich_manifest(manifest_path: str, output_path: str | None = None) -> int:
    """Add provenance fields to an existing manifest, in place and idempotent.

    dataset_revision is the digest of the pre-enrichment manifest bytes, so it
    stays stable across repeated runs. Entries that already carry a
    dataset_revision keep it.
    """
    with open(manifest_path, "rb") as stream:
        raw = stream.read()
    manifest = load_jsonl(manifest_path)
    if not manifest:
        return 0

    existing_revisions = {
        entry.get("dataset_revision") for entry in manifest
        if entry.get("dataset_revision")
    }
    if len(existing_revisions) == 1:
        dataset_revision = next(iter(existing_revisions))
    else:
        dataset_revision = "sha256:" + hashlib.sha256(raw).hexdigest()

    enriched = 0
    for i, entry in enumerate(manifest):
        if all(entry.get(field) for field in _PROVENANCE_FIELDS):
            continue
        manifest[i] = _provenance_for_entry(entry, dataset_revision)
        enriched += 1

    if enriched:
        save_jsonl(manifest, output_path or manifest_path)
    logger.info(
        "Manifest enriched: %d/%d entries updated (dataset_revision=%s)",
        enriched, len(manifest), dataset_revision[:19] + "...",
    )
    return enriched


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="PolyVuln manifest build and enrichment")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_build = subparsers.add_parser("build", help="Build manifest from candidates")
    p_build.add_argument("--candidates", default="eval/multilang/candidates.jsonl")
    p_build.add_argument("--output", default="eval/multilang/manifest.jsonl")
    p_build.add_argument("--per-language", type=int, default=50)

    p_enrich = subparsers.add_parser(
        "enrich", help="Add provenance fields to an existing manifest (idempotent)"
    )
    p_enrich.add_argument("--manifest", default="eval/multilang/manifest.jsonl")
    p_enrich.add_argument("--output", default=None,
                          help="Write elsewhere instead of updating in place")

    args = parser.parse_args()
    if args.command == "build":
        build_manifest(args.candidates, args.output, args.per_language)
    else:
        enrich_manifest(args.manifest, args.output)


if __name__ == "__main__":
    main()
