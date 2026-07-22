from __future__ import annotations

import logging

from eval.cybergym.utils import load_jsonl, save_jsonl
from eval.multilang.constants import CandidateStatus, ECOSYSTEM_TO_LANG

logger = logging.getLogger(__name__)

_MANIFEST_FIELDS = [
    "vuln_id", "osv_id", "cve_id", "ecosystem", "package", "repo_url",
    "fix_commit", "source_root", "language", "description", "severity",
    "published_date", "source_files", "source_functions", "gt_claims",
    "build_success", "vuln_verified", "verification_method",
]


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


def _to_manifest_entry(candidate: dict) -> dict:
    entry = {}
    for field in _MANIFEST_FIELDS:
        if field in candidate:
            entry[field] = candidate[field]
    entry["vuln_id"] = candidate.get("osv_id", candidate.get("vuln_id", ""))
    if "container_image_tag" in candidate:
        entry["container_image"] = candidate["container_image_tag"]
    return entry


def build_manifest(candidates_path: str, output_path: str,
                   per_language: int = 50) -> None:
    candidates = load_jsonl(candidates_path)
    selected = _select_top_cases(candidates, per_language)

    manifest: list[dict] = []
    for c in selected:
        if _validate_manifest_entry(c):
            manifest.append(_to_manifest_entry(c))

    save_jsonl(manifest, output_path)

    by_lang: dict[str, int] = {}
    for entry in manifest:
        lang = entry.get("language", "unknown")
        by_lang[lang] = by_lang.get(lang, 0) + 1
    logger.info("Manifest written: %d entries to %s", len(manifest), output_path)
    for lang, count in sorted(by_lang.items()):
        logger.info("  %s: %d", lang, count)
