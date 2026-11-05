from __future__ import annotations

import logging
import os
import time

from eval.cybergym.generate import _read_source_context
from eval.cybergym.models import get_model, get_model_provenance
from eval.cybergym.prompts import build_reasoning_prompt
from eval.cybergym.utils import load_jsonl, load_json, save_json
from eval.provenance import snapshot_digest, text_digest

logger = logging.getLogger(__name__)


def _extract_project(entry: dict) -> str:
    url = entry.get("repo_url", "")
    if url:
        return url.rstrip("/").rsplit("/", 1)[-1]
    return entry.get("package", "unknown")


def generate_one(entry: dict, model_name: str, condition: str,
                 output_dir: str) -> dict | None:
    vuln_id = entry["vuln_id"]
    out_path = os.path.join(output_dir, model_name, condition, f"{vuln_id}.json")

    existing = load_json(out_path)
    if existing is not None:
        return existing

    source_root = entry.get("source_root", "")
    if source_root and not os.path.isabs(source_root):
        source_root = os.path.abspath(source_root)

    if not source_root or not os.path.isdir(source_root):
        logger.error("Missing source_root for %s: %s", vuln_id, source_root)
        return None

    project = _extract_project(entry)
    system = build_reasoning_prompt(
        condition=condition,
        language=entry.get("language", "unknown"),
        project=project,
        description=entry.get("description", ""),
    )
    source_context = _read_source_context(source_root)
    if not source_context.strip():
        logger.warning("Empty source context for %s at %s", vuln_id, source_root)

    user = f"Source code:\n{source_context}\n\nProvide your analysis."

    expected_source_digest = entry.get("source_digest", "")
    if expected_source_digest and snapshot_digest(source_root) != expected_source_digest:
        logger.error("Skipping %s: source snapshot does not match the manifest", vuln_id)
        return None

    provenance = {
        "manifest_schema": entry.get("manifest_schema"),
        "dataset_revision": entry.get("dataset_revision"),
        "source_digest": expected_source_digest,
        "system_prompt_digest": text_digest(system),
        "user_prompt_digest": text_digest(user),
        "reasoning_version": "multilang-reasoning-v1",
        **get_model_provenance(model_name),
    }

    existing = load_json(out_path)
    # Legacy reasoning files (pre-provenance) are kept as-is; verify tolerates
    # a missing reasoning provenance block.
    if existing is not None and (
        existing.get("provenance") == provenance or "provenance" not in existing
    ):
        return existing

    llm = get_model(model_name)

    start = time.time()
    try:
        reasoning = llm(system, user)
    except Exception as e:
        logger.error("Failed %s/%s/%s: %s", model_name, condition, vuln_id, e)
        return None
    duration = time.time() - start

    result = {
        "vuln_id": vuln_id,
        "model": model_name,
        "condition": condition,
        "reasoning": reasoning,
        "reasoning_length": len(reasoning),
        "source_chars": len(source_context),
        "duration_s": round(duration, 2),
        "provenance": provenance,
    }
    save_json(result, out_path)
    return result


def run_generate(manifest_path: str, model_name: str, condition: str,
                 output_dir: str) -> None:
    manifest = load_jsonl(manifest_path)
    logger.info("Generating reasoning for %d vulns with %s/%s",
                len(manifest), model_name, condition)

    success = 0
    empty_source = 0
    for i, entry in enumerate(manifest):
        result = generate_one(entry, model_name, condition, output_dir)
        if result:
            success += 1
            if result.get("source_chars", 0) == 0:
                empty_source += 1
        if (i + 1) % 10 == 0:
            logger.info("Progress: %d/%d (success: %d, empty_source: %d)",
                        i + 1, len(manifest), success, empty_source)

    logger.info("Done: %d/%d succeeded (%d with empty source context)",
                success, len(manifest), empty_source)
