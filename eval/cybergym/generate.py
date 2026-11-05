from __future__ import annotations

import logging
import os
import time

from eval.cybergym.models import get_model, get_model_provenance
from eval.cybergym.prompts import build_reasoning_prompt
from eval.cybergym.utils import load_jsonl, load_json, save_json, SOURCE_EXTENSIONS
from eval.provenance import snapshot_digest, text_digest

logger = logging.getLogger(__name__)


def _read_source_context(source_root: str, max_chars: int = 32000) -> str:
    chunks: list[str] = []
    total = 0
    for root, _dirs, files in os.walk(source_root):
        for f in sorted(files):
            ext = os.path.splitext(f)[1].lower()
            if ext not in SOURCE_EXTENSIONS:
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, source_root)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read(8000)
                chunk = f"\n--- {rel} ---\n{content}"
                if total + len(chunk) > max_chars:
                    return "".join(chunks)
                chunks.append(chunk)
                total += len(chunk)
            except OSError:
                continue
    return "".join(chunks)


def generate_one(entry: dict, model_name: str, condition: str,
                 output_dir: str) -> dict | None:
    vuln_id = entry["vuln_id"]
    out_path = os.path.join(output_dir, model_name, condition, f"{vuln_id}.json")

    source_root = entry.get("source_root", "")
    expected_source_digest = entry.get("source_digest", "")
    if not expected_source_digest or snapshot_digest(source_root) != expected_source_digest:
        logger.error("Skipping %s: source snapshot does not match the manifest", vuln_id)
        return None

    system = build_reasoning_prompt(
        condition=condition,
        language=entry.get("language", "c"),
        project=entry.get("project", "unknown"),
        description=entry.get("description", ""),
    )
    source_context = _read_source_context(source_root)
    user = f"Source code:\n{source_context}\n\nProvide your analysis."
    provenance = {
        "manifest_schema": entry.get("manifest_schema"),
        "dataset_revision": entry.get("dataset_revision"),
        "source_digest": expected_source_digest,
        "system_prompt_digest": text_digest(system),
        "user_prompt_digest": text_digest(user),
        "reasoning_version": "cybergym-reasoning-v1",
        **get_model_provenance(model_name),
    }

    existing = load_json(out_path)
    if existing is not None and existing.get("provenance") == provenance:
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
    for i, entry in enumerate(manifest):
        result = generate_one(entry, model_name, condition, output_dir)
        if result:
            success += 1
        if (i + 1) % 10 == 0:
            logger.info("Progress: %d/%d (success: %d)", i + 1, len(manifest), success)

    logger.info("Done: %d/%d succeeded", success, len(manifest))
