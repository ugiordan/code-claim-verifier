#!/usr/bin/env python3
"""Run CCV evaluation on Multi-SWE-bench instances.

Generates LLM reasoning about each bug, extracts claims, verifies
deterministically. Uses the same verify_one flow as CyberGym eval.

Usage:
    python eval/multiswe/run_eval.py --manifest eval/multiswe/manifest.jsonl --model granite-3.3-8b
    python eval/multiswe/run_eval.py --manifest eval/multiswe/manifest.jsonl --model claude-sonnet-4 --languages go,rust
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from code_claim_verifier.security import safe_path
from eval.cybergym.utils import load_jsonl, save_json
from eval.cybergym.models import get_model, get_model_provenance
from eval.cybergym.prompts import build_reasoning_prompt
from eval.cybergym.verify import verify_one
from eval.provenance import git_head, git_is_clean, snapshot_digest, text_digest

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")
logger = logging.getLogger(__name__)

REASONING_DIR = "eval/multiswe/reasoning"
RESULTS_DIR = "eval/multiswe/results"
EXTRACTION_LLM = "claude-sonnet-4"


def _base_revision_matches(entry: dict) -> bool:
    expected = entry.get("base_sha", "")
    actual = git_head(entry.get("source_root", ""))
    return bool(
        expected and actual and actual.startswith(expected[:12])
        and git_is_clean(entry.get("source_root", ""))
    )


def _source_snapshot_matches(entry: dict) -> bool:
    expected = entry.get("source_digest", "")
    actual = snapshot_digest(entry.get("source_root", ""))
    return bool(expected and actual == expected)


def generate_reasoning(
    entry: dict,
    model_name: str,
    include_patch_files: bool = False,
) -> dict | None:
    """Generate LLM reasoning about a bug."""
    vid = entry["vuln_id"]
    out_path = os.path.join(REASONING_DIR, model_name, "informed", f"{vid}.json")

    if not _source_snapshot_matches(entry):
        logger.error("Skipping %s: source snapshot does not match the manifest", vid)
        return None

    system = build_reasoning_prompt(
        condition="informed",
        language=entry.get("language", "unknown"),
        project=entry.get("project", "unknown"),
        description=entry.get("description", ""),
    )

    source_root = entry["source_root"]
    patch_files = entry.get("fix_patch_files", []) if include_patch_files else []
    source_context = _read_source_context(source_root, patch_files)
    user = f"Source code:\n{source_context}\n\nProvide your analysis."
    provenance = {
        "manifest_schema": entry.get("manifest_schema"),
        "dataset_revision": entry.get("dataset_revision"),
        "base_sha": entry.get("base_sha"),
        "source_digest": entry.get("source_digest"),
        "source_head": git_head(source_root),
        "system_prompt_digest": text_digest(system),
        "user_prompt_digest": text_digest(user),
        "reasoning_version": "multiswe-reasoning-v1",
        "include_patch_files": include_patch_files,
        **get_model_provenance(model_name),
    }

    if os.path.isfile(out_path):
        with open(out_path) as f:
            existing = json.load(f)
        if existing.get("provenance") == provenance:
            return existing

    llm = get_model(model_name)

    try:
        reasoning = llm(system, user)
    except Exception as e:
        logger.error("Failed %s/%s: %s", model_name, vid, e)
        return None

    result = {
        "vuln_id": vid,
        "model": model_name,
        "condition": "informed",
        "reasoning": reasoning,
        "reasoning_length": len(reasoning),
        "provenance": provenance,
    }

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    save_json(result, out_path)
    return result


def _read_source_context(source_root: str, patch_files: list[str],
                          max_chars: int = 15000) -> str:
    """Read source files, prioritizing files from the fix patch."""
    parts = []
    total = 0

    for rel_path in patch_files:
        full_path = safe_path(rel_path, source_root)
        if full_path and os.path.isfile(full_path):
            try:
                with open(full_path, errors="replace") as f:
                    content = f.read(5000)
                parts.append(f"=== {rel_path} ===\n{content}")
                total += len(content)
                if total >= max_chars:
                    break
            except Exception:
                pass

    if total < max_chars:
        for root, dirs, files in os.walk(source_root):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor", "target", "build", "__pycache__")]
            for fname in sorted(files)[:20]:
                if total >= max_chars:
                    break
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, source_root)
                if rel_path in [p for p, _ in [(p, None) for p in patch_files]]:
                    continue
                if not any(fname.endswith(ext) for ext in (".c", ".h", ".go", ".py", ".java", ".kt", ".rs", ".js", ".ts", ".tsx")):
                    continue
                try:
                    with open(full_path, errors="replace") as f:
                        content = f.read(3000)
                    parts.append(f"=== {rel_path} ===\n{content}")
                    total += len(content)
                except Exception:
                    pass

    return "\n\n".join(parts)[:max_chars]


def main():
    parser = argparse.ArgumentParser(description="Run CCV on Multi-SWE-bench")
    parser.add_argument("--manifest", required=True, help="Path to manifest.jsonl")
    parser.add_argument("--model", required=True, help="Model to generate reasoning")
    parser.add_argument("--languages", default="", help="Filter by languages (comma-separated)")
    parser.add_argument("--extraction-llm", default=EXTRACTION_LLM, help="LLM for claim extraction")
    parser.add_argument("--max", type=int, default=0, help="Max instances to process")
    parser.add_argument(
        "--include-patch-files",
        action="store_true",
        help="Include files changed by the fix patch; disabled for leakage-free evaluation",
    )
    args = parser.parse_args()

    manifest = load_jsonl(args.manifest)
    if args.languages:
        langs = {language.strip() for language in args.languages.split(",")}
        manifest = [e for e in manifest if e.get("language") in langs]
    if args.max > 0:
        manifest = manifest[:args.max]

    print(f"Manifest: {len(manifest)} instances, Model: {args.model}", flush=True)

    start = time.time()
    ok = fail = 0

    for i, entry in enumerate(manifest):
        vid = entry["vuln_id"]

        if not _base_revision_matches(entry):
            logger.error("Skipping %s: checkout does not match base_sha", vid)
            fail += 1
            continue
        if not _source_snapshot_matches(entry):
            logger.error("Skipping %s: checkout does not match source_digest", vid)
            fail += 1
            continue

        reasoning_result = generate_reasoning(
            entry,
            args.model,
            include_patch_files=args.include_patch_files,
        )
        if not reasoning_result:
            fail += 1
            continue

        reasoning_path = os.path.join(REASONING_DIR, args.model, "informed", f"{vid}.json")
        result = verify_one(entry, reasoning_path, RESULTS_DIR, extraction_llm=args.extraction_llm)

        if result and result.get("ccv", {}).get("total_claims", 0) > 0:
            ok += 1
        else:
            fail += 1

        if (i + 1) % 20 == 0:
            elapsed = (time.time() - start) / 60
            print(f"  {args.model}: {i+1}/{len(manifest)} [{elapsed:.0f}m] ({ok} ok, {fail} fail)", flush=True)

    elapsed = (time.time() - start) / 60
    print(f"=== {args.model}: {ok} ok, {fail} failed [{elapsed:.1f}m] ===", flush=True)


if __name__ == "__main__":
    main()
