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

from eval.cybergym.utils import load_jsonl, save_json
from eval.cybergym.models import get_model
from eval.cybergym.prompts import build_reasoning_prompt
from eval.cybergym.verify import verify_one

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")
logger = logging.getLogger(__name__)

REASONING_DIR = "eval/multiswe/reasoning"
RESULTS_DIR = "eval/multiswe/results"
EXTRACTION_LLM = "claude-sonnet-4"


def generate_reasoning(entry: dict, model_name: str) -> dict | None:
    """Generate LLM reasoning about a bug."""
    vid = entry["vuln_id"]
    out_path = os.path.join(REASONING_DIR, model_name, "informed", f"{vid}.json")

    if os.path.isfile(out_path):
        with open(out_path) as f:
            return json.load(f)

    llm = get_model(model_name)
    system = build_reasoning_prompt(
        condition="informed",
        language=entry.get("language", "unknown"),
        project=entry.get("project", "unknown"),
        description=entry.get("description", ""),
    )

    source_root = entry["source_root"]
    source_context = _read_source_context(source_root, entry.get("fix_patch_files", []))
    user = f"Source code:\n{source_context}\n\nProvide your analysis."

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
        full_path = os.path.join(source_root, rel_path)
        if os.path.isfile(full_path):
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
    args = parser.parse_args()

    manifest = load_jsonl(args.manifest)
    if args.languages:
        langs = {l.strip() for l in args.languages.split(",")}
        manifest = [e for e in manifest if e.get("language") in langs]
    if args.max > 0:
        manifest = manifest[:args.max]

    print(f"Manifest: {len(manifest)} instances, Model: {args.model}", flush=True)

    start = time.time()
    ok = fail = 0

    for i, entry in enumerate(manifest):
        vid = entry["vuln_id"]

        reasoning_result = generate_reasoning(entry, args.model)
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
