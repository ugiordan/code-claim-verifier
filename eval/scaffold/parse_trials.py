#!/usr/bin/env python3
"""Parse scaffold-effects trial logs into unified format for CCV verification.

Reads trajectory.json from each trial, extracts agent reasoning text
using harness-specific parsing, and outputs a unified JSONL.

Usage:
    python eval/scaffold/parse_trials.py --scaffold-repo /tmp/scaffold-effects
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

SCAFFOLD_REPO = os.environ.get("SCAFFOLD_REPO", "/tmp/scaffold-effects")


def _extract_opencode_reasoning(trajectory: dict) -> str:
    """OpenCode: structured steps with message + tool_calls."""
    parts = []
    for step in trajectory.get("steps", []):
        if step.get("source") != "agent":
            continue
        msg = step.get("message", "")
        if msg and msg != "(tool use)":
            parts.append(msg)
        for tc in step.get("tool_calls", []):
            args = tc.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    pass
            if isinstance(args, dict):
                cmd = args.get("command", "")
                if cmd:
                    parts.append(f"[runs: {cmd[:200]}]")
    return "\n".join(parts)


def _extract_goose_reasoning(trajectory: dict) -> str:
    """Goose: single giant step with streaming log. Content is streamed
    token-by-token as JSON chunks with type=thinking and type=text."""
    steps = trajectory.get("steps", [])
    if not steps:
        return ""
    msg = steps[0].get("message", "")

    thinking_chunks = []
    for m in re.finditer(r'"thinking":"((?:[^"\\]|\\.)*)"', msg):
        thinking_chunks.append(m.group(1))
    thinking = "".join(thinking_chunks)

    text_chunks = []
    for m in re.finditer(r'"type":"text","text":"((?:[^"\\]|\\.)*)"', msg):
        text_chunks.append(m.group(1))
    text = "".join(text_chunks)

    combined = thinking + "\n" + text if thinking else text
    combined = combined.replace("\\n", "\n").replace('\\"', '"')
    return combined[:15000]


def _extract_openhands_reasoning(trajectory: dict, raw_log_path: str = "") -> str:
    """OpenHands-SDK: tool calls in trajectory, reasoning in raw log."""
    parts = []
    for step in trajectory.get("steps", []):
        if step.get("source") != "agent":
            continue
        msg = step.get("message", "")
        if msg:
            parts.append(msg)
        for tc in step.get("tool_calls", []):
            fn = tc.get("function_name", "")
            args = tc.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    pass
            if fn == "bash" and isinstance(args, dict):
                cmd = args.get("command", "")
                if cmd:
                    parts.append(f"[runs: {cmd[:200]}]")
            elif fn == "file_editor" and isinstance(args, dict):
                path = args.get("path", "")
                if path:
                    parts.append(f"[edits: {path}]")
        obs = step.get("observation", "")
        if obs and len(obs) > 50:
            parts.append(obs[:500])

    if not parts and raw_log_path and os.path.isfile(raw_log_path):
        with open(raw_log_path, errors="replace") as f:
            parts.append(f.read()[:15000])

    return "\n".join(parts)[:15000]


def parse_all_trials(scaffold_repo: str) -> list[dict]:
    """Parse all 300 trials into unified format."""
    snapshots_dir = os.path.join(scaffold_repo, "analysis", "snapshots")
    trials_data = []

    for snapshot_dir in sorted(os.listdir(snapshots_dir)):
        trials_path = os.path.join(snapshots_dir, snapshot_dir, "trials.jsonl")
        if not os.path.isfile(trials_path):
            continue
        with open(trials_path) as f:
            for line in f:
                trial = json.loads(line)
                trials_data.append(trial)

    logger.info("Loaded %d trial records from snapshots", len(trials_data))

    results_dir = os.path.join(scaffold_repo, "results")
    task_repos_dir = os.path.join(scaffold_repo, "terminal-bench-pro-selected-subset")

    parsed = []
    for trial in trials_data:
        task_name = trial.get("task_name", "").replace("terminal-bench-pro/", "")
        harness = trial.get("harness", "")
        model = trial.get("model_name", "")
        trial_dir_name = trial.get("trial_dir", "")

        traj_path = os.path.join(scaffold_repo, trial_dir_name, "agent", "trajectory.json")
        if not os.path.isfile(traj_path):
            traj_path = _find_trajectory(results_dir, harness, model, trial_dir_name, task_name)
        if not traj_path:
            continue

        try:
            with open(traj_path) as f:
                trajectory = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        if harness == "opencode":
            reasoning = _extract_opencode_reasoning(trajectory)
        elif harness == "goose":
            reasoning = _extract_goose_reasoning(trajectory)
        elif harness in ("openhands-sdk", "openhands_sdk"):
            raw_log = traj_path.replace("trajectory.json", "openhands_sdk.txt")
            reasoning = _extract_openhands_reasoning(trajectory, raw_log)
        else:
            reasoning = ""

        task_repo = os.path.join(task_repos_dir, task_name)

        parsed.append({
            "trial_id": trial.get("trial_id", f"{harness}_{model}_{task_name}"),
            "task_name": task_name,
            "harness": harness,
            "model": model,
            "reasoning": reasoning,
            "reasoning_length": len(reasoning),
            "solved": trial.get("solved", False),
            "tokens_total": trial.get("tokens_total", 0),
            "turns_used": trial.get("turns_used", 0),
            "failure_category": trial.get("failure_category", ""),
            "source_root": task_repo if os.path.isdir(task_repo) else "",
        })

    return parsed


def _find_trajectory(results_dir: str, harness: str, model: str, trial_dir: str, task_name: str) -> str | None:
    """Find trajectory.json for a trial by searching the results tree."""
    for provider_dir in os.listdir(results_dir):
        harness_dir = os.path.join(results_dir, provider_dir, harness)
        if not os.path.isdir(harness_dir):
            harness_alt = harness.replace("-", "_")
            harness_dir = os.path.join(results_dir, provider_dir, harness_alt)
            if not os.path.isdir(harness_dir):
                continue

        for run_dir in os.listdir(harness_dir):
            full_run = os.path.join(harness_dir, run_dir)
            if not os.path.isdir(full_run):
                continue

            if trial_dir:
                traj = os.path.join(full_run, trial_dir, "agent", "trajectory.json")
                if os.path.isfile(traj):
                    return traj

            for td in os.listdir(full_run):
                if task_name.replace("-", "") in td.replace("-", ""):
                    traj = os.path.join(full_run, td, "agent", "trajectory.json")
                    if os.path.isfile(traj):
                        return traj

    return None


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--scaffold-repo", default=SCAFFOLD_REPO)
    parser.add_argument("--output", default="eval/scaffold/trials.jsonl")
    args = parser.parse_args()

    parsed = parse_all_trials(args.scaffold_repo)
    logger.info("Parsed %d trials", len(parsed))

    with_reasoning = sum(1 for p in parsed if p["reasoning"])
    logger.info("With reasoning: %d/%d", with_reasoning, len(parsed))

    by_harness = {}
    for p in parsed:
        h = p["harness"]
        by_harness.setdefault(h, {"total": 0, "with_reasoning": 0, "avg_len": 0})
        by_harness[h]["total"] += 1
        if p["reasoning"]:
            by_harness[h]["with_reasoning"] += 1
            by_harness[h]["avg_len"] += p["reasoning_length"]

    for h, s in sorted(by_harness.items()):
        avg = s["avg_len"] / s["with_reasoning"] if s["with_reasoning"] > 0 else 0
        logger.info("  %s: %d/%d with reasoning, avg %d chars",
                     h, s["with_reasoning"], s["total"], avg)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        for p in parsed:
            f.write(json.dumps(p) + "\n")

    logger.info("Written to %s", args.output)


if __name__ == "__main__":
    main()
