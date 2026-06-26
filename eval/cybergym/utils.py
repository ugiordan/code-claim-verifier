from __future__ import annotations

import json
import logging
import os
import posixpath

logger = logging.getLogger(__name__)


def load_jsonl(path: str) -> list[dict]:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def save_jsonl(records: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")


def load_json(path: str) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_json(data: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def normalize_claim_path(path: str) -> str:
    path = path.lstrip("/")
    return posixpath.normpath(path)


def find_source_root(repo_path: str) -> str | None:
    src_vul = os.path.join(repo_path, "src-vul")
    if not os.path.isdir(src_vul):
        return None
    entries = [e for e in os.listdir(src_vul)
               if os.path.isdir(os.path.join(src_vul, e))]
    if len(entries) == 1:
        return os.path.join(src_vul, entries[0])
    for e in entries:
        if e not in ("__pycache__", ".git"):
            return os.path.join(src_vul, e)
    return None
