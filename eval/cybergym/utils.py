from __future__ import annotations

import json
import logging
import os
import posixpath
import tempfile

logger = logging.getLogger(__name__)

SOURCE_EXTENSIONS = frozenset(
    (".c", ".cpp", ".h", ".py", ".go", ".ts", ".js", ".java", ".rs")
)


def load_jsonl(path: str) -> list[dict]:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def save_jsonl(records: list[dict], path: str) -> None:
    dest_dir = os.path.dirname(path) or "."
    os.makedirs(dest_dir, exist_ok=True)
    fd = tempfile.NamedTemporaryFile(
        mode="w", dir=dest_dir, suffix=".tmp", delete=False,
    )
    try:
        for r in records:
            fd.write(json.dumps(r, default=str) + "\n")
        fd.flush()
        os.fsync(fd.fileno())
        fd.close()
        os.replace(fd.name, path)
    except BaseException:
        fd.close()
        try:
            os.unlink(fd.name)
        except OSError:
            pass
        raise


def load_json(path: str) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_json(data: dict, path: str) -> None:
    dest_dir = os.path.dirname(path) or "."
    os.makedirs(dest_dir, exist_ok=True)
    fd = tempfile.NamedTemporaryFile(
        mode="w", dir=dest_dir, suffix=".tmp", delete=False,
    )
    try:
        json.dump(data, fd, indent=2, default=str)
        fd.flush()
        os.fsync(fd.fileno())
        fd.close()
        os.replace(fd.name, path)
    except BaseException:
        fd.close()
        try:
            os.unlink(fd.name)
        except OSError:
            pass
        raise


def normalize_claim_path(path: str) -> str:
    path = path.lstrip("/")
    result = posixpath.normpath(path)
    if ".." in result.split("/"):
        return path.lstrip("/")
    return result


def find_source_root(repo_path: str) -> str | None:
    src_vul = os.path.join(repo_path, "src-vul")
    if not os.path.isdir(src_vul):
        return None
    _exclude = {"__pycache__", ".git", "__MACOSX"}
    entries = sorted(
        e for e in os.listdir(src_vul)
        if os.path.isdir(os.path.join(src_vul, e))
        and e not in _exclude
        and not e.startswith(".")
    )
    if not entries:
        return None
    return os.path.join(src_vul, entries[0])
