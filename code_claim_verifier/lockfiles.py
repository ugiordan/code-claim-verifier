"""Lockfile discovery, parsing, and build-path filtering for dependency claims.

Evidence rules (mirroring cve-automation's triage reference):

- The lockfile must be tied to the shipped artifact. When a Dockerfile or
  Containerfile is present, only lockfiles consumed by the final build chain
  (the final stage plus every stage it copies from, recursively) count as
  build-path evidence. Builder-stage lockfiles count only when the builder
  stage is part of that chain, which is the normal case for compiled
  languages.
- Presence is not reachability. These parsers answer presence and resolved
  version only; call-path analysis lives elsewhere.
- Missing tools or unparsable files reduce confidence; they never prove that
  a package is absent.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

try:
    import tomllib  # Python 3.11+
    _HAVE_TOMLLIB = True
except ImportError:  # pragma: no cover - exercised only on Python < 3.11
    tomllib = None
    _HAVE_TOMLLIB = False

_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "build", "dist", "target",
    ".idea", ".vscode",
}

_REQUIREMENTS_RE = re.compile(r"^requirements([-.][\w.-]+)?\.txt$")


@dataclass
class LockfileInfo:
    path: str          # absolute path
    rel: str           # repo-relative posix path
    ecosystem: str     # go | python | rust | javascript
    kind: str          # lock | manifest


def find_lockfiles(repo_path: str, max_depth: int = 4) -> list[LockfileInfo]:
    """Discover dependency lockfiles and manifests under repo_path."""
    repo_path = os.path.abspath(repo_path)
    found: list[LockfileInfo] = []
    repo_depth = repo_path.rstrip(os.sep).count(os.sep)

    for root, dirs, files in os.walk(repo_path):
        depth = root.rstrip(os.sep).count(os.sep) - repo_depth
        if depth >= max_depth:
            dirs[:] = []
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for fname in sorted(files):
            ecosystem_kind = None
            if fname in ("go.sum", "go.mod"):
                ecosystem_kind = ("go", "lock" if fname == "go.sum" else "manifest")
            elif fname == "modules.txt" and os.path.basename(root) == "vendor":
                ecosystem_kind = ("go", "lock")
            elif fname in ("uv.lock", "poetry.lock"):
                ecosystem_kind = ("python", "lock")
            elif fname == "Cargo.lock":
                ecosystem_kind = ("rust", "lock")
            elif fname in ("package-lock.json", "yarn.lock"):
                ecosystem_kind = ("javascript", "lock")
            elif fname == "pyproject.toml":
                ecosystem_kind = ("python", "manifest")
            elif _REQUIREMENTS_RE.match(fname):
                ecosystem_kind = ("python", "lock")
            if ecosystem_kind:
                abs_path = os.path.join(root, fname)
                rel = os.path.relpath(abs_path, repo_path).replace(os.sep, "/")
                found.append(LockfileInfo(abs_path, rel, ecosystem_kind[0], ecosystem_kind[1]))

    order = {
        "go.sum": 0, "vendor/modules.txt": 1, "uv.lock": 2, "poetry.lock": 3,
        "Cargo.lock": 4, "package-lock.json": 5, "yarn.lock": 6,
        "go.mod": 7, "pyproject.toml": 8, "requirements.txt": 9,
    }
    found.sort(key=lambda lf: (order.get(lf.rel if lf.rel == "vendor/modules.txt"
                                           else os.path.basename(lf.path), 999), lf.rel))
    return found


# --------------------------------------------------------------------------
# Parsers: each returns dict[package name -> resolved version]
# --------------------------------------------------------------------------

def parse_lockfile(info: LockfileInfo) -> dict[str, str]:
    """Parse a lockfile into a package -> resolved-version mapping."""
    name = os.path.basename(info.path)
    try:
        if name == "modules.txt" and info.rel.endswith("vendor/modules.txt"):
            return _parse_go_vendor(info.path)
        if name == "go.sum":
            return _parse_go_sum(info.path)
        if name == "go.mod":
            return _parse_go_mod(info.path)
        if name in ("uv.lock", "Cargo.lock"):
            return _parse_toml_packages(info.path)
        if name == "poetry.lock":
            return _parse_poetry_lock(info.path)
        if name == "package-lock.json":
            return _parse_package_lock(info.path)
        if name == "yarn.lock":
            return _parse_yarn_lock(info.path)
        if name == "pyproject.toml":
            return _parse_pyproject(info.path)
        if _REQUIREMENTS_RE.match(name):
            return _parse_requirements(info.path)
    except Exception:
        return {}
    return {}


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _parse_go_sum(path: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    for line in _read(path).splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            versions[parts[0]] = parts[1].lstrip("v").split("/")[0]
    return versions


def _parse_go_mod(path: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    replaces: dict[str, str] = {}
    in_require = False
    in_replace = False
    for raw in _read(path).splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_require, in_replace = True, False
            continue
        if line.startswith("replace ("):
            in_replace, in_require = True, False
            continue
        if line == ")":
            in_require = in_replace = False
            continue
        if line.startswith("require ") and not in_require:
            line = line[len("require "):].strip()
            _go_mod_require(line, versions)
            continue
        if line.startswith("replace ") and not in_replace:
            line = line[len("replace "):].strip()
            _go_mod_replace(line, replaces)
            continue
        if in_require:
            _go_mod_require(line, versions)
        elif in_replace:
            _go_mod_replace(line, replaces)
    for original, replacement_version in replaces.items():
        if original in versions or original in replaces:
            versions[original] = replacement_version
    return versions


def _go_mod_require(line: str, versions: dict[str, str]) -> None:
    parts = line.split()
    if len(parts) >= 2 and parts[0] != "(":
        versions[parts[0]] = parts[1].removeprefix("v")


def _go_mod_replace(line: str, replaces: dict[str, str]) -> None:
    # Forms: "old => new v1.2.3", "old v0.1.0 => new v1.2.3",
    # "old => ../local" (no version: local replacement, keep out).
    parts = line.split()
    if "=>" not in parts:
        return
    arrow = parts.index("=>")
    original = parts[0]
    right = parts[arrow + 1:]
    if len(right) >= 2 and right[1].startswith("v"):
        replaces[original] = right[1].removeprefix("v")


def _parse_go_vendor(path: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    for line in _read(path).splitlines():
        line = line.strip()
        if line.startswith("#") and not line.startswith("##"):
            parts = line.lstrip("#").strip().split()
            if len(parts) >= 2:
                versions[parts[0]] = parts[1].lstrip("v").split("/")[0]
    return versions


def _parse_toml_packages(path: str) -> dict[str, str]:
    """Parse [[package]] tables (uv.lock, Cargo.lock)."""
    if _HAVE_TOMLLIB:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        return {
            pkg["name"]: pkg["version"]
            for pkg in data.get("package", [])
            if isinstance(pkg, dict) and "name" in pkg and "version" in pkg
        }
    # Fallback for Python < 3.11: [[package]] blocks are regular enough.
    versions: dict[str, str] = {}
    name = version = None
    for line in _read(path).splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            name = version = None
        elif name is None and stripped.startswith("name"):
            name = _toml_scalar(stripped)
        elif name is not None and version is None and stripped.startswith("version"):
            version = _toml_scalar(stripped)
            if name and version:
                versions[name] = version
    return versions


def _toml_scalar(line: str) -> str | None:
    value = line.split("=", 1)[1].strip() if "=" in line else ""
    return value.strip("\"'") or None


def _parse_poetry_lock(path: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    current: str | None = None
    for line in _read(path).splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            current = None
        elif stripped.startswith("name"):
            maybe = _toml_scalar(stripped)
            if maybe and current is None:
                current = maybe
        elif current is not None and stripped.startswith("version"):
            version = _toml_scalar(stripped)
            if version:
                versions[current] = version
                current = None
    return versions


def _parse_requirements(path: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    for line in _read(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            name = name.strip()
            # Strip environment markers and extras: "pkg[extra]>=1 ; python_version<'3'"
            name = name.split(";")[0].split("[")[0].strip()
            version = version.split(";")[0].strip()
            if name:
                versions[name] = version
    return versions


def _parse_package_lock(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    versions: dict[str, str] = {}
    for key, val in (data.get("packages") or {}).items():
        if isinstance(val, dict) and "version" in val:
            name = key.rsplit("node_modules/", 1)[-1]
            versions[name] = val["version"]
    for name, val in (data.get("dependencies") or {}).items():
        if isinstance(val, dict) and "version" in val and name not in versions:
            versions[name] = val["version"]
    return versions


def _parse_yarn_lock(path: str) -> dict[str, str]:
    """Parse yarn classic ('version "1.2.3"') and berry ('version: 1.2.3')."""
    versions: dict[str, str] = {}
    current_names: list[str] = []
    for line in _read(path).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            # Block header: "pkg@spec:" or "pkg@spec, pkg@spec:" (specs may
            # contain colons, e.g. "lodash@npm:^1.0.0").
            header = stripped[:-1].strip("\"'")
            current_names = []
            if header in ("", "__metadata"):
                continue
            for entry in header.split(","):
                entry = entry.strip().strip("\"'")
                if entry.startswith("@"):
                    # Scoped package: "@scope/name@spec".
                    body, sep, _ = entry[1:].rpartition("@")
                    name = "@" + body if sep else entry
                else:
                    name, sep, _ = entry.rpartition("@")
                    if not sep:
                        name = entry
                if name:
                    current_names.append(name)
        elif current_names and stripped.startswith("version"):
            # Berry: "version: 1.2.3"; classic: version "1.2.3"
            value = stripped.split(":", 1)[1] if ":" in stripped else stripped
            tokens = value.split()
            version = tokens[-1].strip("\"'") if tokens else ""
            if version:
                for name in current_names:
                    versions.setdefault(name, version)
                current_names = []
    return versions


def _parse_pyproject(path: str) -> dict[str, str]:
    """Parse exact pins from [project] dependencies (resolved only when ==)."""
    if not _HAVE_TOMLLIB:
        versions: dict[str, str] = {}
        in_deps = False
        for line in _read(path).splitlines():
            stripped = line.strip()
            if stripped.startswith("dependencies") or stripped.startswith("[project.optional-dependencies"):
                in_deps = True
                continue
            if in_deps and stripped.startswith("["):
                in_deps = False
            if in_deps and "==" in stripped:
                pin = stripped.strip("\"',")
                if "==" in pin:
                    name, version = pin.split("==", 1)
                    name = name.split("[")[0].split(";")[0].strip()
                    version = version.split(";")[0].strip().strip("\"'")
                    if name and version:
                        versions[name] = version
        return versions
    with open(path, "rb") as f:
        data = tomllib.load(f)
    versions: dict[str, str] = {}
    project = data.get("project", {})
    deps = list(project.get("dependencies", []))
    for group in (project.get("optional-dependencies") or {}).values():
        deps.extend(group)
    for dep in deps:
        if isinstance(dep, str) and "==" in dep:
            name, version = dep.split("==", 1)
            name = name.strip().split("[")[0].split(";")[0].strip()
            version = version.split(";")[0].strip()
            if name and version:
                versions[name] = version
    return versions


# --------------------------------------------------------------------------
# Dockerfile build-path filtering
# --------------------------------------------------------------------------

_DOCKERFILE_NAMES = ("Dockerfile", "Containerfile", "dockerfile")


def _find_dockerfiles(repo_path: str) -> list[str]:
    candidates: list[str] = []
    for root, dirs, files in os.walk(repo_path):
        depth = root.rstrip(os.sep).count(os.sep) - repo_path.rstrip(os.sep).count(os.sep)
        if depth >= 2:
            dirs[:] = []
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for fname in files:
            if fname in _DOCKERFILE_NAMES or (fname.endswith(".Dockerfile") and depth == 0):
                candidates.append(os.path.join(root, fname))
    return sorted(candidates)


def _parse_dockerfile_stages(path: str) -> list[dict]:
    """Return stages with their FROM/COPY references.

    Each stage: {"name": str, "index": int, "copy_from": set[str|int],
    "copy_sources": list[str]}.
    """
    stages: list[dict] = []
    current: dict | None = None
    for raw in _read(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("FROM"):
            parts = line.split()
            name = None
            if len(parts) >= 4 and parts[2].upper() == "AS":
                name = parts[3]
            current = {
                "name": name, "index": len(stages),
                "copy_from": set(), "copy_sources": [],
            }
            # FROM <earlier-stage-name>: stage inheritance edge.
            base = parts[1] if len(parts) > 1 else ""
            base = base.split("@")[0] if base else ""
            current["copy_from"].add(base)
            stages.append(current)
        elif current is not None and (upper.startswith("COPY") or upper.startswith("ADD")):
            parts = line.split()
            paths: list[str] = []
            flag_value_pending = False
            for token in parts[1:]:
                if token.startswith("--from="):
                    current["copy_from"].add(token.split("=", 1)[1])
                    continue
                if flag_value_pending:
                    flag_value_pending = False
                    continue
                if token.startswith("--"):
                    if token in ("--from", "--chmod", "--chown"):
                        flag_value_pending = True
                    continue
                if token in ("[", "]", ","):
                    continue
                paths.append(token.strip("\"'"))
            # The last path of COPY/ADD is the destination, never a source.
            if len(paths) > 1:
                current["copy_sources"].extend(paths[:-1])
            if "--from" in parts:
                try:
                    src = parts[parts.index("--from") + 1]
                    current["copy_from"].add(src)
                except (ValueError, IndexError):
                    pass
    return stages


def _final_stage_chain(stages: list[dict]) -> set[int]:
    """Indices of the final stage plus every stage it derives from."""
    if not stages:
        return set()
    by_name = {s["name"]: s["index"] for s in stages if s["name"]}
    chain: set[int] = set()
    stack = [stages[-1]["index"]]
    while stack:
        idx = stack.pop()
        if idx in chain:
            continue
        chain.add(idx)
        for ref in stages[idx]["copy_from"]:
            if ref in by_name and by_name[ref] != idx:
                stack.append(by_name[ref])
            elif str(ref).isdigit() and 0 <= int(ref) < len(stages) and int(ref) != idx:
                stack.append(int(ref))
    return chain


def _copy_matches_lockfile(source: str, rel: str) -> bool:
    """Does a COPY/ADD source reference pull in the lockfile at rel?"""
    source = source.strip("./")
    if not source:
        return True  # COPY . . brings in the whole context
    rel_parts = rel.split("/")
    src_parts = source.split("/")
    if len(src_parts) > len(rel_parts):
        return False
    return rel_parts[: len(src_parts)] == src_parts


def build_path_filter(repo_path: str, lockfiles: list[LockfileInfo]) -> set[str] | None:
    """Lockfile rel-paths consumed by the container build, or None if unknown.

    None means "no container build path could be determined"; callers must
    then fall back to all discovered lockfiles with reduced confidence.
    """
    dockerfiles = _find_dockerfiles(repo_path)
    if not dockerfiles:
        return None
    referenced: set[str] = set()
    for df in dockerfiles:
        stages = _parse_dockerfile_stages(df)
        chain = _final_stage_chain(stages)
        sources: list[str] = []
        for idx in chain:
            sources.extend(stages[idx]["copy_sources"])
        matched = {
            lf.rel for lf in lockfiles
            if any(_copy_matches_lockfile(src, lf.rel) for src in sources)
        }
        referenced |= matched
    if not referenced:
        return None
    return referenced
