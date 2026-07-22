from __future__ import annotations

import logging
import os
import re
import subprocess
import time

from eval.cybergym.utils import load_jsonl, save_jsonl
from eval.multilang.constants import (
    BASE_IMAGES, BUILD_COMMANDS, CandidateStatus, PYTHON_ALT_INSTALL,
)

logger = logging.getLogger(__name__)


def _detect_required_version(source_path: str, language: str) -> str | None:
    """Read build files to detect the required language version."""
    try:
        if language == "go":
            go_mod = os.path.join(source_path, "go.mod")
            if os.path.isfile(go_mod):
                with open(go_mod) as f:
                    for line in f:
                        m = re.match(r"^go\s+(1\.\d+)", line)
                        if m:
                            return m.group(1)
        elif language == "python":
            pyproject = os.path.join(source_path, "pyproject.toml")
            if os.path.isfile(pyproject):
                with open(pyproject) as f:
                    for line in f:
                        m = re.search(r'python_requires\s*=\s*["\']>=\s*(3\.\d+)', line)
                        if m:
                            return m.group(1)
        elif language == "rust":
            cargo = os.path.join(source_path, "Cargo.toml")
            if os.path.isfile(cargo):
                with open(cargo) as f:
                    for line in f:
                        m = re.search(r'rust-version\s*=\s*["\'](1\.\d+)', line)
                        if m:
                            return m.group(1)
        elif language in ("javascript", "typescript"):
            pkg = os.path.join(source_path, "package.json")
            if os.path.isfile(pkg):
                import json
                with open(pkg) as f:
                    data = json.load(f)
                engines = data.get("engines", {})
                if isinstance(engines, dict):
                    node_ver = engines.get("node", "")
                    m = re.search(r"(\d+)", node_ver)
                    if m:
                        return m.group(1)
    except (OSError, ValueError):
        pass
    return None


def _parse_version_tuple(s: str) -> tuple[int, int]:
    """Parse version string as (major, minor) tuple. Bug #7 fix: Handle single-number versions."""
    parts = s.split(".")
    try:
        return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
    except (ValueError, IndexError):
        return (0, 0)


def _reorder_images(images: list[str], required_version: str | None,
                    language: str) -> list[str]:
    """Put the best-matching base image first based on detected version."""
    if not required_version:
        return images

    req = _parse_version_tuple(required_version)

    def _sort_key(img: str) -> tuple[int, int, int]:
        tag = img.split(":")[-1]
        # Bug #7 fix: Match major-only versions (e.g., "22") or major.minor (e.g., "1.22")
        m = re.search(r"(\d+(?:\.\d+)?)", tag)
        if not m:
            return (2, 0, 0)
        tag_ver = _parse_version_tuple(m.group(1))
        if tag_ver == req:
            return (0, 0, 0)
        dist = abs(tag_ver[0] - req[0]) * 100 + abs(tag_ver[1] - req[1])
        return (1, dist, 0)

    return sorted(images, key=_sort_key)


def generate_containerfile(
    language: str,
    base_image: str,
    source_root: str,
    has_requirements_txt: bool = False,
    has_setup_py: bool = True,
) -> str:
    cmds = BUILD_COMMANDS.get(language, BUILD_COMMANDS.get("python", {}))
    build_cmd = cmds["build"]
    test_cmd = cmds["test"]

    if language == "python":
        if has_requirements_txt and not has_setup_py:
            build_cmd = PYTHON_ALT_INSTALL

    lines = [
        f"FROM {base_image}",
        "WORKDIR /app",
        "COPY . /app/",
    ]

    if language == "go":
        lines.append("ENV GOFLAGS=-mod=mod")
    if language == "rust":
        lines.append("ENV CARGO_NET_GIT_FETCH_WITH_CLI=true")

    lines.append(f"RUN {build_cmd}")
    lines.append(f'RUN {test_cmd} || echo "POLYVULN_TESTS_FAILED"')

    return "\n".join(lines) + "\n"


def _detect_project_files(source_path: str) -> dict[str, bool]:
    return {
        "has_requirements_txt": os.path.isfile(os.path.join(source_path, "requirements.txt")),
        "has_setup_py": os.path.isfile(os.path.join(source_path, "setup.py"))
                        or os.path.isfile(os.path.join(source_path, "pyproject.toml")),
        "has_package_json": os.path.isfile(os.path.join(source_path, "package.json")),
        "has_cargo_toml": os.path.isfile(os.path.join(source_path, "Cargo.toml")),
        "has_pom_xml": os.path.isfile(os.path.join(source_path, "pom.xml")),
        "has_build_gradle": os.path.isfile(os.path.join(source_path, "build.gradle"))
                            or os.path.isfile(os.path.join(source_path, "build.gradle.kts")),
        "has_go_mod": os.path.isfile(os.path.join(source_path, "go.mod")),
    }


def _podman_build(containerfile_path: str, context_dir: str, tag: str,
                   timeout: int = 600) -> tuple[bool, str, float]:
    start = time.monotonic()
    try:
        result = subprocess.run(
            ["podman", "build", "-f", containerfile_path, "-t", tag, context_dir],
            capture_output=True, text=True, timeout=timeout,
        )
        elapsed = time.monotonic() - start
        success = result.returncode == 0
        output = result.stdout + result.stderr
        return success, output, elapsed
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, "podman not found or build timed out", time.monotonic() - start


def _count_test_output(output: str, language: str) -> tuple[bool, int]:
    if "POLYVULN_TESTS_FAILED" in output:
        test_success = False
    else:
        test_success = True

    test_count = 0
    if language == "go":
        test_count = output.count("--- PASS") + output.count("--- FAIL")
    elif language == "python":
        for line in output.split("\n"):
            if "passed" in line or "failed" in line:
                import re
                nums = re.findall(r"(\d+)\s+(?:passed|failed)", line)
                test_count += sum(int(n) for n in nums)
    elif language in ("javascript", "typescript"):
        for pattern in [r"(\d+)\s+passing", r"(\d+)\s+failing", r"(\d+)\s+(?:passed|failed)"]:
            for m in re.finditer(pattern, output):
                test_count += int(m.group(1))
    elif language == "java":
        for line in output.split("\n"):
            if "Tests run:" in line:
                import re
                m = re.search(r"Tests run:\s*(\d+)", line)
                if m:
                    test_count += int(m.group(1))
    elif language == "rust":
        import re
        m = re.search(r"test result:.*?(\d+)\s+passed", output)
        if m:
            test_count += int(m.group(1))

    return test_success, test_count


def build_case(candidate: dict, containerfiles_dir: str, base_dir: str) -> dict:
    osv_id = candidate["osv_id"]
    language = candidate.get("language", "unknown")
    source_root = candidate.get("source_root", "")

    if not source_root:
        candidate["status"] = CandidateStatus.FAILED
        candidate["failure_reason"] = "no source_root"
        candidate["failure_stage"] = "build"
        return candidate

    source_path = os.path.join(base_dir, source_root) if not os.path.isabs(source_root) else source_root

    if not os.path.isdir(source_path):
        candidate["status"] = CandidateStatus.FAILED
        candidate["failure_reason"] = f"source_root not found: {source_path}"
        candidate["failure_stage"] = "build"
        return candidate

    project_files = _detect_project_files(source_path)
    required_version = _detect_required_version(source_path, language)

    # Map typescript to javascript for base images (Bug #6 fix)
    image_lang = "javascript" if language == "typescript" else language
    images = _reorder_images(BASE_IMAGES.get(image_lang, []), required_version, language)
    if required_version:
        logger.debug("Detected %s version %s for %s", language, required_version, osv_id)

    images = images[:3]

    for base_image in images:
        cf_content = generate_containerfile(
            language, base_image, source_root,
            has_requirements_txt=project_files.get("has_requirements_txt", False),
            has_setup_py=project_files.get("has_setup_py", True),
        )

        cf_dir = os.path.join(containerfiles_dir, language, osv_id)
        os.makedirs(cf_dir, exist_ok=True)
        cf_path = os.path.join(cf_dir, "Containerfile")
        with open(cf_path, "w") as f:
            f.write(cf_content)

        tag = f"polyvuln/{language}/{osv_id}:latest".lower()
        success, output, elapsed = _podman_build(cf_path, source_path, tag)

        if success:
            test_success, test_count = _count_test_output(output, language)
            candidate["build_success"] = True
            candidate["test_success"] = test_success
            candidate["test_count"] = test_count
            candidate["build_time_seconds"] = round(elapsed, 1)
            candidate["containerfile_path"] = os.path.relpath(cf_path, base_dir)
            candidate["container_image_tag"] = tag
            candidate["base_image"] = base_image
            candidate["status"] = CandidateStatus.BUILD_OK
            logger.info("Build OK for %s with %s (%.1fs)", osv_id, base_image, elapsed)
            return candidate

        logger.debug("Build failed for %s with %s, trying next image", osv_id, base_image)

    candidate["status"] = CandidateStatus.FAILED
    candidate["failure_reason"] = f"all {len(images)} base images failed"
    candidate["failure_stage"] = "build"
    candidate["build_success"] = False
    return candidate


def run_build(candidates_path: str, containerfiles_dir: str, base_dir: str,
              max_builds: int = 0, retry_failed: bool = False) -> None:
    candidates = load_jsonl(candidates_path)
    build_count = 0
    _SAVE_INTERVAL = 25

    for i, c in enumerate(candidates):
        status = c.get("status")
        if status == CandidateStatus.BUILD_OK:
            continue
        # Bug #1 fix: protect VERIFIED/READY from being rebuilt
        if status in (CandidateStatus.VERIFIED, CandidateStatus.READY):
            continue
        if status == CandidateStatus.FAILED:
            if c.get("failure_stage") != "build" or not retry_failed:
                continue
        elif status != CandidateStatus.CLONED:
            continue
        if max_builds > 0 and build_count >= max_builds:
            continue

        logger.info("[%d/%d] Building %s", i + 1, len(candidates), c["osv_id"])
        candidates[i] = build_case(c, containerfiles_dir, base_dir)
        build_count += 1

        if build_count % _SAVE_INTERVAL == 0:
            save_jsonl(candidates, candidates_path)
            built_so_far = sum(1 for x in candidates if x.get("build_success"))
            logger.info("Checkpoint: %d built so far (%d attempted)", built_so_far, build_count)

    save_jsonl(candidates, candidates_path)
    built = sum(1 for c in candidates if c.get("build_success"))
    logger.info("Built: %d / %d", built, len(candidates))
