import json
import os
import re

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.language import get_import_patterns, detect_language
from code_claim_verifier.security import safe_path
from code_claim_verifier.verifiers.symbol_claims import _grep


def verify_import_exists(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    module = claim.parameters.get("module", "")
    file_param = claim.parameters.get("file", "")

    lang = detect_language(file_param) if file_param else language
    patterns = get_import_patterns(module, lang)

    if file_param:
        resolved = safe_path(file_param, repo_path)
        search_path = resolved if resolved and os.path.isfile(resolved) else repo_path
    else:
        search_path = repo_path

    for pattern in patterns:
        matches = _grep(pattern, search_path)
        if matches:
            return VerifiedClaim(
                claim=claim, verdict="VERIFIED", method_confidence=0.80,
                evidence=matches[0][:200], method="grep_import",
            )

    return VerifiedClaim(
        claim=claim, verdict="REFUTED", method_confidence=0.80,
        evidence=f"No import of {module} found", method="grep_import",
    )


def verify_package_version(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    package = claim.parameters.get("package", "")
    expected_version = claim.parameters.get("version", "")

    lockfiles = [
        ("go.sum", _parse_go_sum),
        ("go.mod", _parse_go_mod),
        ("requirements.txt", _parse_requirements),
        ("poetry.lock", _parse_poetry_lock),
        ("package-lock.json", _parse_package_lock),
    ]

    for filename, parser in lockfiles:
        lockfile_path = os.path.join(repo_path, filename)
        if os.path.isfile(lockfile_path):
            actual = parser(lockfile_path, package)
            if actual:
                match = actual == expected_version or expected_version in actual
                return VerifiedClaim(
                    claim=claim,
                    verdict="VERIFIED" if match else "REFUTED",
                    method_confidence=0.90,
                    evidence=f"{filename}: {package}=={actual} (expected {expected_version})",
                    method="lockfile_parse",
                )

    return VerifiedClaim(
        claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
        evidence=f"No lockfile found containing {package}", method="lockfile_parse",
    )


def _parse_go_sum(path: str, package: str) -> str | None:
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and package in parts[0]:
                    return parts[1].lstrip("v").split("/")[0]
    except Exception:
        pass
    return None


def _parse_go_mod(path: str, package: str) -> str | None:
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if package in line and not line.startswith("//"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[-1].lstrip("v")
    except Exception:
        pass
    return None


def _parse_requirements(path: str, package: str) -> str | None:
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if "==" in line:
                    name, version = line.split("==", 1)
                    if name.strip().lower() == package.lower():
                        return version.strip()
    except Exception:
        pass
    return None


def _parse_poetry_lock(path: str, package: str) -> str | None:
    try:
        with open(path) as f:
            content = f.read()
        in_package = False
        for line in content.split("\n"):
            if line.strip() == "[[package]]":
                in_package = False
            if f'name = "{package}"' in line.lower() or f"name = '{package}'" in line.lower():
                in_package = True
            if in_package and line.strip().startswith("version"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return None


def _parse_package_lock(path: str, package: str) -> str | None:
    try:
        with open(path) as f:
            data = json.load(f)
        deps = data.get("dependencies", {})
        if package in deps:
            return deps[package].get("version", "")
        packages = data.get("packages", {})
        for key, val in packages.items():
            if key.endswith(f"/{package}") or key == f"node_modules/{package}":
                return val.get("version", "")
    except Exception:
        pass
    return None


def verify_dependency_type(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    package = claim.parameters.get("package", "")
    expected_type = claim.parameters.get("type", "direct")

    manifests = ["go.mod", "requirements.txt", "package.json", "Pipfile", "pyproject.toml"]
    for manifest in manifests:
        manifest_path = os.path.join(repo_path, manifest)
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path) as f:
                    content = f.read()
                is_direct = package.lower() in content.lower()
                match = (is_direct and expected_type == "direct") or (not is_direct and expected_type == "transitive")
                return VerifiedClaim(
                    claim=claim, verdict="VERIFIED" if match else "REFUTED",
                    method_confidence=0.85,
                    evidence=f"{manifest}: {'direct' if is_direct else 'not found (transitive?)'}",
                    method="manifest_parse",
                )
            except Exception:
                continue

    return VerifiedClaim(
        claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
        evidence="No manifest found", method="manifest_parse",
    )


def verify_cve_affects(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    return VerifiedClaim(
        claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
        evidence="CVE version range checking requires external advisory database",
        method="cve_db",
    )
