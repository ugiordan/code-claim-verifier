from __future__ import annotations

import os

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.language import get_import_patterns, detect_language
from code_claim_verifier.security import safe_path
from code_claim_verifier.grep import grep as _grep
from code_claim_verifier.lockfiles import (
    LockfileInfo,
    build_path_filter,
    find_lockfiles,
    parse_lockfile,
)


def verify_import_exists(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    module = (claim.parameters.get("module", "")
              or claim.parameters.get("import", "")
              or claim.parameters.get("name", ""))
    file_param = claim.parameters.get("file", "")
    if not module and file_param and file_param.endswith((".h", ".hpp")):
        module = file_param
    if not module:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence="No module specified", method="grep_import")

    if file_param:
        detected = detect_language(file_param)
        lang = detected if detected != "unknown" else language
    else:
        lang = language
    patterns = get_import_patterns(module, lang)

    if file_param:
        resolved = safe_path(file_param, repo_path)
        if resolved is None or not os.path.isfile(resolved):
            return VerifiedClaim(
                claim=claim, verdict="REFUTED", method_confidence=0.99,
                evidence=(f"Invalid target file path: {file_param}"
                          if resolved is None else f"Target file not found: {file_param}"),
                method="file_scope",
            )
        search_path = resolved
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
    if not package:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence="No package specified", method="lockfile_parse")

    lockfiles = find_lockfiles(repo_path)
    if not lockfiles:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence=f"No lockfile found containing {package}", method="lockfile_parse")

    build_scope = build_path_filter(repo_path, lockfiles)
    found: list[tuple[str, str]] = []       # (rel, version) in build scope
    found_outside: list[tuple[str, str]] = []  # occurrences outside the build path
    for lf in lockfiles:
        versions = parse_lockfile(lf)
        actual = _match_package(versions, package, lf.ecosystem)
        if actual is None:
            continue
        if build_scope is None or lf.rel in build_scope:
            found.append((lf.rel, actual))
        else:
            found_outside.append((lf.rel, actual))

    if not found:
        if found_outside:
            rels = ", ".join(f"{rel} ({ver})" for rel, ver in found_outside)
            return VerifiedClaim(
                claim=claim, verdict="REFUTED", method_confidence=0.70,
                evidence=(f"{package} present in {rels}, but those files are not "
                          f"consumed by the container build path"),
                method="lockfile_parse",
            )
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence=f"No lockfile found containing {package}", method="lockfile_parse")

    # First in-scope hit wins; lockfiles sort before manifests.
    rel, actual = found[0]
    actual_normalized = actual.strip().removeprefix("v")
    expected_normalized = str(expected_version).strip().removeprefix("v")
    match = bool(expected_normalized) and actual_normalized == expected_normalized
    extra = ""
    confidence = 0.90
    if build_scope is None:
        confidence = 0.85
        extra = " (no container build path found; all lockfiles considered)"
    return VerifiedClaim(
        claim=claim,
        verdict="VERIFIED" if match else "REFUTED",
        method_confidence=confidence,
        evidence=f"{rel}: {package}=={actual} (expected {expected_version}){extra}",
        method="lockfile_parse",
    )


def verify_package_absent(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    package = (claim.parameters.get("package", "")
               or claim.parameters.get("name", "")
               or claim.parameters.get("dependency", ""))
    if not package:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence="No package specified", method="lockfile_parse")

    lockfiles = find_lockfiles(repo_path)
    if not lockfiles:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence="No lockfiles found; absence cannot be established",
                             method="lockfile_parse")

    build_scope = build_path_filter(repo_path, lockfiles)
    in_scope = [lf for lf in lockfiles if build_scope is None or lf.rel in build_scope]
    found_in_scope: list[tuple[str, str]] = []
    found_outside: list[tuple[str, str]] = []
    for lf in lockfiles:
        versions = parse_lockfile(lf)
        actual = _match_package(versions, package, lf.ecosystem)
        if actual is None:
            continue
        if build_scope is None or lf.rel in build_scope:
            found_in_scope.append((lf.rel, actual))
        else:
            found_outside.append((lf.rel, actual))

    if found_in_scope:
        rel, ver = found_in_scope[0]
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.90,
            evidence=f"{rel}: {package}=={ver}", method="lockfile_parse",
        )

    checked = ", ".join(lf.rel for lf in in_scope) or "none"
    if found_outside:
        rels = ", ".join(f"{rel} ({ver})" for rel, ver in found_outside)
        return VerifiedClaim(
            claim=claim, verdict="VERIFIED", method_confidence=0.80,
            evidence=(f"{package} absent from the build-path lockfiles ({checked}); "
                      f"present only outside the build path in {rels}"),
            method="lockfile_parse",
        )
    if build_scope is None:
        return VerifiedClaim(
            claim=claim, verdict="VERIFIED", method_confidence=0.80,
            evidence=f"{package} absent from all {len(in_scope)} lockfiles "
                     f"(no container build path found; absence is repo-wide, not build-scoped)",
            method="lockfile_parse",
        )
    return VerifiedClaim(
        claim=claim, verdict="VERIFIED", method_confidence=0.90,
        evidence=f"{package} absent from the {len(in_scope)} lockfiles consumed by the build",
        method="lockfile_parse",
    )


def _match_package(versions: dict[str, str], package: str, ecosystem: str) -> str | None:
    """Resolve a package name inside a parsed lockfile, ecosystem-aware."""
    if ecosystem == "python":
        lowered = {k.lower(): v for k, v in versions.items()}
        return lowered.get(package.lower())
    if ecosystem == "go":
        if package in versions:
            return versions[package]
        for name, version in versions.items():
            if name.endswith("/" + package):
                return version
        return None
    if package in versions:
        return versions[package]
    for name, version in versions.items():
        if name.endswith("/" + package):
            return version
    return None


# Backwards-compatible single-package wrappers (used by tests and callers).
def _parse_go_sum(path: str, package: str) -> str | None:
    return _match_package(_lf_parse(path, "go.sum", "go"), package, "go")


def _parse_go_mod(path: str, package: str) -> str | None:
    return _match_package(_lf_parse(path, "go.mod", "go"), package, "go")


def _parse_requirements(path: str, package: str) -> str | None:
    return _match_package(_lf_parse(path, "requirements.txt", "python"), package, "python")


def _parse_poetry_lock(path: str, package: str) -> str | None:
    return _match_package(_lf_parse(path, "poetry.lock", "python"), package, "python")


def _parse_package_lock(path: str, package: str) -> str | None:
    return _match_package(_lf_parse(path, "package-lock.json", "javascript"), package, "javascript")


def _lf_parse(path: str, basename: str, ecosystem: str) -> dict[str, str]:
    info = LockfileInfo(path=path, rel=basename, ecosystem=ecosystem, kind="lock")
    return parse_lockfile(info)


def verify_dependency_type(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    package = (claim.parameters.get("package", "")
               or claim.parameters.get("name", "")
               or claim.parameters.get("dependency", ""))
    if not package:
        return VerifiedClaim(claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                             evidence="No package specified", method="manifest_parse")
    expected_type = claim.parameters.get("type", claim.parameters.get("dep_type", "direct"))

    manifests = ["go.mod", "requirements.txt", "package.json", "Pipfile", "pyproject.toml",
                  "CMakeLists.txt", "Makefile", "configure.ac", "meson.build", "Cargo.toml"]
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
    cve = claim.parameters.get("cve", "")
    package = claim.parameters.get("package", "")
    version = claim.parameters.get("version", "")

    if not package or not version:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="Missing package or version parameter", method="osv_api",
        )

    try:
        import urllib.request
        import json as _json

        payload = _json.dumps({"package": {"name": package}, "version": version}).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = _json.loads(resp.read())

        vulns = data.get("vulns", [])
        if not vulns:
            return VerifiedClaim(
                claim=claim, verdict="REFUTED", method_confidence=0.75,
                evidence=f"OSV: no known vulnerabilities for {package}@{version}",
                method="osv_api",
            )

        if cve:
            cve_ids = set()
            for v in vulns:
                cve_ids.add(v.get("id", ""))
                for alias in v.get("aliases", []):
                    cve_ids.add(alias)
            if cve in cve_ids:
                return VerifiedClaim(
                    claim=claim, verdict="VERIFIED", method_confidence=0.85,
                    evidence=f"OSV confirms {cve} affects {package}@{version}",
                    method="osv_api",
                )
            return VerifiedClaim(
                claim=claim, verdict="REFUTED", method_confidence=0.75,
                evidence=f"OSV: {len(vulns)} vulns for {package}@{version} but {cve} not among them",
                method="osv_api",
            )

        return VerifiedClaim(
            claim=claim, verdict="VERIFIED", method_confidence=0.80,
            evidence=f"OSV: {len(vulns)} known vulnerabilities for {package}@{version}",
            method="osv_api",
        )

    except Exception as e:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"OSV API error: {str(e)[:200]}", method="osv_api",
            error=str(e)[:200],
        )
