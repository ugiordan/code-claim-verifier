from __future__ import annotations

import os
from dataclasses import dataclass

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
from code_claim_verifier.clair import fetch_clair_assessment, load_clair_report
from code_claim_verifier.versioning import compare, fixes, in_range, normalize_ecosystem

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True)
class OsvAssessment:
    """OSV result; a missing match is not proof that a package is unaffected."""

    package: str
    version: str
    cve_id: str | None
    vulnerability_count: int
    vulnerability_ids: tuple[str, ...]
    matching_cve: bool | None
    source_url: str
    gap_reason: str | None = None
    error: str | None = None


def fetch_osv_assessment(
    package: str, version: str, cve_id: str | None = None,
    ecosystem: str | None = None,
) -> OsvAssessment:
    """Query OSV for a package/version and optionally match a CVE identifier.

    The OSV v1/query contract requires package.ecosystem when the
    package is identified by name, so callers should forward one
    whenever it is known. Follows next_page_token pagination.
    """
    if not package or not version:
        return OsvAssessment(
            package=package,
            version=version,
            cve_id=cve_id,
            vulnerability_count=0,
            vulnerability_ids=(),
            matching_cve=None,
            source_url=OSV_QUERY_URL,
            gap_reason="missing_parameters",
        )

    try:
        import json as _json
        import urllib.request

        package_spec: dict[str, str] = {"name": package}
        if ecosystem:
            package_spec["ecosystem"] = ecosystem
        vulnerabilities: list = []
        page_token = ""
        pages = 0
        while pages < 10:
            body: dict = {"package": package_spec, "version": version}
            if page_token:
                body["page_token"] = page_token
            payload = _json.dumps(body).encode()
            req = urllib.request.Request(
                OSV_QUERY_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = _json.loads(resp.read())

            page_vulns = data.get("vulns", [])
            if not isinstance(page_vulns, list):
                raise ValueError("OSV response field 'vulns' is not a list")
            vulnerabilities.extend(page_vulns)
            page_token = data.get("next_page_token", "")
            pages += 1
            if not page_token:
                break

        if page_token:
            # The page cap stopped pagination; the collected pages are
            # not exhaustive evidence.
            return OsvAssessment(
                package=package, version=version, cve_id=cve_id,
                vulnerability_count=0, vulnerability_ids=(),
                matching_cve=None, source_url=OSV_QUERY_URL,
                gap_reason="osv_pagination_incomplete",
            )

        vulnerability_ids: list[str] = []
        matching_cve = False if cve_id else None
        for vulnerability in vulnerabilities:
            vulnerability_id = vulnerability.get("id", "")
            if vulnerability_id:
                vulnerability_ids.append(vulnerability_id)
            if cve_id:
                cve_ids = {vulnerability_id}
                cve_ids.update(vulnerability.get("aliases", []))
                if cve_id in cve_ids:
                    matching_cve = True

        return OsvAssessment(
            package=package,
            version=version,
            cve_id=cve_id,
            vulnerability_count=len(vulnerabilities),
            vulnerability_ids=tuple(vulnerability_ids),
            matching_cve=matching_cve,
            source_url=OSV_QUERY_URL,
        )
    except Exception as exc:
        error = str(exc)[:200]
        return OsvAssessment(
            package=package,
            version=version,
            cve_id=cve_id,
            vulnerability_count=0,
            vulnerability_ids=(),
            matching_cve=None,
            source_url=OSV_QUERY_URL,
            gap_reason="osv_query_failed",
            error=error,
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

    clair_report_path = claim.parameters.get("clair_report") or ""
    if clair_report_path:
        return _verify_cve_affects_clair(
            claim, clair_report_path, repo_path, cve, package, version,
        )

    # Offline first: when the claim carries the advisory's affected range,
    # compare deterministically without a network round-trip.
    range_spec = (claim.parameters.get("affected_range")
                  or claim.parameters.get("range")
                  or "")
    if isinstance(range_spec, str) and range_spec:
        ecosystem = _claim_ecosystem(claim, language)
        try:
            affected = in_range(version, range_spec, ecosystem)
            return VerifiedClaim(
                claim=claim,
                verdict="VERIFIED" if affected else "REFUTED",
                method_confidence=0.95,
                evidence=(f"offline range check ({ecosystem}): {version} "
                          f"{'is' if affected else 'is not'} in '{range_spec}'"),
                method="version_compare", verification_source="version_compare",
            )
        except ValueError:
            pass  # fall through to the OSV API

    assessment = fetch_osv_assessment(
        package, version, cve or None, _osv_ecosystem(claim, language),
    )
    if assessment.gap_reason:
        error = assessment.error or assessment.gap_reason
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"OSV API error: {error}", method="osv_api",
            error=assessment.error,
        )

    if not assessment.vulnerability_count:
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.75,
            evidence=f"OSV: no known vulnerabilities for {package}@{version}",
            method="osv_api",
        )

    if cve:
        if assessment.matching_cve:
            return VerifiedClaim(
                claim=claim, verdict="VERIFIED", method_confidence=0.85,
                evidence=f"OSV confirms {cve} affects {package}@{version}",
                method="osv_api",
            )
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.75,
            evidence=(f"OSV: {assessment.vulnerability_count} vulns for "
                      f"{package}@{version} but {cve} not among them"),
            method="osv_api",
        )

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED", method_confidence=0.80,
        evidence=(f"OSV: {assessment.vulnerability_count} known vulnerabilities "
                  f"for {package}@{version}"),
        method="osv_api",
    )


def _claim_ecosystem(claim: TypedClaim, language: str) -> str:
    return normalize_ecosystem(
        claim.parameters.get("ecosystem") or language or "semver"
    )


# OSV v1/query ecosystem names, keyed by the CCV-normalized ecosystem
# or language. Claim parameters may carry either form.
_OSV_ECOSYSTEMS = {
    "python": "PyPI",
    "pypi": "PyPI",
    "go": "Go",
    "golang": "Go",
    "javascript": "npm",
    "npm": "npm",
    "typescript": "npm",
    "java": "Maven",
    "maven": "Maven",
    "rust": "crates.io",
    "crates.io": "crates.io",
}


def _osv_ecosystem(claim: TypedClaim, language: str) -> str | None:
    """Map the claim's ecosystem or language to an OSV ecosystem name."""
    raw = (claim.parameters.get("ecosystem") or language or "").strip()
    if not raw:
        return None
    return _OSV_ECOSYSTEMS.get(raw.lower(), raw)


def _resolve_clair_report_path(claim_path: str, repo_path: str) -> str | None:
    """Resolve a claim's Clair report path.

    Repo-relative paths must stay inside the repo (same traversal rules
    as file claims); absolute paths are accepted for report artifacts
    that live outside the source tree.
    """
    resolved = safe_path(claim_path, repo_path)
    if resolved and os.path.isfile(resolved):
        return resolved
    if os.path.isabs(claim_path) and os.path.isfile(claim_path):
        return claim_path
    return None


def _verify_cve_affects_clair(
    claim: TypedClaim, report_path: str, repo_path: str,
    cve: str, package: str, version: str,
) -> VerifiedClaim:
    if not cve:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="clair_report evidence requires the cve parameter",
            method="clair_report", verification_source="clair_report",
        )

    resolved = _resolve_clair_report_path(report_path, repo_path)
    if resolved is None:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Clair report not found: {report_path}",
            method="clair_report", verification_source="clair_report",
        )
    try:
        report = load_clair_report(resolved)
    except (OSError, ValueError) as exc:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Clair report unreadable: {str(exc)[:150]}",
            method="clair_report", verification_source="clair_report",
            error=str(exc)[:200],
        )

    assessment = fetch_clair_assessment(report, cve, package)
    origin = (f"Clair report {assessment.manifest_hash}"
              if assessment.manifest_hash else "Clair report")
    if assessment.gap_reason == "cve_not_in_report":
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"{origin} does not list {cve}",
            method="clair_report", verification_source="clair_report",
        )
    if assessment.gap_reason == "package_not_in_report":
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"{origin} does not list package {package}",
            method="clair_report", verification_source="clair_report",
        )
    if assessment.affected is None:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=(f"{origin} lists {cve} but does not link it to "
                      f"package {package}; a missing link is an evidence "
                      f"gap, not proof of safety ({assessment.gap_reason})"),
            method="clair_report", verification_source="clair_report",
        )

    if version and not assessment.installed_version:
        # Duplicate same-named packages with different linked versions:
        # the report cannot establish which version was assessed.
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=(f"{origin} links {cve} to {package} but the report "
                      f"cannot establish a unique installed version for it"),
            method="clair_report", verification_source="clair_report",
        )

    if version and assessment.installed_version and version != assessment.installed_version:
        # The report only assessed the installed version; a claim about
        # a different version has no evidence either way.
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=(f"{origin} assessed {package}@{assessment.installed_version}; "
                      f"the claim names version {version}, which the report "
                      f"did not assess"),
            method="clair_report", verification_source="clair_report",
        )

    if assessment.affected:
        return VerifiedClaim(
            claim=claim, verdict="VERIFIED", method_confidence=0.90,
            evidence=(f"{origin}: {package}@{assessment.installed_version} "
                      f"affected by {cve} ({assessment.distro}, updater "
                      f"{assessment.updater})"),
            method="clair_report", verification_source="clair_report",
        )
    return VerifiedClaim(
        claim=claim, verdict="REFUTED", method_confidence=0.85,
        evidence=(f"{origin} lists {cve} but not for "
                  f"{package}@{assessment.installed_version} "
                  f"({assessment.distro})"),
        method="clair_report",
    )


def verify_version_in_range(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    """Offline affected-range check: "version X is in range R" (or not)."""
    version = (claim.parameters.get("version")
               or claim.parameters.get("installed")
               or "")
    range_spec = (claim.parameters.get("range")
                  or claim.parameters.get("affected_range")
                  or claim.parameters.get("range_spec")
                  or "")
    expected = claim.parameters.get("expected", True)

    if not version or not range_spec or not isinstance(version, str) \
            or not isinstance(range_spec, str):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="Version and range are required for a range check",
            method="version_compare", verification_source="version_compare",
        )

    ecosystem = _claim_ecosystem(claim, language)
    try:
        affected = in_range(version, range_spec, ecosystem)
    except ValueError as exc:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Unparsable version or range: {exc}", method="version_compare",
            error=str(exc)[:200], verification_source="version_compare",
        )

    matches = affected == bool(expected)
    cve = claim.parameters.get("cve", "")
    cve_text = f" for {cve}" if cve else ""
    return VerifiedClaim(
        claim=claim, verdict="VERIFIED" if matches else "REFUTED",
        method_confidence=0.95,
        evidence=(f"{version} {'is' if affected else 'is not'} in range "
                  f"'{range_spec}' ({ecosystem}){cve_text}"),
        method="version_compare", verification_source="version_compare",
    )


def verify_upgrade_fixes(claim: TypedClaim, repo_path: str, language: str) -> VerifiedClaim:
    """Offline fixed-in check: "upgrading to X fixes the CVE"."""
    upgrade = (claim.parameters.get("upgrade")
               or claim.parameters.get("version")
               or "")
    fixed_in = (claim.parameters.get("fixed_in")
                or claim.parameters.get("fixed_version")
                or "")
    installed = claim.parameters.get("installed", "")

    if not isinstance(upgrade, str) or not isinstance(fixed_in, str) \
            or not upgrade or not fixed_in:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="Upgrade and fixed_in versions are required",
            method="version_compare", verification_source="version_compare",
        )

    ecosystem = _claim_ecosystem(claim, language)
    try:
        reaches = fixes(upgrade, fixed_in, ecosystem)
    except ValueError as exc:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Unparsable version: {exc}", method="version_compare",
            error=str(exc)[:200], verification_source="version_compare",
        )

    evidence = (f"{upgrade} {'reaches' if reaches else 'does not reach'} "
                f"fixed version {fixed_in} ({ecosystem})")
    if isinstance(installed, str) and installed:
        try:
            below = compare(installed, fixed_in, ecosystem) < 0
            evidence += f"; installed {installed} is {'below' if below else 'at or above'} the fix"
        except ValueError:
            pass
    return VerifiedClaim(
        claim=claim, verdict="VERIFIED" if reaches else "REFUTED",
        method_confidence=0.95, evidence=evidence, method="version_compare",
        verification_source="version_compare",
    )
