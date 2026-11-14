"""Clair vulnerability report ingestion.

A Clair (claircore) vulnerability report is treated as a pinned,
deterministic evidence artifact: scanners such as Quay/Clair or
clairctl produce the JSON offline, and a claim carries a path to it.
Live Clair API calls are deliberately avoided; cold matcher
initialization is slow and deployments differ in auth and reachability.

The report shape follows claircore's VulnerabilityReport JSON:
``packages`` maps ids to installed (binary) packages,
``vulnerabilities`` maps ids to records whose ``name`` holds the CVE
identifier, and ``package_vulnerabilities`` maps an installed package
id to the vulnerability ids affecting it. Distro context comes from
``environments`` and ``distributions``.

A missing match is not proof of safety: an empty result means the
report does not link the CVE to the package, nothing more.
"""
from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class ClairPackage:
    id: str
    name: str
    version: str
    kind: str


@dataclass(frozen=True)
class ClairVulnerability:
    id: str
    name: str
    fixed_in_version: str | None
    severity: str | None
    normalized_severity: str | None
    aliases: tuple[str, ...]
    updater: str | None


@dataclass(frozen=True)
class ClairReport:
    manifest_hash: str | None
    distro: str | None
    packages: dict[str, ClairPackage]
    vulnerabilities: dict[str, ClairVulnerability]
    package_vulnerabilities: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class ClairAssessment:
    cve_id: str
    package: str
    affected: bool | None
    installed_version: str | None
    fixed_in_version: str | None
    severity: str | None
    normalized_severity: str | None
    distro: str | None
    manifest_hash: str | None
    updater: str | None
    gap_reason: str | None = None


def parse_clair_report(data: object) -> ClairReport:
    """Normalize a parsed claircore VulnerabilityReport JSON object.

    Malformed entries are skipped rather than rejected so a partially
    odd report still yields the evidence it does contain.
    Raises ValueError when the top level is not a JSON object.
    """
    if not isinstance(data, dict):
        raise ValueError("Clair report must be a JSON object")
    for field in ("packages", "vulnerabilities", "package_vulnerabilities"):
        value = data.get(field)
        if value is not None and not isinstance(value, dict):
            raise ValueError(f"Clair report field {field!r} must be an object")

    packages: dict[str, ClairPackage] = {}
    for pid, raw in (data.get("packages") or {}).items():
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "")
        if not name:
            continue
        packages[str(pid)] = ClairPackage(
            id=str(pid),
            name=name,
            version=str(raw.get("version") or ""),
            kind=str(raw.get("kind") or ""),
        )

    vulnerabilities: dict[str, ClairVulnerability] = {}
    for vid, raw in (data.get("vulnerabilities") or {}).items():
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "")
        if not name:
            continue
        aliases = tuple(
            alias for alias in (raw.get("Aliases") or []) if isinstance(alias, str)
        )
        vulnerabilities[str(vid)] = ClairVulnerability(
            id=str(vid),
            name=name,
            fixed_in_version=str(raw.get("fixed_in_version") or "") or None,
            severity=str(raw.get("severity") or "") or None,
            normalized_severity=str(raw.get("normalized_severity") or "") or None,
            aliases=aliases,
            updater=str(raw.get("updater") or "") or None,
        )

    edges: dict[str, tuple[str, ...]] = {}
    for pid, vids in (data.get("package_vulnerabilities") or {}).items():
        if not isinstance(vids, list):
            continue
        edges[str(pid)] = tuple(str(vid) for vid in vids if vid)

    return ClairReport(
        manifest_hash=str(data["manifest_hash"]) if data.get("manifest_hash") else None,
        distro=_report_distro(data),
        packages=packages,
        vulnerabilities=vulnerabilities,
        package_vulnerabilities=edges,
    )


def load_clair_report(path: str) -> ClairReport:
    """Read and parse a Clair report JSON file."""
    with open(path, "rb") as handle:
        return parse_clair_report(json.loads(handle.read()))


def fetch_clair_assessment(
    report: ClairReport, cve_id: str, package: str,
) -> ClairAssessment:
    """Assess one CVE/package pair against a parsed Clair report.

    Offline and deterministic: no network access, the report is the
    only evidence consulted.
    """
    cve = (cve_id or "").strip().upper()
    package = (package or "").strip()

    matched = [
        vuln for vuln in report.vulnerabilities.values()
        if vuln.name.upper() == cve
        or cve in {alias.upper() for alias in vuln.aliases}
    ]
    pkg_ids = [pid for pid, pkg in report.packages.items() if pkg.name == package]
    pkg_versions = {report.packages[pid].version for pid in pkg_ids}
    installed = pkg_versions.pop() if len(pkg_versions) == 1 else None

    if not matched:
        return ClairAssessment(
            cve_id=cve_id, package=package, affected=None,
            installed_version=installed, fixed_in_version=None,
            severity=None, normalized_severity=None, distro=report.distro,
            manifest_hash=report.manifest_hash, updater=None,
            gap_reason="cve_not_in_report",
        )

    linked_ids = {
        vid
        for pid in pkg_ids
        for vid in report.package_vulnerabilities.get(pid, ())
    }
    linked = [vuln for vuln in matched if vuln.id in linked_ids]
    chosen = linked[0] if linked else matched[0]

    if not pkg_ids:
        return ClairAssessment(
            cve_id=cve_id, package=package, affected=None,
            installed_version=None, fixed_in_version=chosen.fixed_in_version,
            severity=chosen.severity,
            normalized_severity=chosen.normalized_severity,
            distro=report.distro, manifest_hash=report.manifest_hash,
            updater=chosen.updater, gap_reason="package_not_in_report",
        )

    if linked:
        # The installed version must come from the package the report
        # actually linked to the vulnerability, not from an arbitrary
        # same-named package.
        linked_versions = {
            report.packages[pid].version
            for pid in pkg_ids
            if linked_ids.intersection(report.package_vulnerabilities.get(pid, ()))
        }
        if len(linked_versions) == 1:
            installed = linked_versions.pop()

    if not linked:
        # A CVE that the report does not link to an installed package
        # is an evidence gap, not proof of safety.
        return ClairAssessment(
            cve_id=cve_id, package=package, affected=None,
            installed_version=installed,
            fixed_in_version=chosen.fixed_in_version,
            severity=chosen.severity,
            normalized_severity=chosen.normalized_severity,
            distro=report.distro, manifest_hash=report.manifest_hash,
            updater=chosen.updater, gap_reason="cve_not_linked_to_package",
        )

    return ClairAssessment(
        cve_id=cve_id, package=package, affected=True,
        installed_version=installed,
        fixed_in_version=chosen.fixed_in_version,
        severity=chosen.severity,
        normalized_severity=chosen.normalized_severity,
        distro=report.distro, manifest_hash=report.manifest_hash,
        updater=chosen.updater, gap_reason=None,
    )


def _report_distro(data: dict) -> str | None:
    distributions = data.get("distributions") or {}
    for envs in (data.get("environments") or {}).values():
        if not isinstance(envs, list):
            continue
        for env in envs:
            if not isinstance(env, dict):
                continue
            dist = distributions.get(str(env.get("distribution_id") or ""))
            if isinstance(dist, dict) and dist.get("did"):
                label = str(dist["did"])
                if dist.get("version_id"):
                    label += "/" + str(dist["version_id"])
                return label
    return None
