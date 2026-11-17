"""Cross-source agreement harness: VEX vs OSV vs Clair on shared triples.

The last axis of the CCV benchmark: for (CVE, package, version)
triples extracted from pinned Clair reports, run the three public
assessment APIs against each other and classify agreement. No LLM,
no labeling; the disagreement taxonomy comes from the gap_reason
vocabularies the APIs already emit.

Triple sources are Clair scans of public base images, pinned as
committed report files. The Clair leg is the report itself (an edge
means the scanner matched the CVE to the installed package version);
the OSV leg queries the distro ecosystem; the VEX leg asks Red Hat's
CSAF view of the same component under an RHEL product prefix, which
for distro-generic CVEs is expected to produce gap taxonomy as often
as status - that asymmetry is a finding, not a failure.
"""
from __future__ import annotations

import json
import logging
import os

from code_claim_verifier import (
    fetch_osv_assessment,
    fetch_redhat_vex_assessment,
)

logger = logging.getLogger(__name__)

DEFAULT_VEX_PRODUCT_PREFIX = "red_hat_enterprise_linux_9"


def extract_triples(report: dict, source_name: str) -> list[dict]:
    """Extract (cve, package, version) triples from a raw Clair report.

    Only edges are triples: Clair matched the vulnerability to the
    installed package version. The source package name (from the
    vulnerability record) is what distro ecosystems key on; the binary
    name and version describe what is installed.
    """
    packages = report.get("packages") or {}
    vulnerabilities = report.get("vulnerabilities") or {}
    environments = report.get("environments") or {}
    distributions = report.get("distributions") or {}

    distro_label = ""
    for envs in environments.values():
        for env in envs or []:
            dist = distributions.get(str(env.get("distribution_id") or ""))
            if dist and dist.get("did"):
                distro_label = str(dist["did"])
                if dist.get("version_id"):
                    distro_label += ":" + str(dist["version_id"])
                break
        if distro_label:
            break

    triples: list[dict] = []
    seen: set[tuple] = set()
    for pkg_id, vuln_ids in (report.get("package_vulnerabilities") or {}).items():
        binary = packages.get(pkg_id, {})
        for vuln_id in vuln_ids or []:
            vuln = vulnerabilities.get(vuln_id) or {}
            cve = vuln.get("name") or ""
            source_pkg = (vuln.get("package") or {}).get("name") or ""
            if not cve or not source_pkg:
                continue
            key = (cve, source_pkg, distro_label)
            if key in seen:
                continue
            seen.add(key)
            triples.append({
                "cve": cve,
                "source_package": source_pkg,
                "binary_package": binary.get("name", ""),
                "installed_version": binary.get("version", ""),
                "distro": distro_label,
                "clair_affected": True,
                "source_report": source_name,
            })
    return triples


def assess_triples(
    triples: list[dict],
    vex_product_prefix: str = DEFAULT_VEX_PRODUCT_PREFIX,
) -> list[dict]:
    """Run the OSV and VEX assessment APIs for every triple."""
    osv_ecosystems = {
        "debian:12": "Debian:12",
        "debian:13": "Debian:13",
    }
    results = []
    for i, triple in enumerate(triples, 1):
        ecosystem = osv_ecosystems.get(triple["distro"])
        if ecosystem is None:
            ecosystem = triple["distro"]
        osv = fetch_osv_assessment(
            triple["source_package"], triple["installed_version"],
            triple["cve"], ecosystem=ecosystem,
        )
        vex = fetch_redhat_vex_assessment(
            triple["cve"], vex_product_prefix, triple["source_package"],
        )
        results.append({
            **triple,
            "osv": {
                "vulnerability_count": osv.vulnerability_count,
                "matching_cve": osv.matching_cve,
                "gap_reason": osv.gap_reason,
            },
            "vex": {
                "status": vex.status,
                "justification": vex.justification,
                "match_quality": vex.match_quality,
                "gap_reason": vex.gap_reason,
            },
        })
        if i % 25 == 0:
            logger.info("assessed %d/%d", i, len(triples))
    return results


def classify(result: dict) -> dict:
    """Classify pairwise agreement and the VEX coverage view."""
    osv_match = result["osv"]["matching_cve"]
    osv_gap = result["osv"]["gap_reason"]
    if osv_gap:
        clair_osv = f"osv_gap:{osv_gap}"
    elif osv_match is True:
        clair_osv = "agree_affected"
    elif osv_match is False:
        clair_osv = "disagree_affectedness"
    else:
        clair_osv = "osv_indeterminate"

    vex = result["vex"]
    if vex["status"] is not None:
        vex_view = f"status:{vex['status']}"
    elif vex["gap_reason"]:
        vex_view = f"vex_gap:{vex['gap_reason']}"
    else:
        vex_view = "vex_indeterminate"

    return {"clair_vs_osv": clair_osv, "vex_view": vex_view}


def run(data_dir: str, output_path: str) -> dict:
    """Assess every triple in every pinned report and write results."""
    triples: list[dict] = []
    for name in sorted(os.listdir(data_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(data_dir, name)) as handle:
            report = json.load(handle)
        found = extract_triples(report, name)
        logger.info("%s: %d triples", name, len(found))
        triples.extend(found)

    dedup: dict[tuple, dict] = {}
    for triple in triples:
        key = (triple["cve"], triple["source_package"], triple["distro"])
        dedup.setdefault(key, triple)
    triples = list(dedup.values())
    logger.info("total unique triples: %d", len(triples))

    results = assess_triples(triples)
    for result in results:
        result["classification"] = classify(result)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as handle:
        for result in results:
            handle.write(json.dumps(result) + "\n")

    from collections import Counter
    summary = {
        "triples": len(results),
        "clair_vs_osv": dict(Counter(r["classification"]["clair_vs_osv"] for r in results)),
        "vex_view": dict(Counter(r["classification"]["vex_view"] for r in results)),
    }
    logger.info("summary: %s", json.dumps(summary, indent=1))
    return summary
