"""VEX claim verification: agent statements about Red Hat CSAF assessments.

REDHAT_VEX_STATUS verifies "Red Hat Product Security assessed <CVE> as
<status> for <product_prefix>:<component>" against the authoritative
CSAF v2 document, so an agent citing a VEX status is checked rather
than trusted.

Matching rules follow the CVE triage contract:

- Exact product id match decides; the VEX URL and matched product id
  are the evidence.
- known_not_affected requires a justification code: a bare status
  refutes the claim.
- A component found only under a different product prefix is
  AMBIGUOUS_VEX_PRODUCT: unverifiable, never a verdict.
- No entry for the product/component refutes the claim.
- A document covering many unrelated components is normal for Red Hat
  CSAF; it is noted in evidence and never fails the claim by itself.

Network failures never fail the claim: unreachable documents are
UNVERIFIABLE with the reason recorded.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from code_claim_verifier.types import TypedClaim, VerifiedClaim

VEX_BASE_URL = "https://access.redhat.com/security/data/csaf/v2/vex"
_TIMEOUT_SECONDS = 30
_USER_AGENT = "code-claim-verifier/0.7"
_CVE_RE = re.compile(r"^CVE-(\d{4})-\d+$", re.IGNORECASE)

# CSAF product_status branch -> normalized status names used in claims.
_BRANCH_STATUSES = (
    "known_affected", "first_affected", "last_affected",
    "known_not_affected", "fixed", "under_investigation", "recommended",
)
_STATUS_PRIORITY = ("known_affected", "under_investigation",
                    "fixed", "known_not_affected")

# Per-run cache: cve url -> parsed document (dict), or None for a
# confirmed miss. Network errors are not cached; each claim retries.
_VEX_CACHE: dict[str, dict | None] = {}


def clear_vex_cache() -> None:
    """Reset the per-run VEX document cache (used by tests)."""
    _VEX_CACHE.clear()


def _fetch_vex_document(cve_id: str) -> tuple[dict | None, str | None]:
    """Fetch and cache the CSAF document for a CVE.

    Returns (document, None) or (None, reason) where reason is one of
    "no_vex_document" (confirmed 404) or "vex_unreachable".
    """
    match = _CVE_RE.match(cve_id.strip())
    if match is None:
        return None, "invalid_cve_id"
    url = f"{VEX_BASE_URL}/{match.group(1)}/{cve_id.strip().lower()}.json"
    if url in _VEX_CACHE:
        cached = _VEX_CACHE[url]
        return cached, None if cached is not None else "no_vex_document"

    request = urllib.request.Request(
        url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            document = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            _VEX_CACHE[url] = None
            return None, "no_vex_document"
        return None, "vex_unreachable"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None, "vex_unreachable"

    if not isinstance(document, dict):
        _VEX_CACHE[url] = None
        return None, "no_vex_document"
    _VEX_CACHE[url] = document
    return document, None


def _find_vulnerability(document: dict, cve_id: str) -> dict | None:
    for candidate in document.get("vulnerabilities") or []:
        if str(candidate.get("cve", "")).upper() == cve_id.strip().upper():
            return candidate
    return None


def verify_redhat_vex_status(
    claim: TypedClaim, repo_path: str, language: str,
) -> VerifiedClaim:
    cve_id = (claim.parameters.get("cve_id")
              or claim.parameters.get("cve")
              or "")
    expected_status = (claim.parameters.get("expected_status")
                       or claim.parameters.get("status")
                       or "")
    product_prefix = claim.parameters.get("product_prefix", "")
    component = claim.parameters.get("component", "")

    if not (cve_id and expected_status and product_prefix and component):
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence="REDHAT_VEX_STATUS requires cve_id, expected_status, "
                     "product_prefix, and component",
            method="vex_api",
        )

    document, reason = _fetch_vex_document(cve_id)
    if document is None:
        if reason == "invalid_cve_id":
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
                evidence=f"Invalid CVE id: {cve_id!r}", method="vex_api",
            )
        detail = ("no VEX document exists for this CVE"
                  if reason == "no_vex_document"
                  else "VEX file unreachable")
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"{detail} ({VEX_BASE_URL}/...)",
            method="vex_api",
        )

    vulnerability = _find_vulnerability(document, cve_id)
    if vulnerability is None:
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.80,
            evidence=f"VEX document for {cve_id} does not list this CVE",
            method="vex_api",
        )

    product_status = vulnerability.get("product_status") or {}
    exact_id = f"{product_prefix}:{component}"
    exact_statuses: list[str] = []
    component_elsewhere: set[str] = set()
    total_products = 0
    for branch, ids in product_status.items():
        if branch not in _BRANCH_STATUSES:
            continue
        for product_id in ids or []:
            total_products += 1
            if product_id == exact_id:
                exact_statuses.append(branch)
            elif product_id.rsplit(":", 1)[-1] == component:
                component_elsewhere.add(product_id.rsplit(":", 1)[0])

    stripped = cve_id.strip()
    url_note = (f"{VEX_BASE_URL}/{_CVE_RE.match(stripped).group(1)}/"
                f"{stripped.lower()}.json")

    if not exact_statuses:
        if component_elsewhere:
            return VerifiedClaim(
                claim=claim, verdict="UNVERIFIABLE", method_confidence=0.70,
                evidence=(f"AMBIGUOUS_VEX_PRODUCT: component {component} found "
                          f"only under other product prefix(es) "
                          f"{sorted(component_elsewhere)}, not "
                          f"{product_prefix}; the status does not apply to "
                          f"this product ({url_note})"),
                method="vex_api",
            )
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.80,
            evidence=(f"no VEX entry for {product_prefix}:{component} "
                      f"({url_note}); document lists {total_products} "
                      f"other products"),
            method="vex_api",
        )

    actual = next(
        (status for status in _STATUS_PRIORITY if status in exact_statuses),
        exact_statuses[0],
    )
    anomaly_note = (f"; document covers {total_products} products in total "
                    f"(cross-component entries are normal for Red Hat CSAF "
                    f"and do not affect this match)")

    if actual != expected_status:
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.85,
            evidence=(f"VEX lists {exact_id} as {actual}, not "
                      f"{expected_status} ({url_note}){anomaly_note}"),
            method="vex_api",
        )

    if expected_status == "known_not_affected":
        justification = None
        for flag in vulnerability.get("flags") or []:
            if exact_id in (flag.get("product_ids") or []):
                justification = flag.get("label")
                break
        if justification is None:
            return VerifiedClaim(
                claim=claim, verdict="REFUTED", method_confidence=0.85,
                evidence=(f"VEX lists {exact_id} as known_not_affected but "
                          f"without a justification code; a bare status is "
                          f"insufficient ({url_note})"),
                method="vex_api",
            )
        return VerifiedClaim(
            claim=claim, verdict="VERIFIED", method_confidence=0.90,
            evidence=(f"VEX: {exact_id} is known_not_affected with "
                      f"justification {justification} ({url_note})"
                      f"{anomaly_note}"),
            method="vex_api",
        )

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED", method_confidence=0.90,
        evidence=f"VEX: {exact_id} is {actual} ({url_note}){anomaly_note}",
        method="vex_api",
    )
