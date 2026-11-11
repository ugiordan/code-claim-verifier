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
from dataclasses import dataclass
from typing import Literal

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

VexMatchQuality = Literal["exact", "ambiguous", "none", "unavailable"]


@dataclass(frozen=True)
class VexAssessment:
    cve_id: str
    requested_product_id: str
    status: str | None
    justification: str | None
    product_id: str | None
    match_quality: VexMatchQuality
    gap_reason: str | None
    source_url: str | None
    total_products: int = 0
    other_product_prefixes: tuple[str, ...] = ()


def clear_vex_cache() -> None:
    """Reset the per-run VEX document cache (used by tests)."""
    _VEX_CACHE.clear()


def _vex_document_url(cve_id: str) -> str | None:
    match = _CVE_RE.match(cve_id.strip())
    if match is None:
        return None
    return f"{VEX_BASE_URL}/{match.group(1)}/{cve_id.strip().lower()}.json"


def _fetch_vex_document(cve_id: str) -> tuple[dict | None, str | None]:
    """Fetch and cache the CSAF document for a CVE.

    Returns (document, None) or (None, reason) where reason is one of
    "no_vex_document" (confirmed 404) or "vex_unreachable".
    """
    url = _vex_document_url(cve_id)
    if url is None:
        return None, "invalid_cve_id"
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


def fetch_redhat_vex_assessment(
    cve_id: str, product_prefix: str, component: str,
) -> VexAssessment:
    """Fetch Red Hat CSAF/VEX data and assess one product component."""
    requested_product_id = f"{product_prefix}:{component}"
    source_url = _vex_document_url(cve_id)
    if not (cve_id and product_prefix and component):
        return VexAssessment(
            cve_id=cve_id,
            requested_product_id=requested_product_id,
            status=None,
            justification=None,
            product_id=None,
            match_quality="unavailable",
            gap_reason="missing_parameters",
            source_url=source_url,
        )

    document, reason = _fetch_vex_document(cve_id)
    if document is None:
        return VexAssessment(
            cve_id=cve_id,
            requested_product_id=requested_product_id,
            status=None,
            justification=None,
            product_id=None,
            match_quality="unavailable",
            gap_reason=reason or "vex_unreachable",
            source_url=source_url,
        )

    vulnerability = _find_vulnerability(document, cve_id)
    if vulnerability is None:
        return VexAssessment(
            cve_id=cve_id,
            requested_product_id=requested_product_id,
            status=None,
            justification=None,
            product_id=None,
            match_quality="none",
            gap_reason="cve_not_in_document",
            source_url=source_url,
        )

    product_status = vulnerability.get("product_status") or {}
    exact_id = requested_product_id
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

    if not exact_statuses:
        if component_elsewhere:
            return VexAssessment(
                cve_id=cve_id,
                requested_product_id=requested_product_id,
                status=None,
                justification=None,
                product_id=None,
                match_quality="ambiguous",
                gap_reason="component_under_different_product_prefix",
                source_url=source_url,
                total_products=total_products,
                other_product_prefixes=tuple(sorted(component_elsewhere)),
            )
        return VexAssessment(
            cve_id=cve_id,
            requested_product_id=requested_product_id,
            status=None,
            justification=None,
            product_id=None,
            match_quality="none",
            gap_reason="product_not_in_document",
            source_url=source_url,
            total_products=total_products,
        )

    actual = next(
        (status for status in _STATUS_PRIORITY if status in exact_statuses),
        exact_statuses[0],
    )

    justification = None
    if actual == "known_not_affected":
        for flag in vulnerability.get("flags") or []:
            if exact_id in (flag.get("product_ids") or []):
                justification = flag.get("label")
                break

    return VexAssessment(
        cve_id=cve_id,
        requested_product_id=requested_product_id,
        status=actual,
        justification=justification,
        product_id=exact_id,
        match_quality="exact",
        gap_reason=("missing_justification"
                    if actual == "known_not_affected" and justification is None
                    else None),
        source_url=source_url,
        total_products=total_products,
    )


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

    assessment = fetch_redhat_vex_assessment(cve_id, product_prefix, component)
    if assessment.gap_reason == "invalid_cve_id":
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"Invalid CVE id: {cve_id!r}", method="vex_api",
        )
    if assessment.gap_reason in {"no_vex_document", "vex_unreachable"}:
        detail = ("no VEX document exists for this CVE"
                  if assessment.gap_reason == "no_vex_document"
                  else "VEX file unreachable")
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"{detail} ({VEX_BASE_URL}/...)", method="vex_api",
        )
    if assessment.gap_reason == "cve_not_in_document":
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.80,
            evidence=f"VEX document for {cve_id} does not list this CVE",
            method="vex_api",
        )
    if assessment.match_quality == "ambiguous":
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.70,
            evidence=(f"AMBIGUOUS_VEX_PRODUCT: component {component} found "
                      f"only under other product prefix(es) "
                      f"{list(assessment.other_product_prefixes)}, not "
                      f"{product_prefix}; the status does not apply to "
                      f"this product ({assessment.source_url})"),
            method="vex_api",
        )
    if assessment.gap_reason == "product_not_in_document":
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.80,
            evidence=(f"no VEX entry for {product_prefix}:{component} "
                      f"({assessment.source_url}); document lists "
                      f"{assessment.total_products} other products"),
            method="vex_api",
        )
    if assessment.status is None:
        return VerifiedClaim(
            claim=claim, verdict="UNVERIFIABLE", method_confidence=0.0,
            evidence=f"VEX assessment unavailable ({assessment.gap_reason})",
            method="vex_api",
        )

    actual = assessment.status
    anomaly_note = (f"; document covers {assessment.total_products} products in total "
                    f"(cross-component entries are normal for Red Hat CSAF "
                    f"and do not affect this match)")

    if actual != expected_status:
        return VerifiedClaim(
            claim=claim, verdict="REFUTED", method_confidence=0.85,
            evidence=(f"VEX lists {assessment.product_id} as {actual}, not "
                      f"{expected_status} ({assessment.source_url}){anomaly_note}"),
            method="vex_api",
        )

    if expected_status == "known_not_affected":
        if assessment.justification is None:
            return VerifiedClaim(
                claim=claim, verdict="REFUTED", method_confidence=0.85,
                evidence=(f"VEX lists {assessment.product_id} as known_not_affected but "
                          f"without a justification code; a bare status is "
                          f"insufficient ({assessment.source_url})"),
                method="vex_api",
            )
        return VerifiedClaim(
            claim=claim, verdict="VERIFIED", method_confidence=0.90,
            evidence=(f"VEX: {assessment.product_id} is known_not_affected with "
                      f"justification {assessment.justification} ({assessment.source_url})"
                      f"{anomaly_note}"),
            method="vex_api",
        )

    return VerifiedClaim(
        claim=claim, verdict="VERIFIED", method_confidence=0.90,
        evidence=(f"VEX: {assessment.product_id} is {actual} "
                  f"({assessment.source_url}){anomaly_note}"),
        method="vex_api",
    )
