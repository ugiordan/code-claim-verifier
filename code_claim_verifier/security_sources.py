"""Assessment helpers for public security advisory data sources.

These APIs provide external context for a CVE or GitHub advisory. Missing
records and unavailable sources are evidence gaps, not proof of safety.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_API_URL = "https://api.github.com/advisories"

_TIMEOUT_SECONDS = 15
_USER_AGENT = "code-claim-verifier/0.8"

_KEV_CATALOG: dict[str, dict] | None = None
_NVD_CACHE: dict[str, dict | None] = {}
_GHSA_CACHE: dict[str, dict | None] = {}


@dataclass(frozen=True)
class KevAssessment:
    """CISA KEV catalog result; absence is not proof that a CVE is safe."""

    cve_id: str
    known_exploited: bool
    date_added: str | None
    due_date: str | None
    notes: str | None
    gap_reason: str | None = None


@dataclass(frozen=True)
class NvdAssessment:
    """NVD CVE result; an unavailable or missing record is an evidence gap."""

    cve_id: str
    cvss_score: float | None
    cvss_severity: str | None
    description: str | None
    cwe_ids: tuple[str, ...]
    gap_reason: str | None = None


@dataclass(frozen=True)
class GhsaAssessment:
    """GitHub Security Advisory result for a public GHSA identifier."""

    ghsa_id: str
    cve_id: str | None
    summary: str | None
    severity: str | None
    affected_packages: tuple[str, ...]
    published_at: str | None
    gap_reason: str | None = None


def clear_security_source_caches() -> None:
    """Reset per-run security source caches."""
    global _KEV_CATALOG
    _KEV_CATALOG = None
    _NVD_CACHE.clear()
    _GHSA_CACHE.clear()


def _request_json(url: str, *, accept: str = "application/json") -> object:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": accept},
    )
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
        return json.loads(response.read())


def _load_kev_catalog() -> tuple[dict[str, dict] | None, str | None]:
    global _KEV_CATALOG
    if _KEV_CATALOG is not None:
        return _KEV_CATALOG, None

    try:
        data = _request_json(KEV_CATALOG_URL)
    except urllib.error.HTTPError:
        return None, "kev_unavailable"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None, "kev_unavailable"

    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        return None, "kev_invalid_response"

    catalog: dict[str, dict] = {}
    for entry in data["vulnerabilities"]:
        if isinstance(entry, dict) and entry.get("cveID"):
            catalog[str(entry["cveID"]).upper()] = entry
    _KEV_CATALOG = catalog
    return catalog, None


def fetch_kev_assessment(cve_id: str) -> KevAssessment:
    """Fetch CISA's KEV catalog and assess whether it lists ``cve_id``."""
    cve = (cve_id or "").strip().upper()
    if not cve:
        return KevAssessment(
            cve_id=cve_id, known_exploited=False, date_added=None,
            due_date=None, notes=None, gap_reason="missing_parameters",
        )

    catalog, reason = _load_kev_catalog()
    if catalog is None:
        return KevAssessment(
            cve_id=cve_id, known_exploited=False, date_added=None,
            due_date=None, notes=None, gap_reason=reason,
        )

    entry = catalog.get(cve)
    if entry is None:
        return KevAssessment(
            cve_id=cve_id, known_exploited=False, date_added=None,
            due_date=None, notes=None, gap_reason="not_in_kev",
        )
    return KevAssessment(
        cve_id=cve_id,
        known_exploited=True,
        date_added=_optional_text(entry.get("dateAdded")),
        due_date=_optional_text(entry.get("dueDate")),
        notes=_optional_text(entry.get("notes")),
    )


def _fetch_nvd_record(cve: str) -> tuple[dict | None, str | None]:
    if cve in _NVD_CACHE:
        record = _NVD_CACHE[cve]
        return record, "nvd_not_found" if record is None else None

    url = f"{NVD_API_URL}?{urllib.parse.urlencode({'cveId': cve})}"
    try:
        data = _request_json(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            _NVD_CACHE[cve] = None
            return None, "nvd_not_found"
        if exc.code in {403, 429}:
            return None, "nvd_rate_limited"
        return None, "nvd_unavailable"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None, "nvd_unavailable"

    if not isinstance(data, dict):
        return None, "nvd_invalid_response"
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return None, "nvd_invalid_response"
    if not vulnerabilities:
        _NVD_CACHE[cve] = None
        return None, "nvd_not_found"
    first = vulnerabilities[0]
    if not isinstance(first, dict) or not isinstance(first.get("cve"), dict):
        return None, "nvd_invalid_response"
    record = first["cve"]
    _NVD_CACHE[cve] = record
    return record, None


def fetch_nvd_assessment(cve_id: str) -> NvdAssessment:
    """Query NVD API 2.0 for a CVE and extract its primary assessment data."""
    cve = (cve_id or "").strip().upper()
    if not cve:
        return NvdAssessment(
            cve_id=cve_id, cvss_score=None, cvss_severity=None,
            description=None, cwe_ids=(), gap_reason="missing_parameters",
        )

    record, reason = _fetch_nvd_record(cve)
    if record is None:
        return NvdAssessment(
            cve_id=cve_id, cvss_score=None, cvss_severity=None,
            description=None, cwe_ids=(), gap_reason=reason,
        )

    description = _english_description(record.get("descriptions"))
    cwe_ids = _nvd_cwe_ids(record.get("weaknesses"))
    score, severity = _nvd_cvss(record.get("metrics"))
    return NvdAssessment(
        cve_id=cve_id,
        cvss_score=score,
        cvss_severity=severity,
        description=description,
        cwe_ids=cwe_ids,
    )


def _fetch_ghsa_record(ghsa_id: str) -> tuple[dict | None, str | None]:
    if ghsa_id in _GHSA_CACHE:
        record = _GHSA_CACHE[ghsa_id]
        return record, "ghsa_not_found" if record is None else None

    url = f"{GHSA_API_URL}/{urllib.parse.quote(ghsa_id, safe='')}"
    try:
        data = _request_json(
            url, accept="application/vnd.github+json",
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            _GHSA_CACHE[ghsa_id] = None
            return None, "ghsa_not_found"
        return None, "ghsa_unavailable"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None, "ghsa_unavailable"

    if not isinstance(data, dict):
        return None, "ghsa_invalid_response"
    _GHSA_CACHE[ghsa_id] = data
    return data, None


def fetch_ghsa_assessment(ghsa_id: str) -> GhsaAssessment:
    """Fetch a public GitHub Security Advisory by GHSA identifier."""
    ghsa = (ghsa_id or "").strip().upper()
    if not ghsa:
        return GhsaAssessment(
            ghsa_id=ghsa_id, cve_id=None, summary=None, severity=None,
            affected_packages=(), published_at=None,
            gap_reason="missing_parameters",
        )

    record, reason = _fetch_ghsa_record(ghsa)
    if record is None:
        return GhsaAssessment(
            ghsa_id=ghsa_id, cve_id=None, summary=None, severity=None,
            affected_packages=(), published_at=None, gap_reason=reason,
        )

    vulnerabilities = record.get("vulnerabilities")
    packages: list[str] = []
    if isinstance(vulnerabilities, list):
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            package = vulnerability.get("package")
            if isinstance(package, dict) and package.get("name"):
                name = str(package["name"])
                if name not in packages:
                    packages.append(name)

    return GhsaAssessment(
        ghsa_id=ghsa_id,
        cve_id=_optional_text(record.get("cveId")),
        summary=_optional_text(record.get("summary")),
        severity=_optional_text(record.get("severity")),
        affected_packages=tuple(packages),
        published_at=_optional_text(record.get("publishedAt")),
    )


def _optional_text(value: object) -> str | None:
    return str(value) if value is not None and value != "" else None


def _english_description(descriptions: object) -> str | None:
    if not isinstance(descriptions, list):
        return None
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en" and item.get("value"):
            return str(item["value"])
    return None


def _nvd_cwe_ids(weaknesses: object) -> tuple[str, ...]:
    if not isinstance(weaknesses, list):
        return ()
    cwe_ids: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        descriptions = weakness.get("description")
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            if not isinstance(description, dict):
                continue
            value = description.get("value")
            if (
                isinstance(value, str)
                and value.startswith("CWE-")
                and value.removeprefix("CWE-").isdigit()
                and value not in cwe_ids
            ):
                cwe_ids.append(value)
    return tuple(cwe_ids)


def _nvd_cvss(metrics: object) -> tuple[float | None, str | None]:
    if not isinstance(metrics, dict):
        return None, None
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_set = metrics.get(metric_name)
        if not isinstance(metric_set, list) or not metric_set:
            continue
        entries = [
            entry for entry in metric_set if isinstance(entry, dict)
        ]
        if not entries:
            continue
        metric = next(
            (entry for entry in entries if entry.get("type") == "Primary"),
            entries[0],
        )
        cvss_data = metric.get("cvssData")
        if not isinstance(cvss_data, dict):
            continue
        raw_score = cvss_data.get("baseScore")
        try:
            score = float(raw_score) if raw_score is not None else None
        except (TypeError, ValueError):
            score = None
        severity = (
            cvss_data.get("baseSeverity")
            or metric.get("baseSeverity")
        )
        return score, _optional_text(severity)
    return None, None
