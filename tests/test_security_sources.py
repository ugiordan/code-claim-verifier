import json
import urllib.error

import pytest

from code_claim_verifier import (
    GhsaAssessment,
    KevAssessment,
    NvdAssessment,
    fetch_ghsa_assessment,
    fetch_kev_assessment,
    fetch_nvd_assessment,
)
from code_claim_verifier import security_sources


class FakeResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


@pytest.fixture(autouse=True)
def clear_caches():
    security_sources.clear_security_source_caches()
    yield
    security_sources.clear_security_source_caches()


def http_error(code):
    return urllib.error.HTTPError(
        "https://example.test", code, "HTTP error", None, None,
    )


def test_fetch_kev_assessment_and_caches_catalog(monkeypatch):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        return FakeResponse({
            "vulnerabilities": [{
                "cveID": "CVE-2024-1234",
                "dateAdded": "2024-01-02",
                "dueDate": "2024-02-02",
                "notes": "Known exploitation",
            }],
        })

    monkeypatch.setattr(security_sources.urllib.request, "urlopen", fake_urlopen)

    assessment = fetch_kev_assessment("cve-2024-1234")
    second = fetch_kev_assessment("CVE-2024-9999")

    assert assessment == KevAssessment(
        cve_id="cve-2024-1234", known_exploited=True,
        date_added="2024-01-02", due_date="2024-02-02",
        notes="Known exploitation",
    )
    assert second.gap_reason == "not_in_kev"
    assert calls == [(security_sources.KEV_CATALOG_URL, 15)]


def test_fetch_kev_assessment_network_error_returns_gap(monkeypatch):
    def fail(*_args, **_kwargs):
        raise OSError("offline")

    monkeypatch.setattr(security_sources.urllib.request, "urlopen", fail)

    assessment = fetch_kev_assessment("CVE-2024-1234")

    assert assessment.known_exploited is False
    assert assessment.gap_reason == "kev_unavailable"


def test_fetch_kev_assessment_catalog_404_returns_gap(monkeypatch):
    def fail(*_args, **_kwargs):
        raise http_error(404)

    monkeypatch.setattr(security_sources.urllib.request, "urlopen", fail)

    assessment = fetch_kev_assessment("CVE-2024-1234")

    assert assessment.gap_reason == "kev_unavailable"


def test_fetch_nvd_assessment_and_caches_record(monkeypatch):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        return FakeResponse({
            "vulnerabilities": [{
                "cve": {
                    "descriptions": [{"lang": "en", "value": "Example CVE"}],
                    "weaknesses": [{
                        "description": [{"lang": "en", "value": "CWE-79"}],
                    }],
                    "metrics": {
                        "cvssMetricV31": [{
                            "type": "Primary",
                            "cvssData": {
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH",
                            },
                        }],
                    },
                },
            }],
        })

    monkeypatch.setattr(security_sources.urllib.request, "urlopen", fake_urlopen)

    assessment = fetch_nvd_assessment("cve-2024-1234")
    second = fetch_nvd_assessment("cve-2024-1234")

    assert assessment == NvdAssessment(
        cve_id="cve-2024-1234", cvss_score=8.1, cvss_severity="HIGH",
        description="Example CVE", cwe_ids=("CWE-79",),
    )
    assert second == assessment
    assert len(calls) == 1
    assert "cveId=CVE-2024-1234" in calls[0][0]


def test_fetch_nvd_assessment_network_error_returns_gap(monkeypatch):
    def fail(*_args, **_kwargs):
        raise OSError("offline")

    monkeypatch.setattr(security_sources.urllib.request, "urlopen", fail)

    assessment = fetch_nvd_assessment("CVE-2024-1234")

    assert assessment.gap_reason == "nvd_unavailable"


@pytest.mark.parametrize(
    ("status", "reason"),
    [(404, "nvd_not_found"), (429, "nvd_rate_limited"), (403, "nvd_rate_limited")],
)
def test_fetch_nvd_assessment_http_errors_return_gap(monkeypatch, status, reason):
    def fail(*_args, **_kwargs):
        raise http_error(status)

    monkeypatch.setattr(security_sources.urllib.request, "urlopen", fail)

    assessment = fetch_nvd_assessment("CVE-2024-1234")

    assert assessment.gap_reason == reason


def test_fetch_nvd_assessment_empty_results_returns_not_found(monkeypatch):
    monkeypatch.setattr(
        security_sources.urllib.request, "urlopen",
        lambda *_args, **_kwargs: FakeResponse({"vulnerabilities": []}),
    )

    assessment = fetch_nvd_assessment("CVE-2024-1234")

    assert assessment.gap_reason == "nvd_not_found"


def test_fetch_ghsa_assessment_and_caches_record(monkeypatch):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, request.headers, timeout))
        return FakeResponse({
            "ghsaId": "GHSA-1234-5678-90ab",
            "cveId": "CVE-2024-1234",
            "summary": "Example advisory",
            "severity": "HIGH",
            "publishedAt": "2024-01-02T03:04:05Z",
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "example"}},
                {"package": {"ecosystem": "npm", "name": "example"}},
                {"package": {"ecosystem": "PyPI", "name": "another"}},
            ],
        })

    monkeypatch.setattr(security_sources.urllib.request, "urlopen", fake_urlopen)

    assessment = fetch_ghsa_assessment("ghsa-1234-5678-90ab")
    second = fetch_ghsa_assessment("ghsa-1234-5678-90ab")

    assert assessment == GhsaAssessment(
        ghsa_id="ghsa-1234-5678-90ab",
        cve_id="CVE-2024-1234",
        summary="Example advisory",
        severity="HIGH",
        affected_packages=("example", "another"),
        published_at="2024-01-02T03:04:05Z",
    )
    assert second == assessment
    assert len(calls) == 1
    assert calls[0][0].endswith("/GHSA-1234-5678-90AB")
    assert calls[0][1]["Accept"] == "application/vnd.github+json"


def test_fetch_ghsa_assessment_network_error_returns_gap(monkeypatch):
    def fail(*_args, **_kwargs):
        raise OSError("offline")

    monkeypatch.setattr(security_sources.urllib.request, "urlopen", fail)

    assessment = fetch_ghsa_assessment("GHSA-1234-5678-90ab")

    assert assessment.gap_reason == "ghsa_unavailable"


def test_fetch_ghsa_assessment_404_returns_not_found(monkeypatch):
    def fail(*_args, **_kwargs):
        raise http_error(404)

    monkeypatch.setattr(security_sources.urllib.request, "urlopen", fail)

    assessment = fetch_ghsa_assessment("GHSA-1234-5678-90ab")

    assert assessment.gap_reason == "ghsa_not_found"
