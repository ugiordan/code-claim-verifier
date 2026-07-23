from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

from eval.multilang.query_osv import (
    _parse_osv_entry,
    _extract_fix_info,
    _extract_severity,
)


def _make_osv_entry(
    osv_id="GHSA-test-0001",
    summary="Test vuln in example package",
    details="A detailed description of the vulnerability that is long enough.",
    package_name="github.com/example/pkg",
    ecosystem="Go",
    fix_commit="abc123def456",
    repo_url="https://github.com/example/pkg",
    severity="HIGH",
    published="2023-06-15T00:00:00Z",
):
    entry = {
        "id": osv_id,
        "summary": summary,
        "details": details,
        "published": published,
        "affected": [
            {
                "package": {"name": package_name, "ecosystem": ecosystem},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": repo_url,
                        "events": [
                            {"introduced": "0"},
                            {"fixed": fix_commit},
                        ],
                    }
                ],
            }
        ],
        "severity": [{"type": "CVSS_V3", "score": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "aliases": ["CVE-2023-99999"],
    }
    return entry


class TestExtractFixInfo:
    def test_extracts_from_git_range(self):
        entry = _make_osv_entry(fix_commit="abc123", repo_url="https://github.com/example/pkg")
        commit, repo, eco, pkg = _extract_fix_info(entry)
        assert commit == "abc123"
        assert repo == "https://github.com/example/pkg"
        assert eco == "Go"
        assert pkg == "github.com/example/pkg"

    def test_returns_none_when_no_git_range(self):
        entry = _make_osv_entry()
        entry["affected"][0]["ranges"] = [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
        ]
        commit, repo, eco, pkg = _extract_fix_info(entry)
        assert commit is None
        assert repo is None
        assert eco == ""
        assert pkg == ""

    def test_returns_none_for_non_github(self):
        entry = _make_osv_entry(repo_url="https://gitlab.com/example/pkg")
        commit, repo, eco, pkg = _extract_fix_info(entry)
        assert commit is None
        assert repo is None
        assert eco == ""
        assert pkg == ""

    def test_extracts_from_commit_url_in_references(self):
        entry = _make_osv_entry()
        entry["affected"][0]["ranges"] = []
        entry["references"] = [
            {"url": "https://github.com/example/pkg/commit/abc123def"}
        ]
        commit, repo, eco, pkg = _extract_fix_info(entry)
        assert commit == "abc123def"
        assert repo == "https://github.com/example/pkg"
        assert eco == "Go"
        assert pkg == "github.com/example/pkg"


class TestExtractSeverity:
    def test_parses_cvss_high(self):
        entry = _make_osv_entry()
        sev = _extract_severity(entry)
        assert sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_returns_unknown_when_missing(self):
        entry = _make_osv_entry()
        entry.pop("severity", None)
        assert _extract_severity(entry) == "UNKNOWN"


class TestParseOsvEntry:
    def test_parses_valid_entry(self):
        entry = _make_osv_entry()
        result = _parse_osv_entry(entry)
        assert result is not None
        assert result["osv_id"] == "GHSA-test-0001"
        assert result["fix_commit"] == "abc123def456"
        assert result["ecosystem"] == "Go"
        assert result["status"] == "pending"

    def test_rejects_short_description(self):
        entry = _make_osv_entry(summary="Short", details="")
        assert _parse_osv_entry(entry) is None

    def test_rejects_no_fix_commit(self):
        entry = _make_osv_entry()
        entry["affected"][0]["ranges"] = []
        assert _parse_osv_entry(entry) is None

    def test_rejects_pre_2020(self):
        entry = _make_osv_entry(published="2019-01-01T00:00:00Z")
        assert _parse_osv_entry(entry) is None
