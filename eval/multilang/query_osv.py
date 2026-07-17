from __future__ import annotations

import logging
import time

import requests

from eval.cybergym.utils import save_jsonl
from eval.multilang.constants import ECOSYSTEMS, CandidateStatus

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_MIN_DESC_LEN = 50
_MIN_YEAR = 2020
_MEDIUM_PLUS = {"MEDIUM", "HIGH", "CRITICAL"}


def _extract_fix_commit(entry: dict) -> str | None:
    for affected in entry.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _extract_repo_url(entry: dict) -> str | None:
    for affected in entry.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            repo = rng.get("repo", "")
            if "github.com" in repo:
                return repo.rstrip("/").removesuffix(".git")
    return None


def _extract_severity(entry: dict) -> str:
    for sev in entry.get("severity", []):
        score_str = sev.get("score", "")
        if "CVSS" not in score_str:
            continue
        try:
            parts = score_str.split("/")
            for part in parts:
                if part.startswith("AV:"):
                    continue
            base = float(score_str.split("/")[0].split(":")[-1]) if ":" in score_str else 0
        except (ValueError, IndexError):
            pass
        if "/AV:" in score_str:
            try:
                base_score = _cvss_base_from_vector(score_str)
                if base_score >= 9.0:
                    return "CRITICAL"
                if base_score >= 7.0:
                    return "HIGH"
                if base_score >= 4.0:
                    return "MEDIUM"
                return "LOW"
            except Exception:
                pass
    for sev in entry.get("severity", []):
        if sev.get("type") == "ECOSYSTEM":
            text = sev.get("score", "").upper()
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if level in text:
                    return level
    db_severity = entry.get("database_specific", {}).get("severity")
    if db_severity:
        return db_severity.upper()
    return "UNKNOWN"


def _cvss_base_from_vector(vector: str) -> float:
    parts = {}
    for segment in vector.split("/"):
        if ":" in segment:
            key, val = segment.split(":", 1)
            parts[key] = val
    av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_scores = {"L": 0.77, "H": 0.44}
    pr_scores = {"N": 0.85, "L": 0.62, "H": 0.27}
    ui_scores = {"N": 0.85, "R": 0.62}
    impact_map = {"H": 0.56, "L": 0.22, "N": 0.0}
    av = av_scores.get(parts.get("AV", "N"), 0.85)
    ac = ac_scores.get(parts.get("AC", "L"), 0.77)
    pr = pr_scores.get(parts.get("PR", "N"), 0.85)
    ui = ui_scores.get(parts.get("UI", "N"), 0.85)
    c = impact_map.get(parts.get("C", "N"), 0.0)
    i = impact_map.get(parts.get("I", "N"), 0.0)
    a = impact_map.get(parts.get("A", "N"), 0.0)
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    base = min(impact + exploitability, 10.0)
    return round(base, 1)


def _parse_osv_entry(entry: dict) -> dict | None:
    osv_id = entry.get("id", "")
    summary = entry.get("summary", "")
    details = entry.get("details", "")
    description = details if len(details) > len(summary) else summary
    if len(description) < _MIN_DESC_LEN:
        return None

    published = entry.get("published", "")
    if published and int(published[:4]) < _MIN_YEAR:
        return None

    fix_commit = _extract_fix_commit(entry)
    if not fix_commit:
        return None

    repo_url = _extract_repo_url(entry)
    if not repo_url:
        return None

    severity = _extract_severity(entry)

    aliases = entry.get("aliases", [])
    cve_id = next((a for a in aliases if a.startswith("CVE-")), "")

    package_name = ""
    ecosystem = ""
    for affected in entry.get("affected", []):
        pkg = affected.get("package", {})
        package_name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")
        if package_name:
            break

    return {
        "osv_id": osv_id,
        "cve_id": cve_id,
        "ecosystem": ecosystem,
        "package": package_name,
        "repo_url": repo_url,
        "fix_commit": fix_commit,
        "description": description,
        "severity": severity,
        "published_date": published[:10] if published else "",
        "status": CandidateStatus.PENDING,
    }


def _get_star_count(repo_url: str) -> int | None:
    import subprocess
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 2:
        return None
    owner_repo = f"{parts[-2]}/{parts[-1]}"
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{owner_repo}", "--jq", ".stargazers_count"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def query_ecosystem(ecosystem: str, min_stars: int = 100) -> list[dict]:
    logger.info("Querying OSV for ecosystem: %s", ecosystem)
    candidates: list[dict] = []
    page_token = ""
    seen_ids: set[str] = set()

    while True:
        payload: dict = {"package": {"ecosystem": ecosystem}}
        if page_token:
            payload["page_token"] = page_token

        try:
            resp = requests.post(OSV_QUERY_URL, json=payload, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.error("OSV query failed for %s: %s", ecosystem, e)
            break

        data = resp.json()
        vulns = data.get("vulns", [])
        if not vulns:
            break

        for entry in vulns:
            osv_id = entry.get("id", "")
            if osv_id in seen_ids:
                continue
            seen_ids.add(osv_id)

            parsed = _parse_osv_entry(entry)
            if parsed is None:
                continue

            severity = parsed.get("severity", "UNKNOWN")
            if severity not in _MEDIUM_PLUS:
                continue

            candidates.append(parsed)

        page_token = data.get("next_page_token", "")
        if not page_token:
            break
        time.sleep(1)

    logger.info("Found %d raw candidates for %s", len(candidates), ecosystem)

    if min_stars > 0:
        filtered = []
        seen_repos: dict[str, int | None] = {}
        for c in candidates:
            repo = c["repo_url"]
            if repo not in seen_repos:
                seen_repos[repo] = _get_star_count(repo)
                time.sleep(0.5)
            stars = seen_repos[repo]
            if stars is not None and stars >= min_stars:
                filtered.append(c)
        logger.info("After star filter (>=%d): %d candidates for %s",
                     min_stars, len(filtered), ecosystem)
        candidates = filtered

    return candidates


def run_query(output_path: str, ecosystems: list[str] | None = None,
              min_stars: int = 100) -> None:
    if ecosystems is None:
        ecosystems = list(ECOSYSTEMS.values())

    all_candidates: list[dict] = []
    for eco in ecosystems:
        candidates = query_ecosystem(eco, min_stars=min_stars)
        all_candidates.extend(candidates)
        logger.info("Total so far: %d", len(all_candidates))

    save_jsonl(all_candidates, output_path)
    logger.info("Wrote %d candidates to %s", len(all_candidates), output_path)
