from __future__ import annotations

import io
import json
import logging
import os
import tempfile
import time
import zipfile

import requests

from eval.cybergym.utils import save_jsonl
from eval.multilang.constants import ECOSYSTEMS, CandidateStatus

logger = logging.getLogger(__name__)

OSV_GCS_URL = "https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip"
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


def _download_ecosystem_zip(ecosystem: str, cache_dir: str | None = None) -> list[dict]:
    url = OSV_GCS_URL.format(ecosystem=ecosystem)
    logger.info("Downloading OSV bulk data for %s from %s", ecosystem, url)

    if cache_dir:
        cached = os.path.join(cache_dir, f"{ecosystem.replace('/', '_')}.zip")
        if os.path.isfile(cached):
            logger.info("Using cached zip: %s", cached)
            with zipfile.ZipFile(cached) as zf:
                return _parse_zip(zf)

    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.error("Failed to download %s: %s", url, e)
        return []

    content = resp.content
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        with open(cached, "wb") as f:
            f.write(content)

    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        return _parse_zip(zf)


def _parse_zip(zf: zipfile.ZipFile) -> list[dict]:
    entries = []
    for name in zf.namelist():
        if not name.endswith(".json"):
            continue
        try:
            data = json.loads(zf.read(name))
            entries.append(data)
        except (json.JSONDecodeError, KeyError):
            continue
    return entries


def query_ecosystem(ecosystem: str, min_stars: int = 100,
                    cache_dir: str | None = None) -> list[dict]:
    logger.info("Processing ecosystem: %s", ecosystem)

    raw_entries = _download_ecosystem_zip(ecosystem, cache_dir=cache_dir)
    logger.info("Downloaded %d entries for %s", len(raw_entries), ecosystem)

    candidates: list[dict] = []
    seen_ids: set[str] = set()

    for entry in raw_entries:
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

    logger.info("After filtering: %d candidates for %s", len(candidates), ecosystem)

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
              min_stars: int = 100, cache_dir: str | None = None) -> None:
    if ecosystems is None:
        ecosystems = list(ECOSYSTEMS.values())

    if cache_dir is None:
        cache_dir = os.path.join(os.path.dirname(output_path), ".osv_cache")

    all_candidates: list[dict] = []
    for eco in ecosystems:
        candidates = query_ecosystem(eco, min_stars=min_stars, cache_dir=cache_dir)
        all_candidates.extend(candidates)
        logger.info("Total so far: %d", len(all_candidates))

    save_jsonl(all_candidates, output_path)
    logger.info("Wrote %d candidates to %s", len(all_candidates), output_path)
