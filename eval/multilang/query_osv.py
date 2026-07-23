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


def _extract_fix_info(entry: dict) -> tuple[str | None, str | None, str, str]:
    """Returns (fix_commit, repo_url, ecosystem, package) from the same source."""
    for affected in entry.get("affected") or []:
        pkg = affected.get("package") or {}
        eco = pkg.get("ecosystem", "")
        pkg_name = pkg.get("name", "")
        for rng in affected.get("ranges") or []:
            if rng.get("type") != "GIT":
                continue
            fix = None
            for event in rng.get("events") or []:
                if "fixed" in event:
                    fix = event["fixed"]
            repo = rng.get("repo", "")
            if fix and "github.com" in repo:
                return fix, repo.rstrip("/").removesuffix(".git"), eco, pkg_name

    # Fallback to references
    for ref in entry.get("references") or []:
        url = ref.get("url", "")
        if "github.com" in url and "/commit/" in url:
            parts = url.rstrip("/").split("/commit/")
            if len(parts) == 2 and len(parts[1]) >= 7:
                commit = parts[1].split("#")[0].split("?")[0]
                repo = parts[0].rstrip("/").removesuffix(".git")
                # For references fallback, get ecosystem from first affected
                for affected in entry.get("affected") or []:
                    pkg = affected.get("package") or {}
                    return commit, repo, pkg.get("ecosystem", ""), pkg.get("name", "")
                return commit, repo, "", ""

    return None, None, "", ""


def _extract_severity(entry: dict) -> str:
    for sev in entry.get("severity") or []:
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
        # Bug #8 fix: Only parse CVSS v3.x, skip v4.0 and v2.0
        if "/AV:" in score_str and "CVSS:4" not in score_str and "CVSS:2" not in score_str:
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
    for sev in entry.get("severity") or []:
        if sev.get("type") == "ECOSYSTEM":
            text = sev.get("score", "").upper()
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if level in text or (level == "MEDIUM" and "MODERATE" in text):
                    return level
    db_severity = (entry.get("database_specific") or {}).get("severity")
    if db_severity:
        normalized = db_severity.upper()
        if normalized == "MODERATE":
            normalized = "MEDIUM"
        if normalized in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return normalized
    return "UNKNOWN"


def _cvss_base_from_vector(vector: str) -> float:
    """
    Calculate CVSS 3.1 base score from vector string.
    Bug #10 fix: Added Scope handling for accurate base score calculation.
    Bug #12 fix: Use ceiling (roundup) to nearest 0.1 instead of standard round.
    Note: This is an approximate calculation used for filtering purposes.
    """
    import math

    parts = {}
    for segment in vector.split("/"):
        if ":" in segment:
            key, val = segment.split(":", 1)
            parts[key] = val

    av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_scores = {"L": 0.77, "H": 0.44}
    pr_scores = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_scores_changed = {"N": 0.85, "L": 0.68, "H": 0.50}  # When scope is changed
    ui_scores = {"N": 0.85, "R": 0.62}
    impact_map = {"H": 0.56, "L": 0.22, "N": 0.0}

    scope = parts.get("S", "U")  # U = Unchanged, C = Changed
    av = av_scores.get(parts.get("AV", "N"), 0.85)
    ac = ac_scores.get(parts.get("AC", "L"), 0.77)

    # Bug #10: PR values differ when Scope is Changed
    if scope == "C":
        pr = pr_scores_changed.get(parts.get("PR", "N"), 0.85)
    else:
        pr = pr_scores.get(parts.get("PR", "N"), 0.85)

    ui = ui_scores.get(parts.get("UI", "N"), 0.85)
    c = impact_map.get(parts.get("C", "N"), 0.0)
    i = impact_map.get(parts.get("I", "N"), 0.0)
    a = impact_map.get(parts.get("A", "N"), 0.0)

    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    # Bug #10: Impact calculation differs when Scope is Changed
    if scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope == "C":
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    # Bug #12: Use ceiling (roundup) instead of round
    return math.ceil(base * 10) / 10


def _parse_osv_entry(entry: dict) -> dict | None:
    osv_id = entry.get("id") or ""
    summary = entry.get("summary") or ""
    details = entry.get("details") or ""
    description = details if len(details) > len(summary) else summary
    if len(description) < _MIN_DESC_LEN:
        return None

    published = entry.get("published", "")
    # Bug #13 fix: Handle malformed dates with try/except
    if published:
        try:
            if int(published[:4]) < _MIN_YEAR:
                return None
        except (ValueError, IndexError, TypeError):
            pass

    fix_commit, repo_url, ecosystem, package_name = _extract_fix_info(entry)
    if not fix_commit or not repo_url:
        return None

    severity = _extract_severity(entry)

    aliases = entry.get("aliases") or []
    cve_id = next((a for a in aliases if a.startswith("CVE-")), "")

    return {
        "osv_id": osv_id,
        "cve_id": cve_id,
        "ecosystem": ecosystem,
        "package": package_name,
        "repo_url": repo_url,
        "fix_commit": fix_commit,
        "description": description,
        "severity": severity,
        "published_date": str(published)[:10] if published else "",
        "status": CandidateStatus.PENDING,
    }


_gh_warning_logged = False

def _get_star_count(repo_url: str) -> int | None:
    global _gh_warning_logged
    import subprocess
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 2:
        return 0
    owner_repo = f"{parts[-2]}/{parts[-1]}"
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{owner_repo}", "--jq", ".stargazers_count"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
        if "404" in (result.stderr or ""):
            return 0
        return -1  # API error, unknown star count
    except subprocess.TimeoutExpired:
        return -1  # timeout, unknown star count
    except FileNotFoundError:
        if not _gh_warning_logged:
            logger.warning("gh CLI not found, star filtering will be skipped")
            _gh_warning_logged = True
        return None  # gh not installed


def _download_ecosystem_zip(ecosystem: str, cache_dir: str | None = None) -> list[dict]:
    url = OSV_GCS_URL.format(ecosystem=ecosystem)
    logger.info("Downloading OSV bulk data for %s from %s", ecosystem, url)

    if cache_dir:
        cached = os.path.join(cache_dir, f"{ecosystem.replace('/', '_')}.zip")
        if os.path.isfile(cached):
            logger.info("Using cached zip: %s", cached)
            try:
                with zipfile.ZipFile(cached) as zf:
                    return _parse_zip(zf)
            except zipfile.BadZipFile:
                logger.warning("Corrupt cache file %s, re-downloading", cached)
                os.unlink(cached)
                # Fall through to download

    # Bug #9 fix: Move resp.content inside try/except
    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
        content = resp.content
    except requests.RequestException as e:
        logger.error("Failed to download %s: %s", url, e)
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            entries = _parse_zip(zf)
    except zipfile.BadZipFile:
        logger.error("Downloaded invalid zip for %s", ecosystem)
        return []

    # Only cache after successful parse
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        fd = tempfile.NamedTemporaryFile(dir=cache_dir, suffix=".zip.tmp", delete=False)
        try:
            fd.write(content)
            fd.flush()
            os.fsync(fd.fileno())
            fd.close()
            os.replace(fd.name, cached)
        except BaseException:
            fd.close()
            try:
                os.unlink(fd.name)
            except OSError:
                pass
            raise

    return entries


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
        gh_missing = False
        for c in candidates:
            repo = c["repo_url"]
            if repo not in seen_repos:
                stars = _get_star_count(repo)
                if stars is None:
                    gh_missing = True
                    filtered = candidates
                    break
                seen_repos[repo] = stars
                time.sleep(0.5)
            stars = seen_repos.get(repo, -1)
            if stars == -1:
                filtered.append(c)
            elif stars >= min_stars:
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
