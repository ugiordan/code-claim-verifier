from __future__ import annotations

import logging
import os

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.extractor import (
    EXTRACTION_VERSION,
    build_extraction_prompts,
    extract_claims,
)
from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.calibrator import calibrate
from code_claim_verifier.security import safe_path
from eval.cybergym.models import get_model, get_model_provenance
from eval.cybergym.prompts import build_judge_prompt
from eval.cybergym.utils import load_jsonl, load_json, save_json, normalize_claim_path
from eval.provenance import snapshot_digest, text_digest

logger = logging.getLogger(__name__)


def run_ccv_verification(claims: list[TypedClaim], source_root: str,
                         language: str, cymbal_backend=None,
                         cpg=None) -> list[VerifiedClaim]:
    engine = VerificationEngine(cymbal=cymbal_backend, cpg=cpg)
    return engine.verify_claims_with_chaining(claims, source_root, language)


def _normalize_path(p: str) -> str:
    return normalize_claim_path(p) if isinstance(p, str) else p


_PATH_CLAIM_TYPES = frozenset({
    "FILE_EXISTS", "LINE_CONTENT", "FILE_CLASSIFICATION",
    "GENERATED_OR_VENDORED",
})
_FILE_SCOPED_CLAIM_TYPES = frozenset({
    "FUNCTION_EXISTS", "IMPORT_EXISTS", "MITIGATION_EXISTS",
    "DEFAULT_VALUE",
})


def _canonicalize_parameters(claim_type: str, parameters: dict) -> dict:
    """Normalize extractor aliases into the verifier parameter schema.

    Canonicalization is deliberately narrow. Descriptive fields such as
    ``content_description`` are not converted into exact source content.
    """
    normalized = dict(parameters or {})
    if claim_type in _PATH_CLAIM_TYPES:
        if "path" not in normalized:
            for alias in ("file", "filename"):
                if alias in normalized:
                    normalized["path"] = normalized[alias]
                    break
        for alias in ("file", "filename"):
            normalized.pop(alias, None)
    elif claim_type in _FILE_SCOPED_CLAIM_TYPES:
        if "file" not in normalized:
            for alias in ("path", "filename"):
                if alias in normalized:
                    normalized["file"] = normalized[alias]
                    break
        for alias in ("path", "filename"):
            normalized.pop(alias, None)
    if claim_type == "LINE_CONTENT" and "content" not in normalized:
        if "expected_content" in normalized:
            normalized["content"] = normalized["expected_content"]
        elif "expected" in normalized and isinstance(normalized["expected"], str):
            normalized["content"] = normalized["expected"]
    if claim_type == "LINE_CONTENT":
        normalized.pop("expected_content", None)
        if isinstance(normalized.get("expected"), str):
            normalized.pop("expected", None)
    if claim_type == "FILE_CLASSIFICATION":
        if "category" not in normalized and "classification" in normalized:
            normalized["category"] = normalized["classification"]
        normalized.pop("classification", None)
    if claim_type == "DEPENDENCY_TYPE":
        if "dep_type" not in normalized and "type" in normalized:
            normalized["dep_type"] = normalized["type"]
        normalized.pop("type", None)
    for key in ("path", "file"):
        if isinstance(normalized.get(key), str):
            normalized[key] = _normalize_path(normalized[key])
    return normalized


def _import_name_match(gt_module: str, vc_params: dict) -> bool:
    """Match GT 'module' key against LLM claims that use 'import', 'module', or 'from'.

    Matching strategy (in order):
    1. Exact full-string match on any import-related key.
    2. Last path/dot component match, but only if the component is >= 5 chars
       (avoids false matches on short generic names like io, os, net).
    """
    if not isinstance(gt_module, str) or not gt_module:
        return False

    for key in ("module", "import", "from", "package"):
        val = vc_params.get(key)
        if isinstance(val, str) and val:
            if gt_module == val:
                return True

    gt_last = gt_module.split(".")[-1].lstrip("@").split("/")[-1].lower()
    if len(gt_last) < 5:
        return False

    for key in ("module", "import", "from", "package"):
        val = vc_params.get(key)
        if isinstance(val, str) and val:
            val_last = val.split(".")[-1].lstrip("@").split("/")[-1].lower()
            if gt_last == val_last:
                return True
    return False


def _exact_match(gt_params: dict, vc_params: dict, claim_type: str) -> bool:
    vc_params = _canonicalize_parameters(claim_type, vc_params)
    gt_params = _canonicalize_parameters(claim_type, gt_params)
    for key, value in gt_params.items():
        vc_value = vc_params.get(key)
        if vc_value is None and key == "file":
            vc_value = vc_params.get("path")
        if vc_value is None and key == "path":
            vc_value = vc_params.get("file")
        if key in ("file", "path") and isinstance(value, str) and isinstance(vc_value, str):
            value = _normalize_path(value)
            vc_value = _normalize_path(vc_value)
        if vc_value != value:
            return False
    return True


def match_claims_to_gt(verified: list[VerifiedClaim],
                       gt_claims: list[dict]) -> list[dict]:
    matched: list[dict] = []
    used_gt: set[int] = set()

    def _record(vc, gt, i):
        used_gt.add(i)
        matched.append({
            "claim_type": vc.claim.claim_type,
            "expected": gt["expected_verdict"],
            "actual": vc.verdict,
            "confidence": vc.method_confidence,
            "gt_tier": gt.get("gt_tier", "unknown"),
        })

    for vc in verified:
        ct = vc.claim.claim_type
        vc_params = vc.claim.parameters

        # Pass 1: exact match (covers FILE_EXISTS, ABSENCE, and exact file+name matches)
        matched_exact = False
        for i, gt in enumerate(gt_claims):
            if i in used_gt or gt["claim_type"] != ct:
                continue
            if _exact_match(gt.get("parameters", {}), vc_params, ct):
                _record(vc, gt, i)
                matched_exact = True
                break
        if matched_exact:
            continue

        # Pass 2: fuzzy fallbacks per claim type
        if ct == "FUNCTION_EXISTS":
            # Name-only fallback: LLM may report a different file than GT
            vc_name = vc_params.get("name", "")
            for i, gt in enumerate(gt_claims):
                if i in used_gt or gt["claim_type"] != "FUNCTION_EXISTS":
                    continue
                if gt.get("parameters", {}).get("name") == vc_name and vc_name:
                    _record(vc, gt, i)
                    break

        elif ct == "FUNCTION_CALLED":
            # GT uses {name, file} (call site file); LLM uses {name, expected} or {name, caller}
            # Match on function name only
            vc_name = vc_params.get("name", "")
            for i, gt in enumerate(gt_claims):
                if i in used_gt or gt["claim_type"] != "FUNCTION_CALLED":
                    continue
                if gt.get("parameters", {}).get("name") == vc_name and vc_name:
                    _record(vc, gt, i)
                    break

        elif ct == "IMPORT_EXISTS":
            # GT uses {module}; LLM uses {import, from} or {module} with varying formats
            for i, gt in enumerate(gt_claims):
                if i in used_gt or gt["claim_type"] != "IMPORT_EXISTS":
                    continue
                gt_module = gt.get("parameters", {}).get("module", "")
                if _import_name_match(gt_module, vc_params):
                    _record(vc, gt, i)
                    break

    return matched


def compare_claims_to_gt(verified: list[VerifiedClaim],
                         gt_claims: list[dict]) -> list[dict]:
    """Compare every real claim and every GT claim without dropping misses.

    Matched claims are suitable for verifier accuracy. Unmatched predictions
    are extraction mismatches, not verifier errors, and unmatched GT entries
    are missed extractions. Keeping both categories visible prevents a
    matching heuristic from manufacturing a perfect precision score.
    """
    real_claims = [vc for vc in verified if not vc.synthesized]
    used_gt: set[int] = set()
    comparisons: list[dict] = []

    for vc in real_claims:
        matched_index = None
        for index, gt in enumerate(gt_claims):
            if index in used_gt or gt.get("claim_type") != vc.claim.claim_type:
                continue
            if _exact_match(
                gt.get("parameters", {}), vc.claim.parameters, vc.claim.claim_type
            ):
                matched_index = index
                used_gt.add(index)
                break

        if matched_index is None:
            comparisons.append({
                "claim_type": vc.claim.claim_type,
                "parameters": _canonicalize_parameters(
                    vc.claim.claim_type, vc.claim.parameters
                ),
                "expected": None,
                "actual": vc.verdict,
                "confidence": vc.method_confidence,
                "status": "unmatched_prediction",
            })
            continue

        gt = gt_claims[matched_index]
        comparisons.append({
            "claim_type": vc.claim.claim_type,
            "parameters": _canonicalize_parameters(
                vc.claim.claim_type, vc.claim.parameters
            ),
            "expected": gt.get("expected_verdict"),
            "actual": vc.verdict,
            "confidence": vc.method_confidence,
            "gt_tier": gt.get("gt_tier", "unknown"),
            "status": "matched",
        })

    for index, gt in enumerate(gt_claims):
        if index in used_gt:
            continue
        comparisons.append({
            "claim_type": gt.get("claim_type", "unknown"),
            "parameters": _canonicalize_parameters(
                gt.get("claim_type", ""), gt.get("parameters", {})
            ),
            "expected": gt.get("expected_verdict"),
            "actual": None,
            "confidence": None,
            "gt_tier": gt.get("gt_tier", "unknown"),
            "status": "unmatched_ground_truth",
        })

    return comparisons


def _build_judge_context(claim: TypedClaim, source_root: str) -> str:
    """Build the context a judge sees for a claim, equivalent to what CCV uses."""
    claim_type = claim.claim_type
    params = claim.parameters

    if claim_type == "FILE_EXISTS":
        path = params.get("path", params.get("file", ""))
        full = safe_path(path, source_root)
        if full is None:
            return f"File lookup result: invalid path '{path}'"
        exists = os.path.isfile(full)
        return f"File lookup result: os.path.isfile('{path}') = {exists}"

    if claim_type in ("FUNCTION_EXISTS", "FUNCTION_CALLED", "HAS_CALLERS"):
        file_param = params.get("file", params.get("path", ""))
        name = params.get("name", "")
        if file_param:
            full = safe_path(file_param, source_root)
            if full and os.path.isfile(full):
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read(8000)
                    return f"File content of {file_param}:\n{content}"
                except OSError:
                    pass
        import subprocess
        try:
            result = subprocess.run(
                ["grep", "-rn", "--binary-files=without-match", name, source_root],
                capture_output=True, text=True, timeout=10, errors="replace",
            )
            matches = result.stdout.strip().split("\n") if result.stdout.strip() else []
            if matches:
                return f"grep results for '{name}' ({len(matches)} matches):\n" + "\n".join(matches[:10])
            return f"grep results for '{name}': 0 matches"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return f"grep for '{name}': timed out or failed"

    if claim_type == "ABSENCE":
        pattern = params.get("pattern", "")
        import subprocess
        try:
            result = subprocess.run(
                ["grep", "-rnF", "--binary-files=without-match", pattern, source_root],
                capture_output=True, text=True, timeout=10, errors="replace",
            )
            matches = result.stdout.strip().split("\n") if result.stdout.strip() else []
            count = len(matches) if matches[0] else 0
            if count > 0:
                return f"grep -F results for '{pattern}': {count} matches\n" + "\n".join(matches[:5])
            return f"grep -F results for '{pattern}': 0 matches"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return f"grep for '{pattern}': timed out or failed"

    if claim_type == "LINE_CONTENT":
        path = params.get("file", params.get("path", ""))
        line_num = params.get("line", 0)
        full = safe_path(path, source_root)
        if full and os.path.isfile(full):
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                if 0 < line_num <= len(lines):
                    return f"Line {line_num} of {path}: {lines[line_num - 1].rstrip()}"
                return f"File {path} has {len(lines)} lines, line {line_num} out of range"
            except OSError:
                pass
        return f"File not found: {path}"

    if claim_type in ("IMPORT_EXISTS", "PACKAGE_VERSION"):
        file_param = params.get("file", "")
        if file_param:
            full = safe_path(file_param, source_root)
            if full and os.path.isfile(full):
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as f:
                        return f"File content of {file_param}:\n{f.read(8000)}"
                except OSError:
                    pass
        return "No specific file context available for this claim."

    return "No specific context available for this claim type."


def judge_claims(claims: list[TypedClaim], source_root: str,
                 judge_llm_fn) -> list[dict]:
    """Run LLM-as-judge verification on a list of claims."""
    results = []
    for claim in claims:
        context = _build_judge_context(claim, source_root)
        prompt = build_judge_prompt(claim.claim_type, claim.parameters, context)
        try:
            response = judge_llm_fn("You are a code verification judge.", prompt)
            verdict = _parse_judge_verdict(response)
        except Exception as e:
            logger.warning("Judge failed for %s: %s", claim.claim_type, e)
            verdict = "UNVERIFIABLE"
        results.append({
            "claim_type": claim.claim_type,
            "parameters": claim.parameters,
            "verdict": verdict,
        })
    return results


def _parse_judge_verdict(response: str) -> str:
    first_line = response.strip().split("\n")[0].strip().upper()
    for v in ("VERIFIED", "REFUTED", "UNVERIFIABLE"):
        if v in first_line:
            return v
    return "UNVERIFIABLE"


def _normalize_claims(claims: list[TypedClaim]) -> list[TypedClaim]:
    for claim in claims:
        claim.parameters = _canonicalize_parameters(
            claim.claim_type, claim.parameters
        )
    return claims


def verify_one(entry: dict, reasoning_path: str, output_dir: str,
               extraction_llm: str = "claude-sonnet-4",
               with_judge: bool = False,
               with_cymbal: bool = False,
               judge_model: str = "gpt-4o",
               force: bool = False) -> dict | None:
    try:
        vuln_id = entry["vuln_id"]
        reasoning_data = load_json(reasoning_path)
        if reasoning_data is None:
            return None

        if "reasoning" not in reasoning_data:
            logger.error("Missing 'reasoning' key in %s", reasoning_path)
            return None

        model_name = reasoning_data.get("model", "unknown")
        condition = reasoning_data.get("condition", "informed")
        out_path = os.path.join(output_dir, model_name, condition, f"{vuln_id}.json")

        source_root = entry["source_root"]
        expected_source_digest = entry.get("source_digest", "")
        if not expected_source_digest or snapshot_digest(source_root) != expected_source_digest:
            logger.error("Skipping %s: source snapshot does not match the manifest", vuln_id)
            return None

        reasoning_provenance = reasoning_data.get("provenance", {})
        if reasoning_provenance.get("source_digest") not in (None, expected_source_digest):
            logger.error("Skipping %s: reasoning source digest does not match the manifest", vuln_id)
            return None

        reasoning = reasoning_data["reasoning"]
        extraction_system, extraction_user = build_extraction_prompts(reasoning, {})
        extraction_provenance = {
            **get_model_provenance(extraction_llm),
            "extraction_version": EXTRACTION_VERSION,
            "system_prompt_digest": text_digest(extraction_system),
            "user_prompt_digest": text_digest(extraction_user),
        }
        expected_provenance = {
            "manifest_schema": entry.get("manifest_schema"),
            "dataset_revision": entry.get("dataset_revision"),
            "source_digest": expected_source_digest,
            "source_head": reasoning_provenance.get("source_head"),
            "include_patch_files": reasoning_provenance.get("include_patch_files", False),
            "provider": reasoning_provenance.get("provider"),
            "resolved_model": reasoning_provenance.get("resolved_model"),
            "max_tokens": reasoning_provenance.get("max_tokens"),
            "temperature": reasoning_provenance.get("temperature"),
            "config_version": reasoning_provenance.get("config_version"),
            "extraction": extraction_provenance,
            "reasoning_provenance": reasoning_provenance,
            "with_judge": with_judge,
            "judge_model": judge_model if with_judge else None,
            "with_cymbal": with_cymbal,
        }

        existing = load_json(out_path)
        existing_provenance = existing.get("provenance", {}) if existing else {}
        if (
            existing is not None
            and not force
            and all(existing_provenance.get(key) == value
                    for key, value in expected_provenance.items())
        ):
            return existing

        language = entry.get("language", "c")

        extractor_llm = get_model(extraction_llm)
        claims = extract_claims(reasoning, {}, extractor_llm)
        claims = _normalize_claims(claims)

        if not claims:
            missing_gt = compare_claims_to_gt([], entry.get("gt_claims", []))
            result = {
                "vuln_id": vuln_id, "model": model_name, "condition": condition,
                "reasoning_length": len(reasoning),
                "reasoning_truncated": len(reasoning) > 8000,
                "ccv": {
                    "total_claims": 0, "verified": 0, "refuted": 0,
                    "unverifiable": 0, "verification_rate": 0.0,
                    "action": "NO_CHANGE", "claims": [],
                },
                "provenance": {
                    **expected_provenance,
                    "extraction_model": extraction_llm,
                    "verification_backend": "none",
                },
                "gt_comparison": {
                    "matched": 0,
                    "unmatched_predictions": 0,
                    "unmatched_ground_truth": len(missing_gt),
                    "results": missing_gt,
                },
            }
            save_json(result, out_path)
            return result

        cpg = None
        qi_path = os.path.join(source_root, "quick-index.json")
        if os.path.isfile(qi_path):
            from code_claim_verifier.cpg_backend import load_quick_index
            cpg = load_quick_index(qi_path)

        cymbal = None
        if with_cymbal:
            from code_claim_verifier.cymbal_backend import load_cymbal
            cymbal = load_cymbal(source_root)
        verified = run_ccv_verification(claims, source_root, language,
                                        cymbal_backend=cymbal, cpg=cpg)
        report = calibrate(verified)

        gt_comparison = compare_claims_to_gt(
            verified, entry.get("gt_claims", [])
        )

        ccv_result = {
            "total_claims": report.total_claims,
            "verified": report.verified,
            "refuted": report.refuted,
            "unverifiable": report.unverifiable,
            "verification_rate": report.verification_rate,
            "action": report.action,
            "claims": [
                {
                    "claim_type": vc.claim.claim_type,
                    "parameters": vc.claim.parameters,
                    "verdict": vc.verdict,
                    "confidence": vc.method_confidence,
                    "evidence": vc.evidence[:200],
                    "method": vc.method,
                }
                for vc in verified if not vc.synthesized
            ],
        }

        result = {
            "vuln_id": vuln_id,
            "model": model_name,
            "condition": condition,
            "reasoning_length": len(reasoning),
            "reasoning_truncated": len(reasoning) > 8000,
            "ccv": ccv_result,
            "provenance": {
                **expected_provenance,
                "extraction_model": extraction_llm,
                "verification_backend": "cpg+grep" if cpg else "grep",
            },
            "gt_comparison": {
                "matched": sum(
                    1 for item in gt_comparison if item["status"] == "matched"
                ),
                "unmatched_predictions": sum(
                    1 for item in gt_comparison
                    if item["status"] == "unmatched_prediction"
                ),
                "unmatched_ground_truth": sum(
                    1 for item in gt_comparison
                    if item["status"] == "unmatched_ground_truth"
                ),
                "results": gt_comparison,
            },
        }

        if with_judge:
            try:
                judge_llm = get_model(judge_model)
                judge_results = judge_claims(claims, source_root, judge_llm)
                result["llm_judge"] = {
                    "judge_model": judge_model,
                    "total_claims": len(judge_results),
                    "verified": sum(1 for r in judge_results if r["verdict"] == "VERIFIED"),
                    "refuted": sum(1 for r in judge_results if r["verdict"] == "REFUTED"),
                    "unverifiable": sum(1 for r in judge_results if r["verdict"] == "UNVERIFIABLE"),
                    "claims": judge_results,
                }
            except Exception:
                logger.exception("LLM judge failed for %s", vuln_id)

        save_json(result, out_path)
        return result
    except Exception:
        logger.exception("verify_one failed for %s", reasoning_path)
        return None


def run_verify(manifest_path: str, reasoning_dir: str, output_dir: str,
               extraction_llm: str = "claude-sonnet-4",
               with_judge: bool = False,
               with_cymbal: bool = False,
               force: bool = False) -> None:
    manifest = load_jsonl(manifest_path)
    manifest_by_id = {e["vuln_id"]: e for e in manifest}

    for model_dir in sorted(os.listdir(reasoning_dir)):
        model_path = os.path.join(reasoning_dir, model_dir)
        if not os.path.isdir(model_path):
            continue
        for condition_dir in sorted(os.listdir(model_path)):
            cond_path = os.path.join(model_path, condition_dir)
            if not os.path.isdir(cond_path):
                continue
            files = [f for f in os.listdir(cond_path) if f.endswith(".json")]
            logger.info("Verifying %d files from %s/%s", len(files), model_dir, condition_dir)
            for fname in sorted(files):
                vuln_id = fname.replace(".json", "")
                entry = manifest_by_id.get(vuln_id)
                if not entry:
                    continue
                reasoning_path = os.path.join(cond_path, fname)
                try:
                    verify_one(entry, reasoning_path, output_dir,
                               extraction_llm=extraction_llm,
                               with_judge=with_judge,
                               with_cymbal=with_cymbal,
                               force=force)
                except Exception:
                    logger.exception("Unexpected error processing %s", fname)
