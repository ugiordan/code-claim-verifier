from __future__ import annotations

import logging
import os

from code_claim_verifier.types import TypedClaim, VerifiedClaim
from code_claim_verifier.extractor import extract_claims
from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.calibrator import calibrate
from eval.cybergym.models import get_model
from eval.cybergym.prompts import build_judge_prompt
from eval.cybergym.utils import load_jsonl, load_json, save_json, normalize_claim_path

logger = logging.getLogger(__name__)


def run_ccv_verification(claims: list[TypedClaim], source_root: str,
                         language: str) -> list[VerifiedClaim]:
    engine = VerificationEngine()
    return engine.verify_claims_with_chaining(claims, source_root, language)


def match_claims_to_gt(verified: list[VerifiedClaim],
                       gt_claims: list[dict]) -> list[dict]:
    matched: list[dict] = []
    used_gt: set[int] = set()
    for vc in verified:
        for i, gt in enumerate(gt_claims):
            if i in used_gt:
                continue
            if gt["claim_type"] != vc.claim.claim_type:
                continue
            gt_params = gt.get("parameters", {})
            all_match = True
            for key, value in gt_params.items():
                vc_value = vc.claim.parameters.get(key)
                if vc_value is None and key == "file":
                    vc_value = vc.claim.parameters.get("path")
                if vc_value is None and key == "path":
                    vc_value = vc.claim.parameters.get("file")
                if key in ("file", "path") and isinstance(value, str) and isinstance(vc_value, str):
                    value = normalize_claim_path(value)
                    vc_value = normalize_claim_path(vc_value)
                if vc_value != value:
                    all_match = False
                    break
            if all_match:
                used_gt.add(i)
                matched.append({
                    "claim_type": vc.claim.claim_type,
                    "expected": gt["expected_verdict"],
                    "actual": vc.verdict,
                    "confidence": vc.method_confidence,
                    "gt_tier": gt.get("gt_tier", "unknown"),
                })
                break
    return matched


def _build_judge_context(claim: TypedClaim, source_root: str) -> str:
    """Build the context a judge sees for a claim, equivalent to what CCV uses."""
    claim_type = claim.claim_type
    params = claim.parameters

    if claim_type == "FILE_EXISTS":
        path = params.get("path", params.get("file", ""))
        full = os.path.join(source_root, path)
        exists = os.path.isfile(full)
        return f"File lookup result: os.path.isfile('{path}') = {exists}"

    if claim_type in ("FUNCTION_EXISTS", "FUNCTION_CALLED", "HAS_CALLERS"):
        file_param = params.get("file", params.get("path", ""))
        name = params.get("name", "")
        if file_param:
            full = os.path.join(source_root, file_param)
            if os.path.isfile(full):
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
        full = os.path.join(source_root, path)
        if os.path.isfile(full):
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
            full = os.path.join(source_root, file_param)
            if os.path.isfile(full):
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
        for key in ("path", "file"):
            if key in claim.parameters and isinstance(claim.parameters[key], str):
                claim.parameters[key] = normalize_claim_path(claim.parameters[key])
    return claims


def verify_one(entry: dict, reasoning_path: str, output_dir: str,
               extraction_llm: str = "claude-sonnet-4",
               with_judge: bool = False,
               judge_model: str = "gpt-4o") -> dict | None:
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

        existing = load_json(out_path)
        if existing is not None:
            return existing

        reasoning = reasoning_data["reasoning"]
        source_root = entry["source_root"]
        language = entry.get("language", "c")

        extractor_llm = get_model(extraction_llm)
        claims = extract_claims(reasoning, {}, extractor_llm)
        claims = _normalize_claims(claims)

        if not claims:
            result = {
                "vuln_id": vuln_id, "model": model_name, "condition": condition,
                "reasoning_length": len(reasoning),
                "reasoning_truncated": len(reasoning) > 4000,
                "ccv": {
                    "total_claims": 0, "verified": 0, "refuted": 0,
                    "unverifiable": 0, "verification_rate": 0.0,
                    "action": "NO_CHANGE", "claims": [],
                },
                "gt_comparison": {"matched": 0, "results": []},
            }
            save_json(result, out_path)
            return result

        verified = run_ccv_verification(claims, source_root, language)
        report = calibrate(verified)

        gt_comparison = match_claims_to_gt(verified, entry.get("gt_claims", []))

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
            "reasoning_truncated": len(reasoning) > 4000,
            "ccv": ccv_result,
            "gt_comparison": {
                "matched": len(gt_comparison),
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
               with_judge: bool = False) -> None:
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
                               with_judge=with_judge)
                except Exception:
                    logger.exception("Unexpected error processing %s", fname)
