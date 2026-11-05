from __future__ import annotations
import os
import tempfile
import shutil

from eval.cybergym.verify import (
    compare_claims_to_gt,
    match_claims_to_gt,
    run_ccv_verification,
)


class TestClaimMatching:
    def test_exact_match(self):
        gt = [{"claim_type": "FILE_EXISTS", "parameters": {"path": "main.c"}, "expected_verdict": "VERIFIED"}]
        from code_claim_verifier.types import TypedClaim, VerifiedClaim
        vc = VerifiedClaim(
            claim=TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.c"}, source_sentence=""),
            verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="test",
        )
        matched = match_claims_to_gt([vc], gt)
        assert len(matched) == 1
        assert matched[0]["expected"] == "VERIFIED"
        assert matched[0]["actual"] == "VERIFIED"

    def test_file_vs_path_key(self):
        gt = [{"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "foo", "file": "main.c"}, "expected_verdict": "VERIFIED"}]
        from code_claim_verifier.types import TypedClaim, VerifiedClaim
        vc = VerifiedClaim(
            claim=TypedClaim(claim_type="FUNCTION_EXISTS", parameters={"name": "foo", "path": "main.c"}, source_sentence=""),
            verdict="VERIFIED", method_confidence=0.85, evidence="found", method="test",
        )
        matched = match_claims_to_gt([vc], gt)
        assert len(matched) == 1

    def test_line_content_aliases_match_without_retaining_alias_keys(self):
        from code_claim_verifier.types import TypedClaim, VerifiedClaim
        gt = [{
            "claim_type": "LINE_CONTENT",
            "parameters": {"path": "main.c", "line": 1, "expected": "return 0"},
            "expected_verdict": "VERIFIED",
        }]
        vc = VerifiedClaim(
            claim=TypedClaim(
                claim_type="LINE_CONTENT",
                parameters={"filename": "main.c", "line": 1, "content": "return 0"},
                source_sentence="",
            ),
            verdict="VERIFIED", method_confidence=0.9, evidence="", method="test",
        )
        assert len(match_claims_to_gt([vc], gt)) == 1

    def test_no_match(self):
        gt = [{"claim_type": "FILE_EXISTS", "parameters": {"path": "other.c"}, "expected_verdict": "VERIFIED"}]
        from code_claim_verifier.types import TypedClaim, VerifiedClaim
        vc = VerifiedClaim(
            claim=TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.c"}, source_sentence=""),
            verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="test",
        )
        matched = match_claims_to_gt([vc], gt)
        assert len(matched) == 0

    def test_full_comparison_retains_unmatched_items(self):
        from code_claim_verifier.types import TypedClaim, VerifiedClaim

        vc = VerifiedClaim(
            claim=TypedClaim(
                claim_type="FILE_EXISTS",
                parameters={"filename": "main.c"},
                source_sentence="",
            ),
            verdict="VERIFIED", method_confidence=0.99,
            evidence="exists", method="test",
        )
        gt = [
            {"claim_type": "FILE_EXISTS", "parameters": {"path": "main.c"},
             "expected_verdict": "VERIFIED"},
            {"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "foo"},
             "expected_verdict": "VERIFIED"},
        ]
        compared = compare_claims_to_gt([vc], gt)
        assert compared[0]["status"] == "matched"
        assert compared[1]["status"] == "unmatched_ground_truth"
        assert all(item["status"] != "unmatched_prediction" for item in compared)


class TestCCVVerification:
    def test_verifies_against_fixture(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "main.c"), "w") as f:
            f.write("int parse_input() { return 0; }\n")
        try:
            from code_claim_verifier.types import TypedClaim
            claims = [TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.c"}, source_sentence="")]
            results = run_ccv_verification(claims, d, "c")
            assert len(results) == 1
            assert results[0].verdict == "VERIFIED"
        finally:
            shutil.rmtree(d)
