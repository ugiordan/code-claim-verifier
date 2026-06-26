from __future__ import annotations
import os
import tempfile
import shutil

from eval.cybergym.verify import run_ccv_verification, match_claims_to_gt


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

    def test_no_match(self):
        gt = [{"claim_type": "FILE_EXISTS", "parameters": {"path": "other.c"}, "expected_verdict": "VERIFIED"}]
        from code_claim_verifier.types import TypedClaim, VerifiedClaim
        vc = VerifiedClaim(
            claim=TypedClaim(claim_type="FILE_EXISTS", parameters={"path": "main.c"}, source_sentence=""),
            verdict="VERIFIED", method_confidence=0.99, evidence="exists", method="test",
        )
        matched = match_claims_to_gt([vc], gt)
        assert len(matched) == 0


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
