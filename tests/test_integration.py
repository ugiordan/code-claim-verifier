from __future__ import annotations
import os
from code_claim_verifier import CodeClaimVerifier

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "python_repo")

def mock_llm(system, user):
    return '[{"claim_type": "FILE_EXISTS", "parameters": {"path": "main.py"}, "source_sentence": "main.py exists"}]'

class TestCodeClaimVerifierIntegration:
    def test_verify_basic(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        report = v.verify(reasoning="main.py exists", finding_file="main.py")
        assert report.verified >= 1
        assert report.action in ("BOOST", "FLAG", "OVERRIDE", "NO_CHANGE")

    def test_register_custom_type(self):
        from code_claim_verifier.types import VerifiedClaim
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        def custom_verifier(claim, repo_path, language):
            return VerifiedClaim(claim=claim, verdict="VERIFIED", method_confidence=0.90,
                                 evidence="custom", method="custom")
        v.register(claim_type="MY_TYPE", verifier_fn=custom_verifier,
                   extraction_hint="MY_TYPE: {x: str} - custom check")
        assert "MY_TYPE" in v.engine.registry

    def test_register_rejects_builtin_collision(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        import pytest
        with pytest.raises(ValueError):
            v.register("FILE_EXISTS", lambda c, r, l: None, extraction_hint="")

    def test_register_rejects_long_hint(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        import pytest
        with pytest.raises(ValueError, match="500"):
            v.register("LONG", lambda c, r, l: None, extraction_hint="x" * 501)

    def test_verify_batch(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        items = [
            {"reasoning": "main.py exists", "evidence": {}, "finding_file": "main.py"},
            {"reasoning": "utils.py exists", "evidence": {}, "finding_file": "utils.py"},
        ]
        reports = v.verify_batch(items=items)
        assert len(reports) == 2
        for r in reports:
            assert r.total_claims >= 0

    def test_verify_batch_empty(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        reports = v.verify_batch(items=[])
        assert reports == []

    def test_verify_batch_uses_adaptive_batching(self):
        call_count = [0]
        def counting_llm(system, user):
            call_count[0] += 1
            if "<<<FINDING_" in user:
                return '[{"finding_index": 0, "claim_type": "FILE_EXISTS", "parameters": {"path": "main.py"}, "source_sentence": "s"}]'
            return '[{"claim_type": "FILE_EXISTS", "parameters": {"path": "main.py"}, "source_sentence": "s"}]'

        v = CodeClaimVerifier(llm_function=counting_llm, repo_path=FIXTURE)
        items = [
            {"reasoning": "short1", "evidence": {}, "finding_file": "main.py"},
            {"reasoning": "short2", "evidence": {}, "finding_file": "main.py"},
        ]
        v.verify_batch(items=items, max_chars_per_batch=10000)
        assert call_count[0] == 1

    def test_group_into_batches_splits_by_size(self):
        items = [
            {"reasoning": "a" * 100},
            {"reasoning": "b" * 100},
            {"reasoning": "c" * 100},
        ]
        batches = CodeClaimVerifier._group_into_batches(items, max_chars=250)
        assert len(batches) == 2
        assert len(batches[0][0]) == 2
        assert batches[0][1] == 0
        assert len(batches[1][0]) == 1
        assert batches[1][1] == 2

    def test_group_into_batches_oversized_item_alone(self):
        items = [
            {"reasoning": "a" * 50},
            {"reasoning": "b" * 200},
            {"reasoning": "c" * 50},
        ]
        batches = CodeClaimVerifier._group_into_batches(items, max_chars=100)
        assert any(len(b[0]) == 1 and len(b[0][0]["reasoning"]) == 200 for b in batches)

    def test_verify_uses_chaining(self):
        def llm_with_line_content(system, user):
            return '[{"claim_type": "LINE_CONTENT", "parameters": {"path": "main.py", "line": 1, "expected": "import os"}, "source_sentence": "import os at line 1"}]'
        v = CodeClaimVerifier(llm_function=llm_with_line_content, repo_path=FIXTURE)
        report = v.verify(reasoning="import os at line 1", finding_file="main.py")
        synth = [c for c in report.per_claim if c.synthesized]
        assert len(synth) >= 1
