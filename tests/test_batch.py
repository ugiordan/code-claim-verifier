from __future__ import annotations
from code_claim_verifier.extractor import extract_claims_batch, _build_batch_prompt

class TestBuildBatchPrompt:
    def test_single_item(self):
        items = [{"reasoning": "file exists", "evidence": {}, "finding_file": "a.py"}]
        prompt = _build_batch_prompt(items)
        assert "<<<FINDING_0:a.py>>>" in prompt
        assert "file exists" in prompt

    def test_multiple_items(self):
        items = [
            {"reasoning": "first", "evidence": {}, "finding_file": "a.py"},
            {"reasoning": "second", "evidence": {}, "finding_file": "b.py"},
        ]
        prompt = _build_batch_prompt(items)
        assert "<<<FINDING_0:a.py>>>" in prompt
        assert "<<<FINDING_1:b.py>>>" in prompt

class TestExtractClaimsBatch:
    def test_assigns_finding_index(self):
        def mock_llm(system, user):
            return '[{"finding_index": 0, "claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}, "source_sentence": "test"}]'
        items = [{"reasoning": "a.py exists", "evidence": {}, "finding_file": "a.py"}]
        result = extract_claims_batch(items, mock_llm)
        assert len(result) == 1
        assert 0 in result
        assert len(result[0]) == 1

    def test_discards_out_of_range_index(self):
        def mock_llm(system, user):
            return '[{"finding_index": 99, "claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}, "source_sentence": "test"}]'
        items = [{"reasoning": "test", "evidence": {}, "finding_file": "a.py"}]
        result = extract_claims_batch(items, mock_llm)
        assert len(result.get(0, [])) == 0

    def test_partial_recovery_skip(self):
        def mock_llm(system, user):
            return '[{"finding_index": 0, "claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}, "source_sentence": "s1"}, {"claim_type": "FILE_EXISTS", "parameters": {"path": "b.py"}, "source_sentence": "s2"}]'
        items = [
            {"reasoning": "a.py exists", "evidence": {}, "finding_file": "a.py"},
            {"reasoning": "b.py exists", "evidence": {}, "finding_file": "b.py"},
        ]
        result = extract_claims_batch(items, mock_llm, fallback="skip")
        assert len(result.get(0, [])) == 1

    def test_failed_extraction_returns_empty(self):
        def mock_llm(system, user):
            raise RuntimeError("API error")
        items = [{"reasoning": "test", "evidence": {}, "finding_file": "a.py"}]
        result = extract_claims_batch(items, mock_llm)
        assert result == {0: []}

    def test_invalid_json_returns_empty(self):
        def mock_llm(system, user):
            return "not json at all"
        items = [{"reasoning": "test", "evidence": {}, "finding_file": "a.py"}]
        result = extract_claims_batch(items, mock_llm)
        assert result == {0: []}

    def test_finding_index_coerced_to_int(self):
        def mock_llm(system, user):
            return '[{"finding_index": "0", "claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}, "source_sentence": "test"}]'
        items = [{"reasoning": "test", "evidence": {}, "finding_file": "a.py"}]
        result = extract_claims_batch(items, mock_llm)
        assert len(result[0]) == 1
