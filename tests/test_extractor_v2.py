from __future__ import annotations
from code_claim_verifier.extractor import extract_claims, _parse_extraction_output
from code_claim_verifier.types import CLAIM_TYPES

class TestValidTypes:
    def test_parse_rejects_unknown_types_by_default(self):
        raw = '[{"claim_type": "CUSTOM_TYPE", "parameters": {}, "source_sentence": "test"}]'
        result = _parse_extraction_output(raw)
        assert len(result) == 0

    def test_parse_accepts_custom_type_when_provided(self):
        raw = '[{"claim_type": "CUSTOM_TYPE", "parameters": {}, "source_sentence": "test"}]'
        result = _parse_extraction_output(raw, valid_types=frozenset(CLAIM_TYPES | {"CUSTOM_TYPE"}))
        assert len(result) == 1
        assert result[0].claim_type == "CUSTOM_TYPE"

    def test_parse_still_accepts_builtins(self):
        raw = '[{"claim_type": "FILE_EXISTS", "parameters": {"path": "a.py"}, "source_sentence": "test"}]'
        result = _parse_extraction_output(raw)
        assert len(result) == 1

class TestCustomHintSection:
    def test_extraction_includes_custom_hints(self):
        calls = []
        def mock_llm(system, user):
            calls.append(system)
            return "[]"
        extract_claims(
            reasoning="test reasoning", evidence={}, llm_function=mock_llm,
            domain_context="security triage",
            custom_hints=["DATABASE_QUERY: {pattern: str} - checks SQL patterns"],
        )
        assert "CUSTOM CLAIM TYPES:" in calls[0]
        assert "DATABASE_QUERY" in calls[0]

    def test_extraction_without_hints(self):
        calls = []
        def mock_llm(system, user):
            calls.append(system)
            return "[]"
        extract_claims(reasoning="test", evidence={}, llm_function=mock_llm)
        assert "CUSTOM CLAIM TYPES:" not in calls[0]
