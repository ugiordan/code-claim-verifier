from __future__ import annotations
import json
from code_claim_verifier.extractor import (
    extract_claims,
    _parse_batch_output,
    _parse_extraction_output,
)
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

    def test_parse_rejects_non_object_parameters(self):
        raw = '[{"claim_type":"FILE_EXISTS","parameters":"main.py","source_sentence":"main.py exists"}]'
        assert _parse_extraction_output(raw) == []

    def test_parse_rejects_list_and_null_parameters(self):
        raw = ('[{"claim_type":"FILE_EXISTS","parameters":["main.py"],"source_sentence":"a"},'
               '{"claim_type":"FILE_EXISTS","parameters":null,"source_sentence":"b"},'
               '{"claim_type":"FILE_EXISTS","parameters":{"path":"main.py"},"source_sentence":"c"}]')
        claims = _parse_extraction_output(raw)
        # Only the well-formed claim survives.
        assert len(claims) == 1
        assert claims[0].parameters == {"path": "main.py"}

    def test_parse_batch_rejects_non_object_parameters(self):
        raw = json.dumps([{
            "finding_index": 0,
            "claim_type": "FILE_EXISTS",
            "parameters": "main.py",
            "source_sentence": "main.py exists",
        }])
        result = _parse_batch_output(
            raw, num_items=1, valid_types=frozenset({"FILE_EXISTS"}), fallback="FILE_EXISTS",
        )
        assert result == {0: []}
