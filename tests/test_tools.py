from __future__ import annotations

import os

from code_claim_verifier import CodeClaimVerifier
from code_claim_verifier.types import VerifiedClaim

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "python_repo")


def mock_llm(s, u):
    return "[]"


class TestToolSchemas:
    def test_default_tools_returns_list(self):
        tools = CodeClaimVerifier.default_tools()
        assert isinstance(tools, list)
        assert len(tools) == 4
        names = {t["name"] for t in tools}
        assert names == {"extract_claims", "verify_claim", "verify_all", "list_claim_types"}

    def test_as_tools_includes_custom_types(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        v.register(
            "MY_TYPE",
            lambda c, r, l: VerifiedClaim(
                claim=c, verdict="VERIFIED", method_confidence=0.5,
                evidence="", method="test",
            ),
            extraction_hint="MY_TYPE: {x: str} - test",
        )
        tools = v.as_tools()
        list_types_tool = [t for t in tools if t["name"] == "list_claim_types"][0]
        assert "MY_TYPE" in str(list_types_tool)

    def test_each_tool_has_required_fields(self):
        tools = CodeClaimVerifier.default_tools()
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "type" in tool["input_schema"]

    def test_as_tools_without_custom_types(self):
        v = CodeClaimVerifier(llm_function=mock_llm, repo_path=FIXTURE)
        tools = v.as_tools()
        assert len(tools) == 4
        # Should have same types as default_tools
        names = {t["name"] for t in tools}
        assert names == {"extract_claims", "verify_claim", "verify_all", "list_claim_types"}

    def test_verify_claim_tool_has_enum(self):
        tools = CodeClaimVerifier.default_tools()
        verify_tool = [t for t in tools if t["name"] == "verify_claim"][0]
        claim_type_prop = verify_tool["input_schema"]["properties"]["claim_type"]
        assert "enum" in claim_type_prop
        assert "FILE_EXISTS" in claim_type_prop["enum"]
        assert len(claim_type_prop["enum"]) == 14
