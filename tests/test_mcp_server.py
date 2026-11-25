from __future__ import annotations

import io
import json

from code_claim_verifier import mcp_server


def _call_tool(name: str, arguments: dict) -> dict:
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    assert response is not None
    return response["result"]


def test_tools_list_includes_claim_types_and_assessment_tool():
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
    })

    assert response is not None
    tools = response["result"]["tools"]
    assert {tool["name"] for tool in tools} == {
        "verify_claim",
        "list_claim_types",
        "assess_cve",
    }
    schemas = _call_tool("list_claim_types", {})["structuredContent"]
    assert "FILE_EXISTS" in schemas
    assert "REDHAT_VEX_STATUS" in schemas
    assert schemas["FILE_EXISTS"]["parameters"]["required"] == ["path"]


def test_verify_file_exists_claim(tmp_path):
    (tmp_path / "present.py").write_text("value = 1\n")

    result = _call_tool(
        "verify_claim",
        {
            "claim_type": "FILE_EXISTS",
            "parameters": {"path": "present.py"},
            "repo_path": str(tmp_path),
        },
    )

    assert result["structuredContent"]["verdict"] == "VERIFIED"
    assert result["structuredContent"]["method"]
    assert "verification_source" in result["structuredContent"]


def test_unknown_claim_type_returns_tool_error():
    result = _call_tool(
        "verify_claim",
        {
            "claim_type": "NOT_A_CLAIM",
            "parameters": {},
            "repo_path": ".",
        },
    )

    assert result["isError"] is True
    assert "Unknown claim type" in result["content"][0]["text"]


def test_missing_claim_parameters_returns_tool_error():
    result = _call_tool(
        "verify_claim",
        {
            "claim_type": "FILE_EXISTS",
            "parameters": {},
            "repo_path": ".",
        },
    )

    assert result["isError"] is True
    assert "Missing required parameter" in result["content"][0]["text"]


def test_assess_cve_with_mocked_osv_response(monkeypatch):
    class MockResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return json.dumps({
                "vulns": [
                    {
                        "id": "GHSA-test",
                        "aliases": ["CVE-2026-1234"],
                    },
                ],
            }).encode()

    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: MockResponse())

    result = _call_tool(
        "assess_cve",
        {
            "cve_id": "CVE-2026-1234",
            "package": "example",
            "version": "1.0.0",
        },
    )

    assessment = result["structuredContent"]
    assert assessment["vulnerability_count"] == 1
    assert assessment["vulnerability_ids"] == ["GHSA-test"]
    assert assessment["matching_cve"] is True


def test_stdio_server_uses_one_json_rpc_message_per_line():
    request = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "ping",
    })
    output = io.StringIO()

    mcp_server.serve(io.StringIO(request + "\n"), output)

    response = json.loads(output.getvalue())
    assert response == {"jsonrpc": "2.0", "id": 3, "result": {}}
