from __future__ import annotations

import json
import sys
from dataclasses import asdict
from typing import Any

from code_claim_verifier import VerificationEngine, fetch_osv_assessment
from code_claim_verifier.types import CLAIM_TYPES, TypedClaim

_SERVER_NAME = "code-claim-verifier"
_SERVER_VERSION = "0.8.0"
_DEFAULT_PROTOCOL_VERSION = "2025-11-25"

_ADDITIONAL_CLAIM_SCHEMAS: dict[str, dict[str, Any]] = {
    "PACKAGE_ABSENT": {
        "description": "Assert that a package is absent from build-path lockfiles",
        "parameters": {
            "package": {"type": "string", "description": "Package name"},
        },
        "required": ["package"],
    },
    "VERSION_IN_RANGE": {
        "description": "Assert whether an installed version is in an affected range",
        "parameters": {
            "version": {"type": "string", "description": "Installed version"},
            "range": {"type": "string", "description": "Affected version range"},
            "ecosystem": {"type": "string", "description": "Package ecosystem"},
            "cve": {"type": "string", "description": "Optional CVE identifier"},
            "expected": {"type": "boolean", "description": "Expected range membership"},
        },
        "required": ["version", "range"],
    },
    "UPGRADE_FIXES": {
        "description": "Assert whether an upgrade reaches a vulnerability's fixed version",
        "parameters": {
            "upgrade": {"type": "string", "description": "Proposed upgrade version"},
            "fixed_in": {"type": "string", "description": "First fixed version"},
            "installed": {"type": "string", "description": "Currently installed version"},
            "ecosystem": {"type": "string", "description": "Package ecosystem"},
        },
        "required": ["upgrade", "fixed_in"],
    },
    "VULNERABLE_SYMBOL_CALLED": {
        "description": "Assert whether a vulnerable package symbol is called by shipped code",
        "parameters": {
            "function": {"type": "string", "description": "Vulnerable function symbol"},
            "package": {"type": "string", "description": "Package containing the symbol"},
            "expected": {"type": "boolean", "description": "Expected call reachability"},
        },
        "required": ["function", "package"],
    },
    "REDHAT_VEX_STATUS": {
        "description": "Assert the Red Hat VEX status for a component and CVE",
        "parameters": {
            "cve_id": {"type": "string", "description": "CVE identifier"},
            "expected_status": {"type": "string", "description": "Expected VEX status"},
            "product_prefix": {"type": "string", "description": "Red Hat product prefix"},
            "component": {"type": "string", "description": "Component name"},
        },
        "required": ["cve_id", "expected_status", "product_prefix", "component"],
    },
}


def _claim_type_schemas() -> dict[str, dict[str, Any]]:
    """Return parameter schemas for every built-in claim type."""
    from code_claim_verifier.cli import CLAIM_SCHEMAS

    schemas = {name: dict(schema) for name, schema in CLAIM_SCHEMAS.items()}
    schemas.update(_ADDITIONAL_CLAIM_SCHEMAS)
    return {name: schemas[name] for name in sorted(CLAIM_TYPES)}


def _json_schema_type(type_name: str) -> dict[str, Any]:
    """Convert the package's compact parameter type labels to JSON Schema."""
    if type_name in {"str", "string"} or type_name.startswith(("allow|", "code|")):
        return {"type": "string"}
    if type_name in {"int", "integer"}:
        return {"type": "integer"}
    if type_name in {"bool", "boolean"}:
        return {"type": "boolean"}
    if type_name.startswith("list"):
        return {"type": "array", "items": {"type": "string"}}
    return {"type": "object"}


def _parameter_schema(schema: dict[str, Any]) -> dict[str, Any]:
    properties = {}
    for name, details in schema.get("parameters", {}).items():
        property_schema = _json_schema_type(details.get("type", "object"))
        if "description" in details:
            property_schema["description"] = details["description"]
        properties[name] = property_schema
    result: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": True,
    }
    required = schema.get("required", [])
    if required:
        result["required"] = required
    return result


def list_claim_types() -> dict[str, dict[str, Any]]:
    """Return all built-in claim types and their parameter schemas."""
    return {
        name: {
            "description": schema.get("description", ""),
            "parameters": _parameter_schema(schema),
        }
        for name, schema in _claim_type_schemas().items()
    }


def list_tools() -> list[dict[str, Any]]:
    """Return the MCP tool definitions."""
    return [
        {
            "name": "verify_claim",
            "description": (
                "Verify a typed claim against a local source repository."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "claim_type": {
                        "type": "string",
                        "enum": sorted(CLAIM_TYPES),
                        "description": "Built-in claim type to verify",
                    },
                    "parameters": {
                        "type": "object",
                        "description": "Claim parameters, specific to claim_type",
                    },
                    "repo_path": {
                        "type": "string",
                        "description": "Path to the source repository",
                    },
                    "language": {
                        "type": "string",
                        "description": "Repository language, defaults to unknown",
                    },
                },
                "required": ["claim_type", "parameters", "repo_path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "list_claim_types",
            "description": "List built-in claim types and their parameter schemas.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "assess_cve",
            "description": "Assess a package version for a CVE using the OSV API.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE identifier"},
                    "package": {"type": "string", "description": "Package name"},
                    "version": {"type": "string", "description": "Package version"},
                },
                "required": ["cve_id", "package", "version"],
                "additionalProperties": False,
            },
        },
    ]


def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call a supported tool and return its JSON-serializable result."""
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object")

    if name == "list_claim_types":
        return list_claim_types()

    if name == "verify_claim":
        claim_type = arguments.get("claim_type")
        parameters = arguments.get("parameters")
        repo_path = arguments.get("repo_path")
        language = arguments.get("language", "unknown")
        if not isinstance(claim_type, str) or claim_type not in CLAIM_TYPES:
            raise ValueError(f"Unknown claim type: {claim_type!r}")
        if not isinstance(parameters, dict):
            raise ValueError("parameters must be an object")
        if not isinstance(repo_path, str) or not repo_path:
            raise ValueError("repo_path is required")
        if not isinstance(language, str):
            raise ValueError("language must be a string")
        schema = _claim_type_schemas()[claim_type]
        missing = [key for key in schema.get("required", []) if key not in parameters]
        if missing:
            raise ValueError(
                f"Missing required parameter(s) for {claim_type}: {', '.join(missing)}"
            )

        claim = TypedClaim(
            claim_type=claim_type,
            parameters=parameters,
            source_sentence=arguments.get("source_sentence", ""),
        )
        result = VerificationEngine().verify_claims([claim], repo_path, language)[0]
        return {
            "verdict": result.verdict,
            "evidence": result.evidence,
            "method": result.method,
            "verification_source": result.verification_source,
        }

    if name == "assess_cve":
        cve_id = arguments.get("cve_id")
        package = arguments.get("package")
        version = arguments.get("version")
        if not isinstance(cve_id, str) or not cve_id:
            raise ValueError("cve_id is required")
        if not isinstance(package, str) or not package:
            raise ValueError("package is required")
        if not isinstance(version, str) or not version:
            raise ValueError("version is required")

        assessment = fetch_osv_assessment(
            package=package,
            version=version,
            cve_id=cve_id,
        )
        return asdict(assessment)

    raise ValueError(f"Unknown tool: {name}")


def _tool_result(value: Any) -> dict[str, Any]:
    normalized = json.loads(json.dumps(value))
    return {
        "content": [{"type": "text", "text": json.dumps(normalized)}],
        "structuredContent": normalized,
    }


def _error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def handle_request(request: Any) -> dict[str, Any] | None:
    """Handle one JSON-RPC request, returning None for notifications."""
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return _error_response(
            request.get("id") if isinstance(request, dict) else None,
            -32600,
            "Invalid Request",
        )

    request_id = request.get("id")
    method = request.get("method")
    if not isinstance(method, str):
        return _error_response(request_id, -32600, "Invalid Request")
    if "id" not in request:
        return None

    params = request.get("params", {})
    if not isinstance(params, dict):
        return _error_response(request_id, -32602, "Invalid params")

    if method == "initialize":
        requested_version = params.get("protocolVersion")
        protocol_version = (
            requested_version if isinstance(requested_version, str)
            else _DEFAULT_PROTOCOL_VERSION
        )
        result = {
            "protocolVersion": protocol_version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": _SERVER_NAME, "version": _SERVER_VERSION},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": list_tools()}
    elif method == "tools/call":
        name = params.get("name")
        if not isinstance(name, str):
            return _error_response(request_id, -32602, "Tool name is required")
        try:
            value = call_tool(name, params.get("arguments", {}))
        except (ValueError, TypeError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {"type": "text", "text": f"{type(exc).__name__}: {exc}"}
                    ],
                    "isError": True,
                },
            }
        result = _tool_result(value)
    else:
        return _error_response(request_id, -32601, f"Method not found: {method}")

    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve(
    stdin: Any = sys.stdin,
    stdout: Any = sys.stdout,
) -> None:
    """Serve newline-delimited JSON-RPC requests over stdio."""
    for line in stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = _error_response(None, -32700, f"Parse error: {exc.msg}")
        else:
            response = handle_request(request)
        if response is not None:
            stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            stdout.flush()


def main() -> None:
    """Start the MCP stdio server."""
    serve()


if __name__ == "__main__":
    main()
