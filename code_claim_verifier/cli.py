from __future__ import annotations

import argparse
import json
import sys

from code_claim_verifier import CodeClaimVerifier

# Parameter schemas for each of the 14 built-in claim types.
# These describe what the extraction prompt produces and what verifiers consume.
CLAIM_SCHEMAS: dict[str, dict] = {
    "FILE_EXISTS": {
        "description": "Assert that a file exists at a given path",
        "parameters": {"path": {"type": "string", "description": "Relative file path"}},
        "required": ["path"],
    },
    "LINE_CONTENT": {
        "description": "Assert that a file contains specific content at or near a line",
        "parameters": {
            "path": {"type": "string", "description": "Relative file path"},
            "line": {"type": "integer", "description": "Expected line number (approximate)"},
            "content": {"type": "string", "description": "Expected content substring"},
        },
        "required": ["path", "content"],
    },
    "FILE_CLASSIFICATION": {
        "description": "Assert a file's classification (e.g., test, config, source)",
        "parameters": {
            "path": {"type": "string", "description": "Relative file path"},
            "classification": {"type": "string", "description": "Expected classification"},
        },
        "required": ["path", "classification"],
    },
    "GENERATED_OR_VENDORED": {
        "description": "Assert that a file is generated or vendored (not hand-written)",
        "parameters": {
            "path": {"type": "string", "description": "Relative file path"},
            "expected": {"type": "boolean", "description": "True if expected to be generated/vendored"},
        },
        "required": ["path"],
    },
    "FUNCTION_EXISTS": {
        "description": "Assert that a function or method exists",
        "parameters": {
            "name": {"type": "string", "description": "Function or method name"},
            "file": {"type": "string", "description": "File where it should exist (optional)"},
        },
        "required": ["name"],
    },
    "FUNCTION_CALLED": {
        "description": "Assert that a function is called somewhere in the codebase",
        "parameters": {
            "name": {"type": "string", "description": "Function name"},
            "expected": {"type": "boolean", "description": "True if expected to be called"},
        },
        "required": ["name"],
    },
    "HAS_CALLERS": {
        "description": "Assert that a function has callers (is referenced/invoked)",
        "parameters": {
            "name": {"type": "string", "description": "Function name"},
            "expected": {"type": "boolean", "description": "True if expected to have callers"},
        },
        "required": ["name"],
    },
    "IMPORT_EXISTS": {
        "description": "Assert that a module or package is imported",
        "parameters": {
            "module": {"type": "string", "description": "Module or package name"},
            "file": {"type": "string", "description": "File where import should exist (optional)"},
        },
        "required": ["module"],
    },
    "PACKAGE_VERSION": {
        "description": "Assert a dependency's version constraint",
        "parameters": {
            "package": {"type": "string", "description": "Package name"},
            "version": {"type": "string", "description": "Expected version or constraint"},
        },
        "required": ["package"],
    },
    "DEPENDENCY_TYPE": {
        "description": "Assert the type of a dependency (direct, transitive, dev)",
        "parameters": {
            "package": {"type": "string", "description": "Package name"},
            "dep_type": {"type": "string", "description": "Expected dependency type"},
        },
        "required": ["package"],
    },
    "CVE_AFFECTS_VERSION": {
        "description": "Assert that a CVE affects the installed version of a package",
        "parameters": {
            "cve": {"type": "string", "description": "CVE identifier"},
            "package": {"type": "string", "description": "Package name"},
            "version": {"type": "string", "description": "Installed version"},
        },
        "required": ["package"],
    },
    "ABSENCE": {
        "description": "Assert that something does NOT exist in the codebase",
        "parameters": {
            "pattern": {"type": "string", "description": "Pattern that should be absent"},
            "scope": {"type": "string", "description": "Scope: file path, directory, or 'repo'"},
        },
        "required": ["pattern"],
    },
    "MITIGATION_EXISTS": {
        "description": "Assert that a security mitigation or safeguard exists",
        "parameters": {
            "mitigation": {"type": "string", "description": "Description of the mitigation"},
            "file": {"type": "string", "description": "File where mitigation should exist"},
            "pattern": {"type": "string", "description": "Code pattern to search for"},
        },
        "required": ["mitigation"],
    },
    "ENTRY_POINT": {
        "description": "Assert that a function or endpoint is an entry point (externally reachable)",
        "parameters": {
            "name": {"type": "string", "description": "Function or endpoint name"},
            "type": {"type": "string", "description": "Entry point type (http, grpc, cli, etc.)"},
        },
        "required": ["name"],
    },
}

_MAX_STDIN_BYTES = 102400


def _read_reasoning(args: argparse.Namespace) -> str:
    """Read reasoning text from --reasoning flag or stdin."""
    if args.reasoning:
        return args.reasoning
    if not sys.stdin.isatty():
        raw = sys.stdin.buffer.read(_MAX_STDIN_BYTES)
        return raw.decode("utf-8", errors="replace")
    print("Error: --reasoning is required (or pipe text to stdin)", file=sys.stderr)
    sys.exit(1)


def _make_llm_function(provider: str, model: str | None):
    """Construct the LLM function for the given provider."""
    if provider == "anthropic":
        from code_claim_verifier.providers.anthropic_provider import make_llm_function
        return make_llm_function(model)
    elif provider == "openai":
        from code_claim_verifier.providers.openai_provider import make_llm_function
        return make_llm_function(model)
    else:
        print(f"Error: unknown LLM provider '{provider}'", file=sys.stderr)
        sys.exit(1)


def _cmd_eval(args: argparse.Namespace) -> None:
    """Run the evaluation framework."""
    from code_claim_verifier.eval import run_evaluation
    from code_claim_verifier.eval.report import write_report

    report = run_evaluation(
        dataset_path=args.dataset,
        fixtures_path=args.fixtures,
        mock_extraction=args.mock_extraction,
    )
    if args.output:
        write_report(report, args.output)
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _cmd_list_types(_args: argparse.Namespace) -> None:
    """Output all claim type schemas as JSON."""
    json.dump(CLAIM_SCHEMAS, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _cmd_verify(args: argparse.Namespace) -> None:
    """Verify claims in a single reasoning text."""
    reasoning = _read_reasoning(args)
    llm_fn = _make_llm_function(args.llm_provider, args.model)
    verifier = CodeClaimVerifier(llm_function=llm_fn, repo_path=args.repo)
    report = verifier.verify(
        reasoning=reasoning,
        finding_file=args.finding_file or "",
        domain_context=args.domain_context or "",
    )
    json.dump(report.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")


def _cmd_verify_batch(args: argparse.Namespace) -> None:
    """Verify claims across multiple items."""
    if args.input:
        with open(args.input) as f:
            raw = f.read()
    elif not sys.stdin.isatty():
        raw = sys.stdin.buffer.read(_MAX_STDIN_BYTES).decode("utf-8", errors="replace")
    else:
        print("Error: --input is required (or pipe JSON to stdin)", file=sys.stderr)
        sys.exit(1)

    try:
        items = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(items, list):
        print("Error: input must be a JSON array of items", file=sys.stderr)
        sys.exit(1)

    if len(items) > args.max_items:
        print(
            f"Error: input contains {len(items)} items, max is {args.max_items}",
            file=sys.stderr,
        )
        sys.exit(1)

    llm_fn = _make_llm_function(args.llm_provider, args.model)
    verifier = CodeClaimVerifier(llm_function=llm_fn, repo_path=args.repo)
    reports = verifier.verify_batch(
        items=items,
        domain_context=args.domain_context or "",
    )
    output = [r.to_dict() for r in reports]
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="ccv",
        description="Code Claim Verifier: deterministic verification of LLM claims about code",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list-types
    sub_list = subparsers.add_parser(
        "list-types",
        help="Output JSON schemas for all supported claim types",
    )
    sub_list.set_defaults(func=_cmd_list_types)

    # verify
    sub_verify = subparsers.add_parser(
        "verify",
        help="Verify claims in LLM reasoning against a repo",
    )
    sub_verify.add_argument("--repo", required=True, help="Path to the repository")
    sub_verify.add_argument("--reasoning", help="LLM reasoning text (or pipe to stdin)")
    sub_verify.add_argument("--finding-file", default="", help="File path for language detection")
    sub_verify.add_argument("--domain-context", default="", help="Domain-specific extraction context")
    sub_verify.add_argument(
        "--llm-provider", choices=["anthropic", "openai"],
        default="anthropic", help="LLM provider (default: anthropic)",
    )
    sub_verify.add_argument("--model", default=None, help="Model name override")
    sub_verify.set_defaults(func=_cmd_verify)

    # verify-batch
    sub_batch = subparsers.add_parser(
        "verify-batch",
        help="Verify claims across multiple items in batch",
    )
    sub_batch.add_argument("--repo", required=True, help="Path to the repository")
    sub_batch.add_argument("--input", default=None, help="Path to JSON file with items (or pipe to stdin)")
    sub_batch.add_argument("--domain-context", default="", help="Domain-specific extraction context")
    sub_batch.add_argument(
        "--max-items", type=int, default=10000,
        help="Maximum number of items to process (default: 10000)",
    )
    sub_batch.add_argument(
        "--llm-provider", choices=["anthropic", "openai"],
        default="anthropic", help="LLM provider (default: anthropic)",
    )
    sub_batch.add_argument("--model", default=None, help="Model name override")
    sub_batch.set_defaults(func=_cmd_verify_batch)

    # eval
    sub_eval = subparsers.add_parser(
        "eval",
        help="Run evaluation framework against fixture repos",
    )
    sub_eval.add_argument("--dataset", required=True, help="Path to JSONL dataset")
    sub_eval.add_argument("--fixtures", required=True, help="Path to fixture repos directory")
    sub_eval.add_argument("--output", default=None, help="Optional path to write JSON report")
    sub_eval.add_argument(
        "--no-mock-extraction", action="store_false", dest="mock_extraction",
        help="Disable mock extraction and use LLM extraction instead",
    )
    sub_eval.set_defaults(mock_extraction=True)
    sub_eval.set_defaults(func=_cmd_eval)

    args = parser.parse_args(argv)
    args.func(args)
