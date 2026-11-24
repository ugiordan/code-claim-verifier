"""Tree-sitter AST backend for function and symbol verification.

A Python-native AST tier using py-tree-sitter: parses source files
with tree-sitter grammars and answers FUNCTION_EXISTS,
FUNCTION_CALLED, and HAS_CALLERS queries from actual syntax nodes.
String literals and comments are structurally invisible to the AST,
eliminating the false-positive class that grep-based symbol lookups
produce (a function name inside a comment or string is not a
definition).

Dependencies are optional and pure pip: tree-sitter plus the
per-language grammar packages (tree-sitter-python, tree-sitter-go,
...). When a grammar is unavailable or a file cannot be parsed,
callers fall through to the grep backend.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# Claimed language -> tree-sitter grammar module attribute.
# Languages without a grammar here return no results, and the
# engine falls back to grep.
_GRAMMAR_MODULES: dict[str, tuple[str, str]] = {
    "python": ("tree_sitter_python", "language"),
    "go": ("tree_sitter_go", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "rust": ("tree_sitter_rust", "language"),
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
}

_SOURCE_EXTENSIONS = {
    "python": {".py"},
    "go": {".go"},
    "javascript": {".js", ".jsx", ".mjs"},
    "typescript": {".ts", ".tsx"},
    "rust": {".rs"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".cc", ".cxx", ".hpp", ".hh"},
}

# Node types that represent a function or method definition,
# keyed by the tree-sitter grammar's node naming.
_FUNCTION_DEFINITION_NODES = {
    "python": {"function_definition"},
    "go": {"function_declaration", "method_declaration"},
    "javascript": {
        "function_declaration", "method_definition",
        "function_expression", "arrow_function",
    },
    "typescript": {
        "function_declaration", "method_definition",
        "function_expression", "arrow_function",
    },
    "rust": {"function_item"},
    "c": {"function_definition", "declaration"},
    "cpp": {"function_definition", "declaration", "method_declaration"},
}

# Node types that represent a call expression.
_CALL_NODES = {
    "python": {"call"},
    "go": {"call_expression"},
    "javascript": {"call_expression"},
    "typescript": {"call_expression"},
    "rust": {"call_expression", "macro_invocation"},
    "c": {"call_expression", "init_declarator"},
    "cpp": {"call_expression"},
}

# Field or child index holding the function's identifier, per node
# type family. Tree-sitter exposes named fields; we try the common
# ones and fall back to the first named child of type "identifier".
_NAME_FIELDS = ("name", "declarator", "function")


class TreeSitterBackend:
    """Answer symbol queries from tree-sitter AST parses."""

    def __init__(self, languages: list[str] | None = None):
        self._parsers: dict[str, object] = {}
        wanted = languages if languages is not None else list(_GRAMMAR_MODULES)
        for lang in wanted:
            parser = _load_parser(lang)
            if parser is not None:
                self._parsers[lang] = parser

    @property
    def available_languages(self) -> list[str]:
        return sorted(self._parsers)

    def function_exists(self, name: str, repo_path: str,
                        file_hint: str = "") -> dict | None:
        """Find a function definition by name.

        Returns {"file", "line", "name"} when found, {} when the
        search ran and the function is not defined (a confident
        negative), or None when no parser could search (fall back
        to grep).
        """
        searched = False
        for lang, parser in self._parsers.items():
            if file_hint:
                ext = os.path.splitext(file_hint)[1].lower()
                if ext and ext not in _SOURCE_EXTENSIONS.get(lang, set()):
                    continue
            searched = True
            result = _find_in_repo(parser, lang, name, repo_path)
            if result is not None:
                return result
        return {} if searched else None

    def function_callers(self, name: str, repo_path: str,
                         file_hint: str = "") -> list[dict]:
        """Find call sites of a function.

        Returns [{"file", "line", "caller"}] where caller is the
        enclosing function name when determinable.
        """
        callers: list[dict] = []
        for lang, parser in self._parsers.items():
            callers.extend(_find_callers(parser, lang, name, repo_path))
        return callers


def _load_parser(language: str):
    """Load a tree-sitter parser for a language, or None."""
    spec = _GRAMMAR_MODULES.get(language)
    if spec is None:
        return None
    module_name, attr = spec
    try:
        import tree_sitter

        module = __import__(module_name)
        lang_obj = tree_sitter.Language(getattr(module, attr)())
        return tree_sitter.Parser(lang_obj)
    except Exception as exc:
        logger.debug("tree-sitter grammar unavailable for %s: %s", language, exc)
        return None


def _node_name(node, source: bytes) -> str:
    """Extract the identifier from a function definition node."""
    for field in _NAME_FIELDS:
        child = node.child_by_field_name(field)
        if child is not None:
            return source[child.start_byte:child.end_byte].decode(
                "utf-8", errors="replace"
            )
    for child in node.children:
        if child.type in ("identifier", "field_identifier", "property_identifier"):
            return source[child.start_byte:child.end_byte].decode(
                "utf-8", errors="replace"
            )
    return ""


def _iter_source_files(repo_path: str, extensions: set[str]):
    for directory, dirs, files in os.walk(repo_path):
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "__pycache__", "node_modules", "vendor", "thirdparty"}
        ]
        for fname in sorted(files):
            if os.path.splitext(fname)[1].lower() in extensions:
                yield os.path.join(directory, fname)


def _read_source(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(4 * 1024 * 1024)
    except OSError:
        return b""


def _walk(node):
    cursor = node.walk()
    reached_root = False
    while not reached_root:
        yield cursor.node
        if cursor.goto_first_child():
            continue
        if cursor.goto_next_sibling():
            continue
        while True:
            if not cursor.goto_parent():
                reached_root = True
                break
            if cursor.goto_next_sibling():
                break


def _find_in_repo(parser, language: str, name: str, repo_path: str):
    """Search for a function definition, or None if not found."""
    extensions = _SOURCE_EXTENSIONS.get(language, set())
    if not extensions:
        return None
    for path in _iter_source_files(repo_path, extensions):
        source = _read_source(path)
        if not source:
            continue
        try:
            tree = parser.parse(source)
        except Exception:
            continue
        for node in _walk(tree.root_node):
            if node.type not in _FUNCTION_DEFINITION_NODES.get(language, set()):
                continue
            if _node_name(node, source) == name:
                rel = os.path.relpath(path, repo_path).replace(os.sep, "/")
                return {
                    "file": rel,
                    "line": node.start_point[0] + 1,
                    "name": name,
                }
    return None


def _enclosing_function(node, source: bytes) -> str:
    """Walk up from a call node to the enclosing function name."""
    parent = node.parent
    while parent is not None:
        if parent.type in {
            *_FUNCTION_DEFINITION_NODES.get("python", set()),
            *_FUNCTION_DEFINITION_NODES.get("go", set()),
            *_FUNCTION_DEFINITION_NODES.get("c", set()),
        }:
            return _node_name(parent, source)
        parent = parent.parent
    return "?"


def _find_callers(parser, language: str, name: str, repo_path: str):
    """Find call sites of a function across the repo."""
    callers: list[dict] = []
    extensions = _SOURCE_EXTENSIONS.get(language, set())
    if not extensions:
        return callers
    for path in _iter_source_files(repo_path, extensions):
        source = _read_source(path)
        if not source:
            continue
        try:
            tree = parser.parse(source)
        except Exception:
            continue
        for node in _walk(tree.root_node):
            if node.type not in _CALL_NODES.get(language, set()):
                continue
            call_text = source[node.start_byte:node.end_byte].decode(
                "utf-8", errors="replace"
            )
            if not call_text.startswith(name + "("):
                continue
            rel = os.path.relpath(path, repo_path).replace(os.sep, "/")
            callers.append({
                "file": rel,
                "line": node.start_point[0] + 1,
                "caller": _enclosing_function(node, source),
            })
    return callers
