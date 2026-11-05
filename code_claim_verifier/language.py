import os
import re

LANG_MAP = {
    ".py": "python", ".go": "go", ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".c": "c", ".cpp": "cpp",
    ".h": "c", ".hpp": "cpp", ".rs": "rust", ".rb": "ruby",
}

# These templates are consumed by BOTH grep -E and Python re (eval GT
# generation compiles them with re), so they must stay valid Python re.
# grep -E does not accept (?:...) groups (GNU prints "warning: ? at start
# of expression" and never matches; the BSD grep on macOS accepts them),
# so grep.py translates (?: to ( at the grep boundary. Capture-group
# numbering matters to the Python re consumers: the {name} group must
# stay the first group that can match non-empty text.
# {{ and }} are str.format escapes for literal braces.
FUNCTION_DEF_PATTERNS: dict[str, str] = {
    "python": r"def\s+{name}\s*\(",
    "go": r"func\s+(?:\([^)]*\)\s+)?{name}\s*\(",
    "typescript": (
        r"(?:"
        r"(?:^|[^A-Za-z0-9_$])(?:async\s+)?function\s+"
        r"{name}\s*\("
        r"|(?:^|[^A-Za-z0-9_$])(?:const|let|var)\s+{name}"
        r"\s*=\s*(?:async\s+)?"
        r"(?:function(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\(|"
        r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*"
        r"(?::\s*[^=]+)?=>)"
        r"|(?:^|\s|\{{){name}\s*\([^;{{}}]*\)\s*\{{"
        r")"
    ),
    "javascript": (
        r"(?:"
        r"(?:^|[^A-Za-z0-9_$])(?:async\s+)?function\s+"
        r"{name}\s*\("
        r"|(?:^|[^A-Za-z0-9_$])(?:const|let|var)\s+{name}"
        r"\s*=\s*(?:async\s+)?"
        r"(?:function(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\(|"
        r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>)"
        r"|(?:^|\s|\{{){name}\s*\([^;{{}}]*\)\s*\{{"
        r")"
    ),
    "java": r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+{name}\s*\(",
    "kotlin": r"(?:fun\s+{name}\s*[\(<]|(?:override\s+)?fun\s+{name}\s*[\(<])",
    "c": r"(?:[\w*]+\s+{name}\s*\(|^{name}\s*\()",
    "cpp": r"(?:[\w*:]+\s+{name}\s*\(|^{name}\s*\()",
    "rust": r"fn\s+{name}\s*[<(]",
    "unknown": (
        r"(?:\b(?:def|func|function|fn)\s+{name}\s*\(|"
        r"\b(?:const|let|var)\s+{name}\s*=\s*"
        r"(?:async\s+)?(?:function\b|"
        r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>))"
    ),
}

IMPORT_PATTERNS: dict[str, list[str]] = {
    "python": [r"import\s+{module}", r"from\s+{module}\s+import"],
    "go": [r'"\s*{module}\s*"'],
    "typescript": [r"import\s+.*from\s+['\"].*{module}", r"require\(['\"].*{module}"],
    "javascript": [r"import\s+.*from\s+['\"].*{module}", r"require\(['\"].*{module}"],
    "java": [r"import\s+.*{module}", r"import\s+{module_prefix}\.\*"],
    "kotlin": [r"import\s+.*{module}", r"import\s+{module_prefix}\.\*"],
    "c": [r"#include\s+[<\"].*{module}"],
    "cpp": [r"#include\s+[<\"].*{module}"],
    "rust": [r"use\s+.*{module}"],
    "unknown": [r"import.*{module}", r"require.*{module}", r"#include.*{module}"],
}


def detect_language(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    return LANG_MAP.get(ext, "unknown")


def get_function_pattern(name: str, language: str) -> str:
    template = FUNCTION_DEF_PATTERNS.get(language, FUNCTION_DEF_PATTERNS["unknown"])
    return template.format(name=re.escape(name))


def get_import_patterns(module: str, language: str) -> list[str]:
    templates = IMPORT_PATTERNS.get(language, IMPORT_PATTERNS["unknown"])
    module_prefix = ".".join(module.split(".")[:-1]) if "." in module else module
    results = []
    for t in templates:
        try:
            results.append(t.format(module=re.escape(module), module_prefix=re.escape(module_prefix)))
        except KeyError:
            results.append(t.format(module=re.escape(module)))
    return results
