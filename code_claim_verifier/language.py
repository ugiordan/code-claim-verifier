import os
import re

LANG_MAP = {
    ".py": "python", ".go": "go", ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".java": "java", ".c": "c", ".cpp": "cpp",
    ".h": "c", ".hpp": "cpp", ".rs": "rust", ".rb": "ruby",
}

FUNCTION_DEF_PATTERNS: dict[str, str] = {
    "python": r"def\s+{name}\s*\(",
    "go": r"func\s+(?:\([^)]*\)\s+)?{name}\s*\(",
    "typescript": r"(?:function\s+{name}|(?:const|let|var)\s+{name}\s*=)",
    "javascript": r"(?:function\s+{name}|(?:const|let|var)\s+{name}\s*=)",
    "java": r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+{name}\s*\(",
    "c": r"[\w*]+\s+{name}\s*\(",
    "cpp": r"[\w*:]+\s+{name}\s*\(",
    "rust": r"fn\s+{name}\s*[<(]",
    "unknown": r"(?:def|func|function|fn)\s+{name}\s*\(|{name}\s*[=:]\s*(?:function|\()",
}

IMPORT_PATTERNS: dict[str, list[str]] = {
    "python": [r"import\s+{module}", r"from\s+{module}\s+import"],
    "go": [r'"\s*{module}\s*"'],
    "typescript": [r"import\s+.*from\s+['\"].*{module}", r"require\(['\"].*{module}"],
    "javascript": [r"import\s+.*from\s+['\"].*{module}", r"require\(['\"].*{module}"],
    "java": [r"import\s+.*{module}"],
    "c": [r"#include\s+[<\"].*{module}"],
    "cpp": [r"#include\s+[<\"].*{module}"],
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
    return [t.format(module=re.escape(module)) for t in templates]
