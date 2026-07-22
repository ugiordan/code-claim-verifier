from __future__ import annotations


class CandidateStatus:
    PENDING = "pending"
    CLONED = "cloned"
    BUILD_OK = "build_ok"
    VERIFIED = "verified"
    READY = "ready"
    FAILED = "failed"


ECOSYSTEMS: dict[str, str] = {
    "Go": "Go",
    "PyPI": "PyPI",
    "npm": "npm",
    "Maven": "Maven",
    "crates.io": "crates.io",
}

ECOSYSTEM_TO_LANG: dict[str, str] = {
    "Go": "go",
    "PyPI": "python",
    "npm": "javascript",
    "Maven": "java",
    "crates.io": "rust",
}

BASE_IMAGES: dict[str, list[str]] = {
    "go": ["golang:1.24", "golang:1.23", "golang:1.22", "golang:1.21", "golang:1.20", "golang:1.19"],
    "python": ["python:3.13", "python:3.12", "python:3.11", "python:3.10", "python:3.9"],
    "javascript": ["node:22", "node:20", "node:18", "node:16"],
    "typescript": ["node:22", "node:20", "node:18", "node:16"],
    "java": [
        "maven:3.9-eclipse-temurin-21",
        "maven:3.9-eclipse-temurin-17",
        "maven:3.9-eclipse-temurin-11",
        "maven:3.8-eclipse-temurin-11",
    ],
    "rust": ["rust:1.79", "rust:1.75", "rust:1.70", "rust:1.65"],
}

BUILD_COMMANDS: dict[str, dict[str, str]] = {
    "go": {"build": "go build ./...", "test": "go test ./..."},
    "python": {"build": "pip install --no-cache-dir -e .", "test": "python -m pytest --tb=short -q"},
    "javascript": {"build": "npm install", "test": "npm test"},
    "typescript": {"build": "npm install", "test": "npm test"},
    "java": {"build": "mvn compile -q", "test": "mvn test -q"},
    "rust": {"build": "cargo build", "test": "cargo test"},
}

PYTHON_ALT_INSTALL = "pip install --no-cache-dir -r requirements.txt"
