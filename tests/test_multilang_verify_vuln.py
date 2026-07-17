from __future__ import annotations

import os
import subprocess
import tempfile

from eval.multilang.verify_vuln import _get_changed_files, _is_source_change


def _make_git_repo_with_fix():
    d = tempfile.mkdtemp()
    subprocess.run(["git", "init"], cwd=d, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=d, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=d, capture_output=True)
    with open(os.path.join(d, "handler.go"), "w") as f:
        f.write("package main\nfunc vulnerable() {}\n")
    with open(os.path.join(d, "README.md"), "w") as f:
        f.write("# readme\n")
    subprocess.run(["git", "add", "."], cwd=d, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=d, capture_output=True)
    with open(os.path.join(d, "handler.go"), "w") as f:
        f.write("package main\nfunc fixed() {}\n")
    subprocess.run(["git", "add", "."], cwd=d, capture_output=True)
    subprocess.run(["git", "commit", "-m", "fix vuln"], cwd=d, capture_output=True)
    fix_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True,
    ).stdout.strip()
    return d, fix_sha


class TestGetChangedFiles:
    def test_lists_changed_source_files(self):
        repo, fix_sha = _make_git_repo_with_fix()
        changed = _get_changed_files(repo, fix_sha)
        assert "handler.go" in changed
        assert "README.md" not in changed


class TestIsSourceChange:
    def test_source_file_is_source_change(self):
        assert _is_source_change(["handler.go", "main.py"])

    def test_docs_only_is_not_source_change(self):
        assert not _is_source_change(["README.md", ".github/workflows/ci.yml"])
