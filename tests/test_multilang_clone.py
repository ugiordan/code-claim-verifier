from __future__ import annotations

import os
import subprocess
import tempfile

from eval.multilang.clone_repos import _repo_dir_name, _count_source_files
from eval.multilang.constants import CandidateStatus


def test_repo_dir_name_from_url():
    assert _repo_dir_name("https://github.com/example/pkg", "GHSA-1234-5678") == "GHSA-1234-5678"


def test_count_source_files():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "main.go"), "w") as f:
        f.write("package main")
    with open(os.path.join(d, "README.md"), "w") as f:
        f.write("readme")
    os.makedirs(os.path.join(d, "pkg"))
    with open(os.path.join(d, "pkg", "util.go"), "w") as f:
        f.write("package pkg")
    assert _count_source_files(d) == 2


def test_clone_and_checkout_on_real_git_repo():
    d = tempfile.mkdtemp()
    repo_path = os.path.join(d, "test-repo")
    os.makedirs(repo_path)
    subprocess.run(["git", "init"], cwd=repo_path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo_path, capture_output=True)
    with open(os.path.join(repo_path, "main.go"), "w") as f:
        f.write("package main\nfunc vulnerable() {}\n")
    subprocess.run(["git", "add", "."], cwd=repo_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "vuln code"], cwd=repo_path, capture_output=True)
    vuln_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo_path, capture_output=True, text=True,
    ).stdout.strip()
    with open(os.path.join(repo_path, "main.go"), "w") as f:
        f.write("package main\nfunc fixed() {}\n")
    subprocess.run(["git", "add", "."], cwd=repo_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "fix vuln"], cwd=repo_path, capture_output=True)
    fix_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo_path, capture_output=True, text=True,
    ).stdout.strip()

    from eval.multilang.clone_repos import _checkout_pre_fix
    success = _checkout_pre_fix(repo_path, fix_commit)
    assert success
    with open(os.path.join(repo_path, "main.go")) as f:
        content = f.read()
    assert "vulnerable" in content
    assert "fixed" not in content
