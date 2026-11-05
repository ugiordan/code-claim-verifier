"""Tests for eval/provenance.py: digests, revision validation, git state."""
from __future__ import annotations

import os
import subprocess

from eval.provenance import (
    git_head,
    git_is_clean,
    is_immutable_revision,
    snapshot_digest,
    text_digest,
)


def _git_repo(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, capture_output=True)
    # Tests must not sign commits: a global commit.gpgsign=true makes git
    # invoke gpg, which blocks on pinentry when the agent cache is cold.
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp_path, capture_output=True)
    (tmp_path / "main.go").write_text("package main\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)
    return tmp_path


class TestSnapshotDigest:
    def test_stable_across_calls(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello\n")
        assert snapshot_digest(str(tmp_path)) == snapshot_digest(str(tmp_path))

    def test_empty_directory_is_stable(self, tmp_path):
        first = snapshot_digest(str(tmp_path))
        assert first == snapshot_digest(str(tmp_path))
        assert len(first) == 64

    def test_nested_directories_included(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello\n")
        first = snapshot_digest(str(tmp_path))
        sub = tmp_path / "deep" / "nested"
        sub.mkdir(parents=True)
        (sub / "b.txt").write_text("x\n")
        assert snapshot_digest(str(tmp_path)) != first

    def test_excluded_dirs_skipped_at_any_depth(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello\n")
        first = snapshot_digest(str(tmp_path))
        deep = tmp_path / "src" / ".git"
        deep.mkdir(parents=True)
        (deep / "HEAD").write_text("ref: refs/heads/main\n")
        assert snapshot_digest(str(tmp_path)) == first

    def test_changes_with_content(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello\n")
        first = snapshot_digest(str(tmp_path))
        (tmp_path / "a.txt").write_text("world\n")
        assert snapshot_digest(str(tmp_path)) != first

    def test_changes_with_file_names(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello\n")
        first = snapshot_digest(str(tmp_path))
        (tmp_path / "a.txt").unlink()
        (tmp_path / "b.txt").write_text("hello\n")
        assert snapshot_digest(str(tmp_path)) != first

    def test_ignores_vcs_metadata_and_cache(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello\n")
        first = snapshot_digest(str(tmp_path))
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "index").write_text("git internals\n")
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "a.pyc").write_text("bytes\n")
        assert snapshot_digest(str(tmp_path)) == first

    def test_skips_symlinks(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello\n")
        first = snapshot_digest(str(tmp_path))
        os.symlink("/etc/hostname", tmp_path / "link.txt")
        assert snapshot_digest(str(tmp_path)) == first


class TestTextDigest:
    def test_matches_sha256(self):
        import hashlib
        expected = hashlib.sha256(b"claim extractor prompt").hexdigest()
        assert text_digest("claim extractor prompt") == expected

    def test_distinct_inputs(self):
        assert text_digest("a") != text_digest("b")


class TestImmutableRevision:
    def test_accepts_40_char_commit(self):
        assert is_immutable_revision("a" * 40)
        assert is_immutable_revision("0123456789abcdef0123456789abcdef01234567")

    def test_accepts_sha256_digest(self):
        assert is_immutable_revision("sha256:" + "a" * 64)

    def test_rejects_mutable_refs(self):
        assert not is_immutable_revision("main")
        assert not is_immutable_revision("v1.0.0")
        assert not is_immutable_revision("HEAD")

    def test_rejects_short_hashes(self):
        assert not is_immutable_revision("a" * 12)
        assert not is_immutable_revision("sha256:" + "a" * 63)

    def test_rejects_non_strings(self):
        assert not is_immutable_revision(None)
        assert not is_immutable_revision(123)

    def test_accepts_uppercase_hex(self):
        assert is_immutable_revision("A" * 40)
        assert is_immutable_revision("sha256:" + "F" * 64)

    def test_rejects_non_hex_characters(self):
        assert not is_immutable_revision("g" * 40)
        assert not is_immutable_revision("")
        assert not is_immutable_revision("sha256:")


class TestGitState:
    def test_clean_repo_reports_head_and_clean(self, tmp_path):
        repo = _git_repo(tmp_path)
        head = git_head(str(repo))
        assert head is not None and len(head) == 40
        assert git_is_clean(str(repo)) is True

    def test_dirty_repo_is_not_clean(self, tmp_path):
        repo = _git_repo(tmp_path)
        (repo / "dirty.txt").write_text("uncommitted\n")
        assert git_is_clean(str(repo)) is False

    def test_non_repo_directory(self, tmp_path):
        (tmp_path / "plain.txt").write_text("hi\n")
        assert git_head(str(tmp_path)) is None
        assert git_is_clean(str(tmp_path)) is False

    def test_repo_without_commits_has_no_head(self, tmp_path):
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        assert git_head(str(tmp_path)) is None

    def test_untracked_file_makes_repo_dirty(self, tmp_path):
        repo = _git_repo(tmp_path)
        (repo / "untracked.txt").write_text("new\n")
        assert git_is_clean(str(repo)) is False

    def test_staged_change_makes_repo_dirty(self, tmp_path):
        repo = _git_repo(tmp_path)
        (repo / "main.go").write_text("package main\nfunc changed() {}\n")
        subprocess.run(["git", "add", "."], cwd=repo, capture_output=True)
        assert git_is_clean(str(repo)) is False
