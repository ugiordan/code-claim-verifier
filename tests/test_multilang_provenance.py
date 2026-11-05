"""Tests for multilang provenance: manifest enrichment and reasoning provenance."""
from __future__ import annotations

import json
import os
import subprocess

from eval.multilang.build_manifest import enrich_manifest, _to_manifest_entry
from eval.multilang.generate import generate_one
from eval.provenance import git_head, snapshot_digest


def _write_jsonl(path, entries):
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))
    return str(path)


def _git_repo(tmp_path, name):
    repo = tmp_path / name
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, capture_output=True)
    # Tests must not sign commits: a global commit.gpgsign=true makes git
    # invoke gpg, which blocks on pinentry when the agent cache is cold.
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repo, capture_output=True)
    (repo / "main.go").write_text("package main\n")
    subprocess.run(["git", "add", "."], cwd=repo, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)
    return str(repo)


class TestEnrichManifest:
    def test_empty_manifest_is_a_noop(self, tmp_path):
        manifest = _write_jsonl(tmp_path / "manifest.jsonl", [])
        assert enrich_manifest(manifest) == 0
        assert (tmp_path / "manifest.jsonl").read_text() == ""

    def test_non_git_source_root_gets_digest_without_head(self, tmp_path):
        root = tmp_path / "plain"
        root.mkdir()
        (root / "main.go").write_text("package main\n")
        manifest = _write_jsonl(
            tmp_path / "manifest.jsonl",
            [{"vuln_id": "GHSA-1", "source_root": str(root), "language": "go"}],
        )
        enrich_manifest(manifest)
        entry = json.loads((tmp_path / "manifest.jsonl").read_text().splitlines()[0])
        assert entry["source_digest"] == snapshot_digest(str(root))
        assert "source_head" not in entry

    def test_partially_enriched_manifest_reuses_existing_revision(self, tmp_path):
        repo = _git_repo(tmp_path, "repo")
        stale_revision = "sha256:" + "d" * 64
        manifest = _write_jsonl(
            tmp_path / "manifest.jsonl",
            [
                {
                    "vuln_id": "GHSA-done", "source_root": repo, "language": "go",
                    "manifest_schema": 2, "dataset_revision": stale_revision,
                    "source_digest": snapshot_digest(repo), "source_head": git_head(repo),
                },
                {"vuln_id": "GHSA-todo", "source_root": repo, "language": "go"},
            ],
        )
        enrich_manifest(manifest)
        entries = {
            json.loads(line)["vuln_id"]: json.loads(line)
            for line in (tmp_path / "manifest.jsonl").read_text().splitlines()
        }
        # A single recorded revision is reused so the manifest stays uniform.
        assert entries["GHSA-done"]["dataset_revision"] == stale_revision
        assert entries["GHSA-todo"]["dataset_revision"] == stale_revision
        assert entries["GHSA-todo"]["manifest_schema"] == 2
        assert entries["GHSA-todo"]["source_digest"] == snapshot_digest(repo)

    def test_whitespace_only_lines_are_tolerated(self, tmp_path):
        repo = _git_repo(tmp_path, "repo")
        path = tmp_path / "manifest.jsonl"
        path.write_text(
            json.dumps({"vuln_id": "GHSA-1", "source_root": repo, "language": "go"}) + "\n"
            "   \n"
        )
        enrich_manifest(str(path))
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        assert len(lines) == 1
        assert json.loads(lines[0])["manifest_schema"] == 2
    def test_adds_provenance_fields(self, tmp_path):
        repo = _git_repo(tmp_path, "repo")
        manifest = _write_jsonl(
            tmp_path / "manifest.jsonl",
            [{"vuln_id": "GHSA-1", "source_root": repo, "language": "go"}],
        )
        enriched = enrich_manifest(manifest)
        assert enriched == 1
        entry = json.loads((tmp_path / "manifest.jsonl").read_text().splitlines()[0])
        assert entry["manifest_schema"] == 2
        assert entry["source_digest"] == snapshot_digest(repo)
        assert entry["source_head"] == git_head(repo)
        assert entry["dataset_revision"].startswith("sha256:")
        assert len(entry["dataset_revision"]) == len("sha256:") + 64

    def test_idempotent(self, tmp_path):
        repo = _git_repo(tmp_path, "repo")
        manifest = _write_jsonl(
            tmp_path / "manifest.jsonl",
            [{"vuln_id": "GHSA-1", "source_root": repo, "language": "go"}],
        )
        assert enrich_manifest(manifest) == 1
        first = (tmp_path / "manifest.jsonl").read_text()
        assert enrich_manifest(manifest) == 0
        assert (tmp_path / "manifest.jsonl").read_text() == first

    def test_preserves_existing_fields_and_dataset_revision(self, tmp_path):
        repo = _git_repo(tmp_path, "repo")
        original_revision = "sha256:" + "a" * 64
        manifest = _write_jsonl(
            tmp_path / "manifest.jsonl",
            [{
                "vuln_id": "GHSA-1",
                "source_root": repo,
                "language": "go",
                "gt_claims": [{"claim_type": "FUNCTION_EXISTS"}],
                "dataset_revision": original_revision,
                "source_digest": snapshot_digest(repo),
                "source_head": git_head(repo),
                "manifest_schema": 2,
            }],
        )
        assert enrich_manifest(manifest) == 0  # already complete
        entry = json.loads((tmp_path / "manifest.jsonl").read_text().splitlines()[0])
        assert entry["dataset_revision"] == original_revision
        assert entry["gt_claims"] == [{"claim_type": "FUNCTION_EXISTS"}]

    def test_output_path_writes_elsewhere(self, tmp_path):
        repo = _git_repo(tmp_path, "repo")
        manifest = _write_jsonl(
            tmp_path / "manifest.jsonl",
            [{"vuln_id": "GHSA-1", "source_root": repo, "language": "go"}],
        )
        out = tmp_path / "enriched.jsonl"
        enrich_manifest(manifest, str(out))
        assert out.exists()
        original = json.loads((tmp_path / "manifest.jsonl").read_text().splitlines()[0])
        assert "manifest_schema" not in original
        assert json.loads(out.read_text().splitlines()[0])["manifest_schema"] == 2

    def test_missing_source_root_gets_schema_and_revision_only(self, tmp_path):
        manifest = _write_jsonl(
            tmp_path / "manifest.jsonl",
            [{"vuln_id": "GHSA-1", "source_root": "", "language": "go"}],
        )
        enrich_manifest(manifest)
        entry = json.loads((tmp_path / "manifest.jsonl").read_text().splitlines()[0])
        assert entry["manifest_schema"] == 2
        assert "source_digest" not in entry


class TestToManifestEntry:
    def test_includes_provenance_fields(self, tmp_path):
        repo = _git_repo(tmp_path, "repo")
        entry = _to_manifest_entry(
            {"osv_id": "GHSA-9", "source_root": repo, "language": "go"},
            "sha256:" + "b" * 64,
        )
        assert entry["vuln_id"] == "GHSA-9"
        assert entry["manifest_schema"] == 2
        assert entry["dataset_revision"] == "sha256:" + "b" * 64
        assert entry["source_digest"] == snapshot_digest(repo)
        assert entry["source_head"] == git_head(repo)


class TestGenerateProvenance:
    def _entry(self, tmp_path, name="repo"):
        repo = _git_repo(tmp_path, name)
        return {
            "vuln_id": "GHSA-1",
            "source_root": repo,
            "language": "go",
            "source_digest": snapshot_digest(repo),
            "manifest_schema": 2,
            "dataset_revision": "sha256:" + "c" * 64,
            "description": "A vulnerability description for testing.",
            "repo_url": "https://github.com/example/repo",
        }

    def test_writes_reasoning_with_provenance(self, tmp_path, monkeypatch):
        import eval.multilang.generate as gen

        def fake_llm(system, user):
            return "the vulnerable function is called from main"

        monkeypatch.setattr(gen, "get_model", lambda name: fake_llm)
        monkeypatch.setattr(
            gen, "get_model_provenance",
            lambda name: {
                "registry_name": name, "provider": "test",
                "resolved_model": name, "max_tokens": 8192,
                "temperature": 0, "config_version": "model-config-v1",
            },
        )
        entry = self._entry(tmp_path)
        result = generate_one(entry, "test-model", "informed", str(tmp_path / "out"))
        assert result is not None
        provenance = result["provenance"]
        assert provenance["manifest_schema"] == 2
        assert provenance["dataset_revision"] == entry["dataset_revision"]
        assert provenance["source_digest"] == entry["source_digest"]
        assert provenance["reasoning_version"] == "multilang-reasoning-v1"
        assert provenance["provider"] == "test"
        assert len(provenance["system_prompt_digest"]) == 64
        assert len(provenance["user_prompt_digest"]) == 64

    def test_resume_keeps_legacy_reasoning_without_provenance(self, tmp_path):
        entry = self._entry(tmp_path, "repo2")
        out_dir = tmp_path / "out" / "test-model" / "informed"
        out_dir.mkdir(parents=True)
        legacy = {
            "vuln_id": entry["vuln_id"],
            "model": "test-model",
            "condition": "informed",
            "reasoning": "cached legacy reasoning",
            "reasoning_length": 22,
            "source_chars": 100,
            "duration_s": 0.1,
        }
        (out_dir / f"{entry['vuln_id']}.json").write_text(json.dumps(legacy))
        result = generate_one(entry, "test-model", "informed", str(tmp_path / "out"))
        assert result == legacy

    def test_resume_returns_matching_provenance_without_llm_call(self, tmp_path, monkeypatch):
        import eval.multilang.generate as gen

        entry = self._entry(tmp_path, "repo3")

        def fake_llm(system, user):
            return "first run reasoning"

        monkeypatch.setattr(gen, "get_model", lambda name: fake_llm)
        monkeypatch.setattr(
            gen, "get_model_provenance",
            lambda name: {
                "registry_name": name, "provider": "test",
                "resolved_model": name, "max_tokens": 8192,
                "temperature": 0, "config_version": "model-config-v1",
            },
        )
        out_dir = str(tmp_path / "out")
        first = generate_one(entry, "test-model", "informed", out_dir)
        assert first is not None

        def boom(system, user):
            raise AssertionError("LLM must not be called on provenance-matched resume")

        monkeypatch.setattr(gen, "get_model", lambda name: boom)
        second = generate_one(entry, "test-model", "informed", out_dir)
        assert second == first

    def test_skips_when_source_digest_mismatches(self, tmp_path):
        entry = self._entry(tmp_path, "repo4")
        (tmp_path / "repo4" / "main.go").write_text("package main\nfunc tampered() {}\n")
        result = generate_one(entry, "test-model", "informed", str(tmp_path / "out"))
        assert result is None

    def test_missing_source_root_returns_none(self, tmp_path):
        entry = self._entry(tmp_path, "repo5")
        entry["source_root"] = str(tmp_path / "does-not-exist")
        entry["source_digest"] = ""
        result = generate_one(entry, "test-model", "informed", str(tmp_path / "out"))
        assert result is None

    def test_unenriched_entry_still_generates(self, tmp_path, monkeypatch):
        import eval.multilang.generate as gen

        def fake_llm(system, user):
            return "reasoning without provenance-tracked manifest"

        monkeypatch.setattr(gen, "get_model", lambda name: fake_llm)
        monkeypatch.setattr(
            gen, "get_model_provenance",
            lambda name: {
                "registry_name": name, "provider": "test",
                "resolved_model": name, "max_tokens": 8192,
                "temperature": 0, "config_version": "model-config-v1",
            },
        )
        entry = self._entry(tmp_path, "repo6")
        for field in ("source_digest", "manifest_schema", "dataset_revision"):
            entry[field] = None
        result = generate_one(entry, "test-model", "informed", str(tmp_path / "out"))
        assert result is not None
        assert result["reasoning"] == "reasoning without provenance-tracked manifest"
        # Legacy manifests produce provenance with unset manifest fields.
        assert result["provenance"]["source_digest"] is None

    def test_changed_provenance_regenerates(self, tmp_path, monkeypatch):
        import eval.multilang.generate as gen

        entry = self._entry(tmp_path, "repo7")
        calls = []

        def fake_llm(system, user):
            calls.append(1)
            return "regenerated reasoning"

        monkeypatch.setattr(gen, "get_model", lambda name: fake_llm)
        monkeypatch.setattr(
            gen, "get_model_provenance",
            lambda name: {
                "registry_name": name, "provider": "test",
                "resolved_model": name, "max_tokens": 8192,
                "temperature": 0, "config_version": "model-config-v1",
            },
        )
        out_dir = str(tmp_path / "out")
        first = generate_one(entry, "test-model", "informed", out_dir)
        assert first is not None and len(calls) == 1

        # Same entry, different model: provenance differs, so it must regenerate.
        second = generate_one(entry, "other-model", "informed", out_dir)
        assert second is not None
        assert len(calls) == 2
        assert second["model"] == "other-model"
        assert second["reasoning"] == "regenerated reasoning"

    def test_relative_source_root_is_resolved(self, tmp_path, monkeypatch):
        import eval.multilang.generate as gen

        repo = _git_repo(tmp_path, "repo8")
        monkeypatch.chdir(tmp_path)
        entry = {
            "vuln_id": "GHSA-1",
            "source_root": os.path.relpath(repo, tmp_path),
            "language": "go",
            "source_digest": snapshot_digest(repo),
            "manifest_schema": 2,
            "dataset_revision": "sha256:" + "e" * 64,
            "description": "A vulnerability description for testing.",
        }

        def fake_llm(system, user):
            return "relative path reasoning"

        monkeypatch.setattr(gen, "get_model", lambda name: fake_llm)
        monkeypatch.setattr(
            gen, "get_model_provenance",
            lambda name: {
                "registry_name": name, "provider": "test",
                "resolved_model": name, "max_tokens": 8192,
                "temperature": 0, "config_version": "model-config-v1",
            },
        )
        result = generate_one(entry, "test-model", "informed", str(tmp_path / "out"))
        assert result is not None
        assert result["provenance"]["source_digest"] == snapshot_digest(str(repo))
