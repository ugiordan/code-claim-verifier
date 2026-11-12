"""Tests for selective CyberGym dataset fetch and patch-derived GT."""
from __future__ import annotations

import io
import os
import shutil
import sys
import tarfile
import tempfile
import types
from pathlib import Path

from eval.cybergym.fetch import (
    _safe_extract,
    fetch_instance,
    stratified_sample,
)
from eval.cybergym.prepare import scan_repo

REAL_PATCH = Path(__file__).parent / "fixtures" / "cybergym" / "arvo-1065.patch.diff"

MINI_PATCH = """diff --git a/src/funcs.c b/src/funcs.c
index d39056b7..33778ff1 100644
--- a/src/funcs.c
+++ b/src/funcs.c
@@ -2,4 +2,4 @@ int helper_unused(void)
 #include "file.h"
-int vulnerable_check(const char *s) { return 1; }
+int vulnerable_check(const char *s) { return 0; }
 /* trailing context */
"""

PRE_PATCH_SOURCE = (
    "int helper_unused(void) {\n"
    '#include "file.h"\n'
    "int vulnerable_check(const char *s) { return 1; }\n"
    "/* trailing context */\n"
)


def _make_source(files: dict[str, str]) -> str:
    d = tempfile.mkdtemp()
    for name, content in files.items():
        path = os.path.join(d, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    return d


def _write_patch(source_dir: str, patch_text: str) -> str:
    path = os.path.join(source_dir, "patch.diff")
    with open(path, "w") as f:
        f.write(patch_text)
    return path


class TestStratifiedSample:
    def _tasks(self) -> list[dict]:
        tasks = []
        for project in ("alpha", "beta", "gamma"):
            for i in range(8):
                tasks.append({
                    "task_id": f"arvo:{project}{i}",
                    "project_name": project,
                })
        return tasks

    def test_deterministic_for_seed(self):
        tasks = self._tasks()
        first = stratified_sample(tasks, count=6, max_per_project=2, seed=42)
        second = stratified_sample(tasks, count=6, max_per_project=2, seed=42)
        assert [t["task_id"] for t in first] == [t["task_id"] for t in second]

    def test_respects_count_and_cap(self):
        selected = stratified_sample(self._tasks(), count=5, max_per_project=2, seed=1)
        assert len(selected) == 5
        per_project: dict[str, int] = {}
        for task in selected:
            per_project[task["project_name"]] = per_project.get(task["project_name"], 0) + 1
        assert all(count <= 2 for count in per_project.values())


class TestSafeExtract:
    def _tar_with_members(self, members: list[tuple[str, str]]) -> str:
        fd, path = tempfile.mkstemp(suffix=".tar.gz")
        os.close(fd)
        with tarfile.open(path, "w:gz") as tar:
            for name, content in members:
                info = tarfile.TarInfo(name=name)
                payload = content.encode()
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
        return path

    def test_extracts_normal_tarball(self):
        tar_path = self._tar_with_members([("src-vul/proj/main.c", "int main() {}\n")])
        dest = tempfile.mkdtemp()
        try:
            with tarfile.open(tar_path) as tar:
                _safe_extract(tar, dest)
            assert os.path.isfile(os.path.join(dest, "src-vul", "proj", "main.c"))
        finally:
            shutil.rmtree(dest)
            os.unlink(tar_path)

    def test_rejects_path_traversal(self):
        tar_path = self._tar_with_members([("../escape.txt", "bad")])
        dest = tempfile.mkdtemp()
        try:
            with tarfile.open(tar_path) as tar:
                try:
                    _safe_extract(tar, dest)
                except ValueError as exc:
                    assert "unsafe path" in str(exc)
                else:
                    raise AssertionError("traversal must be rejected")
            assert not os.path.exists(os.path.join(dest, "..", "escape.txt"))
        finally:
            shutil.rmtree(dest)
            os.unlink(tar_path)

    def test_skips_absolute_symlink_member(self):
        fd, tar_path = tempfile.mkstemp(suffix=".tar.gz")
        os.close(fd)
        with tarfile.open(tar_path, "w:gz") as tar:
            payload = b"int main() {}\n"
            info = tarfile.TarInfo(name="src-vul/proj/main.c")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
            link = tarfile.TarInfo(name="link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
        dest = tempfile.mkdtemp()
        try:
            with tarfile.open(tar_path) as tar:
                _safe_extract(tar, dest)
            assert os.path.isfile(os.path.join(dest, "src-vul", "proj", "main.c"))
            assert not os.path.lexists(os.path.join(dest, "link"))
        finally:
            shutil.rmtree(dest)
            os.unlink(tar_path)

    def test_skips_escaping_symlink_member(self):
        fd, tar_path = tempfile.mkstemp(suffix=".tar.gz")
        os.close(fd)
        with tarfile.open(tar_path, "w:gz") as tar:
            payload = b"int main() {}\n"
            info = tarfile.TarInfo(name="src-vul/proj/main.c")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
            link = tarfile.TarInfo(name="src-vul/proj/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../../../etc/passwd"
            tar.addfile(link)
        dest = tempfile.mkdtemp()
        try:
            with tarfile.open(tar_path) as tar:
                _safe_extract(tar, dest)
            assert os.path.isfile(os.path.join(dest, "src-vul", "proj", "main.c"))
            assert not os.path.lexists(os.path.join(dest, "src-vul", "proj", "link"))
        finally:
            shutil.rmtree(dest)
            os.unlink(tar_path)

    def test_allows_in_destination_symlink_member(self):
        fd, tar_path = tempfile.mkstemp(suffix=".tar.gz")
        os.close(fd)
        with tarfile.open(tar_path, "w:gz") as tar:
            payload = b"int main() {}\n"
            info = tarfile.TarInfo(name="src-vul/proj/main.c")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
            link = tarfile.TarInfo(name="src-vul/proj/main_link.c")
            link.type = tarfile.SYMTYPE
            link.linkname = "main.c"
            tar.addfile(link)
        dest = tempfile.mkdtemp()
        try:
            with tarfile.open(tar_path) as tar:
                _safe_extract(tar, dest)
            assert os.path.islink(os.path.join(dest, "src-vul", "proj", "main_link.c"))
        finally:
            shutil.rmtree(dest)
            os.unlink(tar_path)


class TestFetchInstance:
    def test_fetch_unpacks_and_records_provenance(self, monkeypatch):
        cache = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with tarfile.open(os.path.join(cache, "repo-vul.tar.gz"), "w:gz") as tar:
                info = tarfile.TarInfo(name="src-vul/proj/main.c")
                payload = b"int main() {}\n"
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            with open(os.path.join(cache, "description.txt"), "w") as f:
                f.write("A bug in the parser.")
            with open(os.path.join(cache, "patch.diff"), "w") as f:
                f.write(MINI_PATCH)

            downloads = []

            def fake_download(repo_id, filename, repo_type, revision):
                downloads.append(filename)
                return os.path.join(cache, os.path.basename(filename))

            fake_hub = types.ModuleType("huggingface_hub")
            fake_hub.hf_hub_download = fake_download
            monkeypatch.setitem(sys.modules, "huggingface_hub", fake_hub)

            task = {"task_id": "arvo:424242", "project_name": "proj", "project_language": "c"}
            record = fetch_instance(task, dest_root, revision="a" * 40)

            assert record is not None
            assert record["vuln_id"] == "proj-arvo-424242"
            assert record["description"] == "A bug in the parser."
            assert record["language"] == "c"
            assert set(record["artifact_digests"]) == {
                "repo-vul.tar.gz", "description.txt", "patch.diff",
            }
            assert all(v.startswith("sha256:") for v in record["artifact_digests"].values())
            inst_dir = record["instance_dir"]
            assert os.path.isfile(os.path.join(inst_dir, "src-vul", "proj", "main.c"))
            assert os.path.isfile(os.path.join(inst_dir, "patch.diff"))

            second = fetch_instance(task, dest_root, revision="a" * 40)
            assert second is not None
            assert second["artifact_digests"] == record["artifact_digests"]
            assert len(downloads) == 3  # no re-download on second call
        finally:
            shutil.rmtree(cache)
            shutil.rmtree(dest_root)

    def test_fetch_uses_task_prefix_in_path_and_name(self, monkeypatch):
        cache = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with tarfile.open(os.path.join(cache, "repo-vul.tar.gz"), "w:gz") as tar:
                info = tarfile.TarInfo(name="src-vul/proj/main.c")
                payload = b"int main() {}\n"
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            for fname in ("description.txt", "patch.diff"):
                with open(os.path.join(cache, fname), "w") as f:
                    f.write("x")

            requested = []

            def fake_download(repo_id, filename, repo_type, revision):
                requested.append(filename)
                return os.path.join(cache, os.path.basename(filename))

            fake_hub = types.ModuleType("huggingface_hub")
            fake_hub.hf_hub_download = fake_download
            monkeypatch.setitem(sys.modules, "huggingface_hub", fake_hub)

            task = {
                "task_id": "oss-fuzz:42536279",
                "project_name": "proj",
                "project_language": "c",
            }
            record = fetch_instance(task, dest_root, revision="a" * 40)
            assert record is not None
            assert record["vuln_id"] == "proj-oss-fuzz-42536279"
            assert all(p.startswith("data/oss-fuzz/42536279/") for p in requested)
        finally:
            shutil.rmtree(cache)
            shutil.rmtree(dest_root)

    def test_failed_extraction_cleans_partial_instance(self, monkeypatch):
        cache = tempfile.mkdtemp()
        dest_root = tempfile.mkdtemp()
        try:
            with tarfile.open(os.path.join(cache, "repo-vul.tar.gz"), "w:gz") as tar:
                info = tarfile.TarInfo(name="src-vul/proj/main.c")
                payload = b"int main() {}\n"
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            for fname in ("description.txt", "patch.diff"):
                with open(os.path.join(cache, fname), "w") as f:
                    f.write("x")

            def fake_download(repo_id, filename, repo_type, revision):
                return os.path.join(cache, os.path.basename(filename))

            def broken_extract(tar, dest):
                os.makedirs(os.path.join(dest, "src-vul", "partial"))
                raise ValueError("boom")

            fake_hub = types.ModuleType("huggingface_hub")
            fake_hub.hf_hub_download = fake_download
            monkeypatch.setitem(sys.modules, "huggingface_hub", fake_hub)
            monkeypatch.setattr(
                "eval.cybergym.fetch._safe_extract", broken_extract,
            )

            task = {"task_id": "arvo:777", "project_name": "proj", "project_language": "c"}
            record = fetch_instance(task, dest_root, revision="a" * 40)
            assert record is None
            inst_dir = os.path.join(dest_root, "proj-arvo-777")
            assert not os.path.exists(inst_dir), "partial instance must be cleaned up"
        finally:
            shutil.rmtree(cache)
            shutil.rmtree(dest_root)


class TestPatchGtIntegration:
    def test_scan_repo_picks_up_patch_gt(self):
        d = tempfile.mkdtemp()
        try:
            src_vul = os.path.join(d, "src-vul", "proj")
            os.makedirs(os.path.join(src_vul, "src"))
            with open(os.path.join(src_vul, "src", "funcs.c"), "w") as f:
                f.write(PRE_PATCH_SOURCE)
            with open(os.path.join(d, "patch.diff"), "w") as f:
                f.write(MINI_PATCH)
            with open(os.path.join(d, "description.txt"), "w") as f:
                f.write("A bug in funcs.c.")

            entry = scan_repo(d, "proj-arvo-1")
            assert entry["patch_gt_count"] >= 3
            assert entry["ground_truth_validation"] == "patch-derived"
            assert "patch.diff" in entry["artifact_digests"]
            assert entry["description"] == "A bug in funcs.c."
            patch_claims = [c for c in entry["gt_claims"] if c.get("gt_tier") == "patch"]
            assert len(patch_claims) == entry["patch_gt_count"]
            assert all(c["gt_tier"] == "patch" for c in patch_claims)
        finally:
            shutil.rmtree(d)

    def test_scan_repo_without_patch_stays_legacy_schema(self):
        d = tempfile.mkdtemp()
        try:
            src_vul = os.path.join(d, "src-vul", "proj")
            os.makedirs(src_vul)
            with open(os.path.join(src_vul, "main.c"), "w") as f:
                f.write("void foo() {}\n")
            entry = scan_repo(d, "proj-arvo-2")
            assert entry["patch_gt_count"] == 0
            assert entry["ground_truth_validation"] == "source-derived-unvalidated"
            assert entry["artifact_digests"] == {}
        finally:
            shutil.rmtree(d)
