from __future__ import annotations
import os
import tempfile
import shutil

from eval.cybergym.prepare import scan_repo, build_manifest
from eval.cybergym.utils import find_source_root


class TestScanRepo:
    def test_scan_finds_files_and_functions(self):
        d = tempfile.mkdtemp()
        src_vul = os.path.join(d, "src-vul", "myproject")
        os.makedirs(src_vul)
        with open(os.path.join(src_vul, "main.c"), "w") as f:
            f.write("int parse_input(char *buf) {\n    return 0;\n}\n")
        try:
            entry = scan_repo(d, "test-arvo-123")
            assert entry["vuln_id"] == "test-arvo-123"
            assert entry["language"] == "c"
            assert len(entry["source_files"]) >= 1
            assert len(entry["gt_claims"]) >= 1
            verified = [c for c in entry["gt_claims"] if c["expected_verdict"] == "VERIFIED"]
            refuted = [c for c in entry["gt_claims"] if c["expected_verdict"] == "REFUTED"]
            assert len(verified) >= 1
            assert len(refuted) >= 1
        finally:
            shutil.rmtree(d)


class TestBuildManifest:
    def test_builds_from_directory(self):
        d = tempfile.mkdtemp()
        repo = os.path.join(d, "proj-arvo-100")
        src_vul = os.path.join(repo, "src-vul", "proj")
        os.makedirs(src_vul)
        with open(os.path.join(src_vul, "main.c"), "w") as f:
            f.write("void foo() {}\n")
        try:
            manifest = build_manifest(d)
            assert len(manifest) == 1
            assert manifest[0]["vuln_id"] == "proj-arvo-100"
        finally:
            shutil.rmtree(d)
