from __future__ import annotations
import os
import tempfile

from eval.cybergym.gt import (
    generate_verified_gt, generate_refuted_gt, validate_negatives,
    generate_patch_gt, parse_unified_diff,
)


def _make_source(files: dict[str, str]) -> str:
    d = tempfile.mkdtemp()
    for name, content in files.items():
        path = os.path.join(d, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    return d


class TestVerifiedGT:
    def test_generates_file_exists_claims(self):
        src = _make_source({"main.c": "int main() {}", "lib/util.c": "void help() {}"})
        claims = generate_verified_gt(src, "c")
        file_claims = [c for c in claims if c["claim_type"] == "FILE_EXISTS"]
        paths = {c["parameters"]["path"] for c in file_claims}
        assert "main.c" in paths
        assert "lib/util.c" in paths

    def test_generates_function_exists_claims(self):
        src = _make_source({"main.c": "int main() {\n    return 0;\n}\n"})
        claims = generate_verified_gt(src, "c")
        func_claims = [c for c in claims if c["claim_type"] == "FUNCTION_EXISTS"]
        assert any(c["parameters"]["name"] == "main" for c in func_claims)

    def test_generates_absence_verified(self):
        src = _make_source({"main.c": "int main() {}"})
        claims = generate_verified_gt(src, "c")
        absence_claims = [c for c in claims if c["claim_type"] == "ABSENCE"]
        assert len(absence_claims) >= 1
        assert all(c["expected_verdict"] == "VERIFIED" for c in absence_claims)


class TestRefutedGT:
    def test_generates_nonexistent_files(self):
        real_files = ["main.c", "lib/util.c"]
        claims = generate_refuted_gt(real_files, ["main", "help"], "c")
        file_claims = [c for c in claims if c["claim_type"] == "FILE_EXISTS"]
        assert all(c["expected_verdict"] == "REFUTED" for c in file_claims)
        assert len(file_claims) >= 1

    def test_generates_nonexistent_functions(self):
        claims = generate_refuted_gt(["main.c"], ["parse_header", "load_data"], "c")
        func_claims = [c for c in claims if c["claim_type"] == "FUNCTION_EXISTS"]
        assert all(c["expected_verdict"] == "REFUTED" for c in func_claims)


class TestValidateNegatives:
    def test_removes_collisions(self):
        src = _make_source({"main.c": "int validate_input() {}"})
        claims = [
            {"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "validate_input", "file": "main.c"}, "expected_verdict": "REFUTED"},
            {"claim_type": "FUNCTION_EXISTS", "parameters": {"name": "nonexistent_fn", "file": "main.c"}, "expected_verdict": "REFUTED"},
        ]
        valid = validate_negatives(claims, src, "c")
        names = {c["parameters"]["name"] for c in valid}
        assert "validate_input" not in names
        assert "nonexistent_fn" in names


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


class TestParseUnifiedDiff:
    def test_line_numbers_and_paths(self):
        parsed = parse_unified_diff(MINI_PATCH)
        assert len(parsed) == 1
        entry = parsed[0]
        assert entry["path"] == "src/funcs.c"
        hunk = entry["hunks"][0]
        assert hunk["context"] == "int helper_unused(void)"
        assert hunk["removed"][0]["line"] == 3
        assert "vulnerable_check" in hunk["removed"][0]["text"]
        assert hunk["added"][0]["line"] == 2  # anchored at hunk old start

    def test_new_and_deleted_files_skipped(self):
        patch = (
            "diff --git a/new.c b/new.c\n"
            "--- /dev/null\n"
            "+++ b/new.c\n"
            "@@ -0,0 +1,2 @@\n"
            "+int added(void) { return 1; }\n"
            "+\n"
            "diff --git a/gone.c b/gone.c\n"
            "--- a/gone.c\n"
            "+++ /dev/null\n"
            "@@ -1,1 +0,0 @@\n"
            "-int gone(void) { return 1; }\n"
        )
        assert parse_unified_diff(patch) == []

    def test_real_arvo_patch_parses(self):
        from pathlib import Path
        fixture = Path(__file__).parent / "fixtures" / "cybergym" / "arvo-1065.patch.diff"
        parsed = parse_unified_diff(fixture.read_text())
        assert len(parsed) >= 1
        for entry in parsed:
            assert entry["path"]
            for hunk in entry["hunks"]:
                for item in hunk["removed"]:
                    assert item["line"] >= 1


class TestGeneratePatchGt:
    def _patched_source(self):
        src = _make_source({"src/funcs.c": PRE_PATCH_SOURCE})
        patch_path = os.path.join(src, "patch.diff")
        with open(patch_path, "w") as f:
            f.write(MINI_PATCH)
        return src, patch_path

    def test_removed_line_verifies_with_exact_number(self):
        src, patch_path = self._patched_source()
        try:
            claims = generate_patch_gt(src, patch_path, "c")
            line_claims = [
                c for c in claims
                if c["claim_type"] == "LINE_CONTENT"
                and c["expected_verdict"] == "VERIFIED"
            ]
            assert any(
                c["parameters"]["line"] == 3
                and "return 1" in c["parameters"]["content"]
                for c in line_claims
            )
        finally:
            import shutil
            shutil.rmtree(src)

    def test_added_line_is_expected_refuted(self):
        src, patch_path = self._patched_source()
        try:
            claims = generate_patch_gt(src, patch_path, "c")
            refuted = [
                c for c in claims
                if c["claim_type"] == "LINE_CONTENT"
                and c["expected_verdict"] == "REFUTED"
            ]
            assert any("return 0" in c["parameters"]["content"] for c in refuted)
            assert all(c["parameters"]["line"] == 2 for c in refuted)
        finally:
            import shutil
            shutil.rmtree(src)

    def test_file_and_function_claims(self):
        src, patch_path = self._patched_source()
        try:
            claims = generate_patch_gt(src, patch_path, "c")
            assert any(
                c["claim_type"] == "FILE_EXISTS"
                and c["parameters"]["path"] == "src/funcs.c"
                for c in claims
            )
            assert any(
                c["claim_type"] == "FUNCTION_EXISTS"
                and c["parameters"]["name"] == "helper_unused"
                for c in claims
            )
            assert all(c["gt_tier"] == "patch" for c in claims)
        finally:
            import shutil
            shutil.rmtree(src)

    def test_fuzzy_patch_context_dropped(self):
        src = _make_source({"src/funcs.c": "int other(void) { return 1; }\n"})
        patch_path = os.path.join(src, "patch.diff")
        with open(patch_path, "w") as f:
            f.write(MINI_PATCH)
        try:
            claims = generate_patch_gt(src, patch_path, "c")
            assert not any(
                c["claim_type"] == "LINE_CONTENT"
                and c["expected_verdict"] == "VERIFIED"
                for c in claims
            )
        finally:
            import shutil
            shutil.rmtree(src)

    def test_missing_patch_file_returns_empty(self):
        assert generate_patch_gt("/tmp", "/no/such/patch.diff", "c") == []
