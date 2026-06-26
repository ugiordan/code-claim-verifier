from __future__ import annotations
import os
import tempfile

from eval.cybergym.gt import (
    generate_verified_gt, generate_refuted_gt, validate_negatives,
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
