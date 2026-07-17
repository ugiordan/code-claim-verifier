from __future__ import annotations

import os
import tempfile

from eval.multilang.generate_gt import (
    generate_verified_gt,
    generate_refuted_gt,
    validate_negatives,
    _extract_imports,
    _extract_call_sites,
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
    def test_file_exists_claims(self):
        src = _make_source({"main.go": "package main", "pkg/util.go": "package pkg"})
        claims = generate_verified_gt(src, "go")
        file_claims = [c for c in claims if c["claim_type"] == "FILE_EXISTS"]
        paths = {c["parameters"]["path"] for c in file_claims}
        assert "main.go" in paths
        assert "pkg/util.go" in paths

    def test_function_exists_claims(self):
        src = _make_source({"main.go": "package main\nfunc handleAuth(r Request) {}\n"})
        claims = generate_verified_gt(src, "go")
        func_claims = [c for c in claims if c["claim_type"] == "FUNCTION_EXISTS"]
        assert any(c["parameters"]["name"] == "handleAuth" for c in func_claims)

    def test_import_exists_claims(self):
        src = _make_source({"main.py": "import os\nfrom json import loads\n"})
        claims = generate_verified_gt(src, "python")
        import_claims = [c for c in claims if c["claim_type"] == "IMPORT_EXISTS"]
        modules = {c["parameters"]["module"] for c in import_claims}
        assert "os" in modules
        assert "json" in modules

    def test_function_called_claims(self):
        src = _make_source({
            "main.go": "package main\nfunc main() { handleAuth() }\n",
            "auth.go": "package main\nfunc handleAuth() {}\n",
        })
        claims = generate_verified_gt(src, "go")
        call_claims = [c for c in claims if c["claim_type"] == "FUNCTION_CALLED"]
        assert any(c["parameters"]["name"] == "handleAuth" for c in call_claims)

    def test_absence_verified_claims(self):
        src = _make_source({"main.go": "package main\nfunc main() {}\n"})
        claims = generate_verified_gt(src, "go")
        absence_claims = [c for c in claims if c["claim_type"] == "ABSENCE"]
        assert len(absence_claims) >= 1
        assert all(c["expected_verdict"] == "VERIFIED" for c in absence_claims)


class TestRefutedGT:
    def test_refuted_file(self):
        claims = generate_refuted_gt(["main.go", "pkg/util.go"], ["main"], [], "go")
        file_claims = [c for c in claims if c["claim_type"] == "FILE_EXISTS"]
        assert all(c["expected_verdict"] == "REFUTED" for c in file_claims)

    def test_refuted_function(self):
        claims = generate_refuted_gt(["main.go"], ["handleAuth", "parseToken"], [], "go")
        func_claims = [c for c in claims if c["claim_type"] == "FUNCTION_EXISTS"]
        assert all(c["expected_verdict"] == "REFUTED" for c in func_claims)

    def test_refuted_import(self):
        claims = generate_refuted_gt([], [], ["os", "json"], "python")
        import_claims = [c for c in claims if c["claim_type"] == "IMPORT_EXISTS"]
        assert all(c["expected_verdict"] == "REFUTED" for c in import_claims)

    def test_refuted_absence(self):
        claims = generate_refuted_gt(["main.go"], ["handleAuth"], [], "go")
        absence_claims = [c for c in claims if c["claim_type"] == "ABSENCE"]
        assert all(c["expected_verdict"] == "REFUTED" for c in absence_claims)


class TestValidateNegatives:
    def test_drops_colliding_file(self):
        src = _make_source({"mxain.go": "package main"})
        claims = [
            {"claim_type": "FILE_EXISTS", "parameters": {"path": "mxain.go"},
             "expected_verdict": "REFUTED", "gt_tier": "tier1"},
        ]
        valid = validate_negatives(claims, src, "go")
        assert len(valid) == 0

    def test_keeps_non_colliding_file(self):
        src = _make_source({"main.go": "package main"})
        claims = [
            {"claim_type": "FILE_EXISTS", "parameters": {"path": "mxain.go"},
             "expected_verdict": "REFUTED", "gt_tier": "tier1"},
        ]
        valid = validate_negatives(claims, src, "go")
        assert len(valid) == 1


class TestExtractImports:
    def test_python_imports(self):
        imports = _extract_imports(
            _make_source({"main.py": "import os\nfrom json import loads\nimport sys\n"}),
            "python",
        )
        assert "os" in imports
        assert "json" in imports
        assert "sys" in imports

    def test_go_imports(self):
        imports = _extract_imports(
            _make_source({"main.go": 'package main\nimport (\n\t"fmt"\n\t"net/http"\n)\n'}),
            "go",
        )
        assert "fmt" in imports or "net/http" in imports
