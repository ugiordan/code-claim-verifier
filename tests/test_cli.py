from __future__ import annotations

import json
import subprocess
import sys


class TestListTypes:
    def test_list_types_outputs_json(self):
        result = subprocess.run(
            [sys.executable, "-m", "code_claim_verifier", "list-types"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "FILE_EXISTS" in data
        assert "FUNCTION_CALLED" in data

    def test_list_types_has_all_14_types(self):
        result = subprocess.run(
            [sys.executable, "-m", "code_claim_verifier", "list-types"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert len(data) == 14

    def test_each_type_has_description_and_parameters(self):
        result = subprocess.run(
            [sys.executable, "-m", "code_claim_verifier", "list-types"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        for name, schema in data.items():
            assert "description" in schema, f"{name} missing description"
            assert "parameters" in schema, f"{name} missing parameters"
            assert "required" in schema, f"{name} missing required"
