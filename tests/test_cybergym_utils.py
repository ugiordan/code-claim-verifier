from __future__ import annotations
import json
import os
import tempfile

from eval.cybergym.utils import (
    load_jsonl, save_jsonl, save_json, load_json,
    normalize_claim_path, find_source_root,
)


class TestJsonIO:
    def test_save_and_load_jsonl(self):
        records = [{"id": "a", "val": 1}, {"id": "b", "val": 2}]
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
            path = f.name
        try:
            save_jsonl(records, path)
            loaded = load_jsonl(path)
            assert loaded == records
        finally:
            os.unlink(path)

    def test_save_and_load_json(self):
        data = {"key": "value", "nested": {"a": 1}}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            save_json(data, path)
            loaded = load_json(path)
            assert loaded == data
        finally:
            os.unlink(path)

    def test_load_json_returns_none_for_corrupt(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("not valid json{{{")
            path = f.name
        try:
            assert load_json(path) is None
        finally:
            os.unlink(path)


class TestPathNormalization:
    def test_strips_leading_slash(self):
        assert normalize_claim_path("/src/main.c") == "src/main.c"

    def test_resolves_dotdot(self):
        assert normalize_claim_path("src/../lib/main.c") == "lib/main.c"

    def test_passthrough_normal(self):
        assert normalize_claim_path("lib/main.c") == "lib/main.c"


class TestFindSourceRoot:
    def test_finds_src_vul_project(self):
        d = tempfile.mkdtemp()
        proj_dir = os.path.join(d, "src-vul", "myproject")
        os.makedirs(proj_dir)
        with open(os.path.join(proj_dir, "main.c"), "w") as f:
            f.write("int main() {}")
        result = find_source_root(d)
        assert result == proj_dir
        import shutil
        shutil.rmtree(d)

    def test_returns_none_if_no_src_vul(self):
        d = tempfile.mkdtemp()
        assert find_source_root(d) is None
        os.rmdir(d)
