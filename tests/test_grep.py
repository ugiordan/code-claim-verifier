"""Tests for code_claim_verifier.grep module."""

import os
import tempfile
import textwrap

import pytest

from code_claim_verifier.grep import grep, _grep_cache, cache_context, reset_cache


@pytest.fixture()
def sample_repo():
    """Create a temp directory with known files for grep testing."""
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "src")
    os.makedirs(src)

    with open(os.path.join(src, "main.py"), "w") as f:
        f.write(textwrap.dedent("""\
            import os

            def hello():
                print("hello world")

            def goodbye():
                print("goodbye world")
        """))

    with open(os.path.join(src, "util.py"), "w") as f:
        f.write(textwrap.dedent("""\
            SECRET_KEY = "abc123"
            API_URL = "https://example.com"
        """))

    yield tmp

    # cleanup
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)


class TestGrep:
    def test_regex_match(self, sample_repo):
        """grep with a regex pattern finds matching lines."""
        matches = grep(r"def\s+hello", sample_repo)
        assert len(matches) > 0
        assert any("def hello" in m for m in matches)

    def test_fixed_match(self, sample_repo):
        """grep with fixed=True finds literal string matches."""
        matches = grep("SECRET_KEY", sample_repo, fixed=True)
        assert len(matches) > 0
        assert any("SECRET_KEY" in m for m in matches)

    def test_no_match(self, sample_repo):
        """Returns empty list when pattern matches nothing."""
        matches = grep("nonexistent_function_xyz", sample_repo)
        assert matches == []


class TestGrepCache:
    def test_cache_returns_same_result(self, sample_repo):
        """Cached results equal fresh results."""
        token = cache_context()
        try:
            first = grep(r"def\s+hello", sample_repo)
            second = grep(r"def\s+hello", sample_repo)
            assert first == second
        finally:
            reset_cache(token)

    def test_cache_returns_defensive_copy(self, sample_repo):
        """Mutating a returned result does not affect the cache."""
        token = cache_context()
        try:
            first = grep(r"def\s+hello", sample_repo)
            first.append("INJECTED")
            second = grep(r"def\s+hello", sample_repo)
            assert "INJECTED" not in second
        finally:
            reset_cache(token)

    def test_no_cache_by_default(self):
        """_grep_cache.get() is None when no context has been set."""
        assert _grep_cache.get() is None

    def test_cache_isolated_after_reset(self, sample_repo):
        """Cache is None after reset."""
        token = cache_context()
        _ = grep("hello", sample_repo, fixed=True)
        reset_cache(token)
        assert _grep_cache.get() is None
