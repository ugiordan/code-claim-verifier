"""Shared test fixtures.

Test suites create throwaway Git repositories. Without this guard, every
``git init`` inherits the machine's ``init.templateDir``, so a corporate
pre-commit template (secret scanning, GPG signing) runs inside test
repositories and can fail or block on machine state the suite does not
control: an expired pattern-server token makes commits exit 1, and a
global ``commit.gpgsign`` can block on pinentry. Pointing
``GIT_TEMPLATE_DIR`` at an empty directory keeps test repositories
hermetic; tests that need hooks or signing configure them explicitly.
"""
from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture(autouse=True, scope="session")
def _hermetic_git_template_dir():
    empty_template = tempfile.mkdtemp(prefix="ccv-git-template-")
    old = os.environ.get("GIT_TEMPLATE_DIR")
    os.environ["GIT_TEMPLATE_DIR"] = empty_template
    yield
    if old is None:
        os.environ.pop("GIT_TEMPLATE_DIR", None)
    else:
        os.environ["GIT_TEMPLATE_DIR"] = old
