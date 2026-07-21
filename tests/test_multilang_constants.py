from __future__ import annotations


def test_ecosystems_mapping():
    from eval.multilang.constants import ECOSYSTEMS
    assert ECOSYSTEMS["Go"] == "Go"
    assert ECOSYSTEMS["PyPI"] == "PyPI"
    assert ECOSYSTEMS["npm"] == "npm"
    assert ECOSYSTEMS["Maven"] == "Maven"
    assert ECOSYSTEMS["crates.io"] == "crates.io"
    assert len(ECOSYSTEMS) == 5


def test_base_images_per_language():
    from eval.multilang.constants import BASE_IMAGES
    # Bug #3 fix: Update assertions to match current values
    assert BASE_IMAGES["go"][0] == "golang:1.24"
    assert BASE_IMAGES["python"][0] == "python:3.13"
    assert BASE_IMAGES["javascript"][0] == "node:22"
    assert BASE_IMAGES["java"][0] == "maven:3.9-eclipse-temurin-21"
    assert BASE_IMAGES["rust"][0] == "rust:1.79"
    for lang, images in BASE_IMAGES.items():
        assert len(images) >= 4, f"{lang} needs at least 4 fallback images"


def test_ecosystem_to_lang():
    from eval.multilang.constants import ECOSYSTEM_TO_LANG
    assert ECOSYSTEM_TO_LANG["Go"] == "go"
    assert ECOSYSTEM_TO_LANG["PyPI"] == "python"
    assert ECOSYSTEM_TO_LANG["npm"] == "javascript"
    assert ECOSYSTEM_TO_LANG["Maven"] == "java"
    assert ECOSYSTEM_TO_LANG["crates.io"] == "rust"


def test_candidate_status_values():
    from eval.multilang.constants import CandidateStatus
    assert CandidateStatus.PENDING == "pending"
    assert CandidateStatus.CLONED == "cloned"
    assert CandidateStatus.BUILD_OK == "build_ok"
    assert CandidateStatus.VERIFIED == "verified"
    assert CandidateStatus.READY == "ready"
    assert CandidateStatus.FAILED == "failed"
