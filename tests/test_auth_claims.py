"""Tests for auth chain claim verifiers (CALL_CHAIN, DEFAULT_VALUE, CONFIG_FLAG)."""
from __future__ import annotations

import os

import pytest

from code_claim_verifier.types import TypedClaim
from code_claim_verifier.verifiers.auth_claims import (
    verify_call_chain,
    verify_config_flag,
    verify_default_value,
)

GO_REPO = os.path.join(os.path.dirname(__file__), "fixtures", "go_repo")
PYTHON_REPO = os.path.join(os.path.dirname(__file__), "fixtures", "python_repo")


# ------------------------------------------------------------------
# CALL_CHAIN
# ------------------------------------------------------------------

class TestCallChain:
    def test_simple_chain_verified(self):
        """A calls B, B calls C: chain is verified."""
        claim = TypedClaim(
            claim_type="CALL_CHAIN",
            parameters={"chain": ["Authenticate", "Authorize", "CheckRBAC"]},
            source_sentence="Authenticate calls Authorize which calls CheckRBAC",
        )
        result = verify_call_chain(claim, GO_REPO, "go")
        assert result.verdict == "VERIFIED"
        assert result.method == "call_chain"
        assert "Chain verified" in result.evidence

    def test_chain_broken(self):
        """A calls B but B doesn't call C: chain is refuted."""
        claim = TypedClaim(
            claim_type="CALL_CHAIN",
            parameters={"chain": ["Authenticate", "Authorize", "NonExistentFunc"]},
            source_sentence="Authenticate calls Authorize which calls NonExistentFunc",
        )
        result = verify_call_chain(claim, GO_REPO, "go")
        assert result.verdict == "REFUTED"
        assert "Chain broken" in result.evidence

    def test_caller_callee_shorthand(self):
        """Using caller/callee params instead of chain list."""
        claim = TypedClaim(
            claim_type="CALL_CHAIN",
            parameters={"caller": "Authenticate", "callee": "Authorize"},
            source_sentence="Authenticate calls Authorize",
        )
        result = verify_call_chain(claim, GO_REPO, "go")
        assert result.verdict == "VERIFIED"
        assert result.method == "call_chain"

    def test_chain_too_short(self):
        """Single function in chain is unverifiable (need at least 2)."""
        claim = TypedClaim(
            claim_type="CALL_CHAIN",
            parameters={"chain": ["Authenticate"]},
            source_sentence="Authenticate exists",
        )
        result = verify_call_chain(claim, GO_REPO, "go")
        assert result.verdict == "UNVERIFIABLE"
        assert result.method_confidence == 0.0
        assert "at least 2" in result.evidence


# ------------------------------------------------------------------
# DEFAULT_VALUE
# ------------------------------------------------------------------

class TestDefaultValue:
    def test_variable_found(self):
        """Variable exists in code: verified."""
        claim = TypedClaim(
            claim_type="DEFAULT_VALUE",
            parameters={"variable": "AllowedNamespaces", "default_behavior": "deny"},
            source_sentence="AllowedNamespaces defaults to deny-all when empty",
        )
        result = verify_default_value(claim, GO_REPO, "go")
        assert result.verdict == "VERIFIED"
        assert result.method == "default_value"
        assert "AllowedNamespaces" in result.evidence

    def test_variable_not_found(self):
        """Variable doesn't exist in codebase: refuted."""
        claim = TypedClaim(
            claim_type="DEFAULT_VALUE",
            parameters={"variable": "totallyMadeUpVar", "default_behavior": "allow"},
            source_sentence="totallyMadeUpVar defaults to allow",
        )
        result = verify_default_value(claim, GO_REPO, "go")
        assert result.verdict == "REFUTED"
        assert "not found" in result.evidence

    def test_no_variable_param(self):
        """Missing variable parameter: unverifiable."""
        claim = TypedClaim(
            claim_type="DEFAULT_VALUE",
            parameters={"default_behavior": "deny"},
            source_sentence="Something defaults to deny",
        )
        result = verify_default_value(claim, GO_REPO, "go")
        assert result.verdict == "UNVERIFIABLE"
        assert result.method_confidence == 0.0
        assert "No variable" in result.evidence


# ------------------------------------------------------------------
# CONFIG_FLAG
# ------------------------------------------------------------------

class TestConfigFlag:
    def test_flag_found_with_value(self):
        """Flag with expected value found: verified."""
        claim = TypedClaim(
            claim_type="CONFIG_FLAG",
            parameters={"flag": "enableK8sTokenValidation", "value": "true"},
            source_sentence="enableK8sTokenValidation is set to true",
        )
        result = verify_config_flag(claim, GO_REPO, "go")
        assert result.verdict == "VERIFIED"
        assert result.method == "config_flag"
        assert "true" in result.evidence

    def test_flag_found_wrong_value(self):
        """Flag exists but with a different value: refuted."""
        claim = TypedClaim(
            claim_type="CONFIG_FLAG",
            parameters={"flag": "enableAuditLogging", "value": "true"},
            source_sentence="enableAuditLogging is set to true",
        )
        result = verify_config_flag(claim, GO_REPO, "go")
        assert result.verdict == "REFUTED"
        assert "not with value" in result.evidence

    def test_flag_not_found(self):
        """Flag doesn't exist in the repo: refuted."""
        claim = TypedClaim(
            claim_type="CONFIG_FLAG",
            parameters={"flag": "nonExistentFlag123"},
            source_sentence="nonExistentFlag123 is enabled",
        )
        result = verify_config_flag(claim, GO_REPO, "go")
        assert result.verdict == "REFUTED"
        assert "not found" in result.evidence

    def test_flag_no_param(self):
        """Missing flag parameter: unverifiable."""
        claim = TypedClaim(
            claim_type="CONFIG_FLAG",
            parameters={"value": "true"},
            source_sentence="Some flag is set to true",
        )
        result = verify_config_flag(claim, GO_REPO, "go")
        assert result.verdict == "UNVERIFIABLE"
        assert result.method_confidence == 0.0
        assert "No flag" in result.evidence
