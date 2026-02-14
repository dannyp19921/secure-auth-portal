# tests/test_auth.py
"""
Tests for authentication logic.
Run with: pytest tests/ -v
"""

import hashlib
import base64
import secrets
import os

import pytest

from app.auth.oidc import generate_pkce_pair


class TestPKCE:
    """Test PKCE code_verifier and code_challenge generation."""

    def test_pkce_pair_returns_two_strings(self):
        """Verify that PKCE pair consists of two non-empty strings."""
        verifier, challenge = generate_pkce_pair()
        assert isinstance(verifier, str)
        assert isinstance(challenge, str)
        assert len(verifier) > 0
        assert len(challenge) > 0

    def test_code_challenge_is_sha256_of_verifier(self):
        """Verify code_challenge = BASE64URL(SHA256(code_verifier))."""
        verifier, challenge = generate_pkce_pair()

        expected_digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected_challenge = base64.urlsafe_b64encode(expected_digest).rstrip(b"=").decode("ascii")

        assert challenge == expected_challenge

    def test_pkce_pairs_are_unique(self):
        """Each call should produce a unique pair (randomness check)."""
        pair1 = generate_pkce_pair()
        pair2 = generate_pkce_pair()
        assert pair1[0] != pair2[0]
        assert pair1[1] != pair2[1]

    def test_code_verifier_length(self):
        """Verifier should be long enough to be secure (min 43 chars per RFC 7636)."""
        verifier, _ = generate_pkce_pair()
        assert len(verifier) >= 43


class TestStateParameter:
    """Test OAuth2 state parameter for CSRF prevention."""

    def test_state_is_unique(self):
        """Each state should be cryptographically random."""
        state1 = secrets.token_urlsafe(32)
        state2 = secrets.token_urlsafe(32)
        assert state1 != state2

    def test_state_sufficient_length(self):
        """State should be long enough to prevent brute force."""
        state = secrets.token_urlsafe(32)
        assert len(state) >= 32


class TestConfigLoading:
    """Test that configuration loads correctly."""

    def test_settings_with_explicit_values(self):
        """Settings should accept explicit values."""
        from app.config import Settings
        settings = Settings(
            entra_tenant_id="test-tenant",
            entra_client_id="test-client",
            entra_client_secret="test-secret",
            vault_enabled=False,
            _env_file=None,
        )
        assert settings.entra_tenant_id == "test-tenant"
        assert settings.redirect_uri == "http://localhost:8000/callback"
        assert settings.vault_enabled is False

    def test_settings_has_sensible_defaults(self):
        """Default redirect_uri should point to localhost callback."""
        from app.config import Settings
        settings = Settings(
            vault_enabled=False,
            _env_file=None,
        )
        assert settings.redirect_uri == "http://localhost:8000/callback"
        assert settings.vault_secret_path == "secure-auth-portal/entra"
