# app/auth/oidc.py
"""
OIDC/OAuth2 integration with Entra ID.
Handles: discovery, authorization URL building, token exchange, JWT validation.
"""

import hashlib
import logging
import base64
import secrets

import httpx
import jwt
from jwt import PyJWKClient

from app.config import settings
from app.auth.utils import build_query_string

logger = logging.getLogger(__name__)

# Cache for OIDC discovery document
# NOTE: In production, add TTL-based cache invalidation (e.g., 24h)
# to pick up provider configuration changes and key rotations.
_oidc_config_cache = None


async def get_oidc_config() -> dict:
    """
    Fetch OIDC discovery document from Entra ID.
    This document contains all endpoints we need (authorize, token, jwks, etc.)
    """
    global _oidc_config_cache
    if _oidc_config_cache:
        return _oidc_config_cache

    discovery_url = (
        f"https://login.microsoftonline.com/{settings.entra_tenant_id}"
        f"/v2.0/.well-known/openid-configuration"
    )
    async with httpx.AsyncClient() as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        logger.info("Fetched OIDC discovery document")
        _oidc_config_cache = response.json()
        return _oidc_config_cache


def generate_pkce_pair() -> tuple[str, str]:
    """
    Generate PKCE code_verifier and code_challenge.

    PKCE prevents authorization code interception:
    1. Client generates random code_verifier
    2. Client sends SHA256 hash (code_challenge) with auth request
    3. Client sends original code_verifier with token request
    4. Server verifies hash matches
    """
    code_verifier = secrets.token_urlsafe(32)

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    return code_verifier, code_challenge


async def build_auth_url() -> tuple[str, str, str]:
    """
    Build the authorization URL for Entra ID.
    Returns: (auth_url, state, code_verifier)
    """
    config = await get_oidc_config()
    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()

    params = {
        "client_id": settings.entra_client_id,
        "response_type": "code",
        "redirect_uri": settings.redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "response_mode": "query",
    }

    auth_endpoint = config["authorization_endpoint"]
    query_string = build_query_string(params)

    return f"{auth_endpoint}?{query_string}", state, code_verifier


async def exchange_code_for_tokens(code: str, code_verifier: str) -> dict:
    """
    Exchange authorization code for tokens (backend-to-backend).
    Returns decoded ID token claims.
    """
    config = await get_oidc_config()

    token_data = {
        "client_id": settings.entra_client_id,
        "client_secret": settings.entra_client_secret,
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": settings.redirect_uri,
        "grant_type": "authorization_code",
        "scope": "openid profile email",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(config["token_endpoint"], data=token_data)
        response.raise_for_status()
        logger.info("Token exchange successful")
        tokens = response.json()

    # Validate and decode the ID token
    id_token = tokens["id_token"]
    claims = validate_id_token(id_token, config)

    return claims


def validate_id_token(id_token: str, oidc_config: dict) -> dict:
    """
    Validate JWT ID token:
    1. Fetch signing keys from JWKS endpoint
    2. Verify signature (RS256)
    3. Verify claims: issuer, audience, expiration
    """
    jwks_client = PyJWKClient(oidc_config["jwks_uri"])
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=settings.entra_client_id,
        issuer=oidc_config["issuer"],
        options={
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": True,
        },
    )

    logger.info("ID token validated successfully")
    return claims
