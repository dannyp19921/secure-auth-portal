# app/auth/idporten.py
"""
ID-porten integration (Norwegian public sector authentication).

ID-porten is operated by Digitaliseringsdirektoratet and provides
authentication for Norwegian citizens via BankID, MinID, etc.

Key facts:
- Uses standard OIDC (Authorization Code Flow with PKCE)
- Same flow as Entra ID, different provider
- Security levels: "substantial" (MinID) and "high" (BankID)
- Discovery endpoint: https://login.idporten.no/.well-known/openid-configuration

"""

from app.auth.utils import build_query_string

# ID-porten OIDC configuration
IDPORTEN_CONFIG = {
    "discovery_url": "https://login.idporten.no/.well-known/openid-configuration",
    "authorization_endpoint": "https://login.idporten.no/authorize",
    "token_endpoint": "https://login.idporten.no/token",
    "jwks_uri": "https://login.idporten.no/jwk",
    "issuer": "https://login.idporten.no",

    # Scopes
    "default_scopes": "openid profile",

    # Security levels (acr_values)
    # Level3 = "substantial" (MinID)
    # Level4 = "high" (BankID, Buypass, Commfides)
    "acr_values": {
        "substantial": "idporten-loa-substantial",  # MinID
        "high": "idporten-loa-high",                # BankID
    },

    # UI locales
    "ui_locales": "nb",  # Norwegian Bokmal
}


def build_idporten_auth_url(
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    security_level: str = "high",
) -> str:
    """
    Build ID-porten authorization URL.

    Same OIDC flow as Entra ID, with these differences:
    - acr_values parameter to request security level
    - ui_locales for Norwegian UI
    - Different scopes available (e.g., pid for national ID number)

    Args:
        client_id: Registered client ID from Samarbeidsportalen
        redirect_uri: Must match registered redirect URI
        state: CSRF protection (same as Entra ID)
        code_challenge: PKCE challenge (same as Entra ID)
        security_level: "substantial" (MinID) or "high" (BankID)
    """
    acr = IDPORTEN_CONFIG["acr_values"].get(security_level, "idporten-loa-high")

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": IDPORTEN_CONFIG["default_scopes"],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "acr_values": acr,
        "ui_locales": IDPORTEN_CONFIG["ui_locales"],
        "response_mode": "query",
    }

    query = build_query_string(params)
    return f"{IDPORTEN_CONFIG['authorization_endpoint']}?{query}"
