# app/config.py
"""
Application configuration.
Supports loading secrets from either .env or HashiCorp Vault.
"""

import os
import logging

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


def get_secret_from_vault(secret_path: str, key: str) -> str | None:
    """
    Fetch a secret from HashiCorp Vault (KV v2 secrets engine).
    Returns None if Vault is unavailable — app falls back to .env.
    """
    try:
        import hvac

        vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        vault_token = os.getenv("VAULT_TOKEN")

        if not vault_token:
            logger.info("No VAULT_TOKEN set, skipping Vault")
            return None

        client = hvac.Client(url=vault_addr, token=vault_token)

        if not client.is_authenticated():
            logger.warning("Vault authentication failed")
            return None

        secret = client.secrets.kv.v2.read_secret_version(path=secret_path)
        value = secret["data"]["data"].get(key)
        logger.info(f"Loaded '{key}' from Vault path '{secret_path}'")
        return value

    except Exception as e:
        logger.warning(f"Vault error: {e}")
        return None


class Settings(BaseSettings):
    """App settings. Priority: Vault > environment variables > .env file."""

    # Entra ID
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""

    # App
    redirect_uri: str = "http://localhost:8000/callback"
    session_secret: str = "change-me-in-production"

    # Vault
    vault_enabled: bool = False
    vault_addr: str = "http://127.0.0.1:8200"
    vault_token: str = ""
    vault_secret_path: str = "secure-auth-portal/entra"

    class Config:
        env_file = ".env"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        if self.vault_enabled:
            vault_secret = get_secret_from_vault(
                self.vault_secret_path, "client_secret"
            )
            if vault_secret:
                self.entra_client_secret = vault_secret
                logger.info("Using client_secret from Vault")


settings = Settings()
