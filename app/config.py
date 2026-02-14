# app/config.py
"""
Application configuration.
Loads settings from .env file using pydantic-settings.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """App settings loaded from environment variables / .env file."""

    # Entra ID
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""

    # App
    redirect_uri: str = "http://localhost:8000/callback"
    session_secret: str = "change-me-in-production"

    class Config:
        env_file = ".env"


settings = Settings()
