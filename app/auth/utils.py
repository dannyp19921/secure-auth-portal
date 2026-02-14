# app/auth/utils.py
"""Shared utilities for authentication modules."""

from urllib.parse import quote


def build_query_string(params: dict) -> str:
    """
    Build a URL query string from a dictionary of parameters.
    Shared by OIDC and ID-porten modules (DRY principle).
    """
    return "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
