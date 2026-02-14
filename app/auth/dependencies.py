# app/auth/dependencies.py
"""FastAPI dependencies for authentication."""

from fastapi import Request, HTTPException


async def get_current_user(request: Request) -> dict:
    """
    Extract current user from session.
    Raises 401 if not authenticated.
    """
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated. Please log in.",
        )
    return user
