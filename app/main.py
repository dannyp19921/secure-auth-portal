# app/main.py
"""
Secure Auth Portal — FastAPI app with OIDC/OAuth2 authentication via Entra ID.
"""

from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware

from app.auth.oidc import build_auth_url, exchange_code_for_tokens
from app.auth.dependencies import get_current_user
from app.auth.saml_routes import router as saml_router
from app.config import settings

app = FastAPI(title="Secure Auth Portal", version="0.2.0")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)
app.include_router(saml_router)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Public landing page."""
    user = request.session.get("user")

    if user:
        user_html = f"""
            <div style="background: #e8f4e8; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
                <p>Logged in as <strong>{user['name']}</strong></p>
            </div>
            <a href="/protected" style="display: inline-block; padding: 0.8rem 2rem;
               background: #1b3a5c; color: white; text-decoration: none; border-radius: 8px;">
               Go to Dashboard</a>
            <br><br>
            <a href="/logout" style="color: #666;">Log out</a>
        """
    else:
        user_html = """
            <p style="color: #666; margin-bottom: 2rem;">
                OIDC/OAuth2 authentication demo using Entra ID.<br>
                Authorization Code Flow with PKCE.
            </p>
            <a href="/login" style="display: inline-block; padding: 0.8rem 2rem;
               background: #1b3a5c; color: white; text-decoration: none; border-radius: 8px;">
               Log in with Entra ID (OIDC)</a>
            <br><br>
            <a href="/saml/login" style="display: inline-block; padding: 0.8rem 2rem;
               background: #4a6741; color: white; text-decoration: none; border-radius: 8px;">
               Log in with SAML</a>
        """

    return f"""
    <html>
        <head><title>Secure Auth Portal</title></head>
        <body style="font-family: sans-serif; display: flex; align-items: center;
                     justify-content: center; min-height: 100vh; background: #f0f2f5;">
            <div style="background: white; padding: 3rem; border-radius: 12px;
                        box-shadow: 0 4px 24px rgba(0,0,0,0.1); text-align: center; max-width: 480px;">
                <h1 style="color: #1b3a5c;">Secure Auth Portal</h1>
                {user_html}
                <p style="color: #999; font-size: 0.8rem; margin-top: 2rem;">
                    FastAPI · OIDC · SAML · Entra ID · ID-porten · Vault · Terraform</p>
            </div>
        </body>
    </html>
    """


@app.get("/login")
async def login(request: Request):
    """Redirect user to Entra ID for authentication."""
    auth_url, state, code_verifier = await build_auth_url()

    request.session["oauth_state"] = state
    request.session["code_verifier"] = code_verifier

    return RedirectResponse(url=auth_url)


@app.get("/callback")
async def callback(request: Request, code: str, state: str):
    """Receive auth code from Entra ID and exchange for tokens."""
    stored_state = request.session.get("oauth_state")
    if state != stored_state:
        return HTMLResponse("Invalid state — possible CSRF attack.", status_code=400)

    code_verifier = request.session.get("code_verifier")
    claims = await exchange_code_for_tokens(code, code_verifier)

    request.session["user"] = {
        "name": claims.get("name", "Unknown"),
        "email": claims.get("preferred_username", ""),
        "sub": claims.get("sub", ""),
    }

    request.session.pop("oauth_state", None)
    request.session.pop("code_verifier", None)

    return RedirectResponse(url="/protected")


@app.get("/protected", response_class=HTMLResponse)
async def protected(request: Request, user: dict = Depends(get_current_user)):
    """Protected route — requires authentication."""
    return f"""
    <html>
        <head><title>Dashboard — Secure Auth Portal</title></head>
        <body style="font-family: sans-serif; background: #f0f2f5; padding: 2rem;">
            <div style="background: white; padding: 2rem; border-radius: 12px;
                        box-shadow: 0 4px 24px rgba(0,0,0,0.1); max-width: 640px; margin: 0 auto;">
                <h1 style="color: #1b3a5c;">Protected Dashboard</h1>
                <p style="color: #666; margin-bottom: 1.5rem;">
                    Your identity was verified via OIDC.</p>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;
                            border-left: 4px solid #1b3a5c; margin-bottom: 1rem;">
                    <div style="font-size: 0.8rem; color: #666;">Name</div>
                    <div>{user['name']}</div>
                </div>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;
                            border-left: 4px solid #1b3a5c; margin-bottom: 1rem;">
                    <div style="font-size: 0.8rem; color: #666;">Email</div>
                    <div>{user['email']}</div>
                </div>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;
                            border-left: 4px solid #1b3a5c; margin-bottom: 1rem;">
                    <div style="font-size: 0.8rem; color: #666;">Subject ID (sub claim)</div>
                    <div style="font-family: monospace; font-size: 0.9rem;">{user['sub']}</div>
                </div>
                <a href="/logout" style="color: #666;">Log out</a>
                <p style="font-size: 0.85rem; color: #888; margin-top: 1.5rem; padding-top: 1rem;
                          border-top: 1px solid #eee;">
                    Token validation: RS256 signature, issuer, audience, expiration.</p>
            </div>
        </body>
    </html>
    """


@app.get("/logout")
async def logout(request: Request):
    """Clear session and redirect to home."""
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/idporten", response_class=HTMLResponse)
async def idporten_info(request: Request):
    """ID-porten information and demo endpoint."""
    from app.auth.idporten import IDPORTEN_CONFIG, build_idporten_auth_url
    from app.auth.oidc import generate_pkce_pair
    import secrets
    state = secrets.token_urlsafe(32)
    verifier, challenge = generate_pkce_pair()
    demo_url = build_idporten_auth_url("demo-client-id", "http://localhost:8000/callback", state, challenge)
    return f"""
    <html>
        <head><title>ID-porten - Secure Auth Portal</title></head>
        <body style="font-family: sans-serif; display: flex; align-items: center;
                     justify-content: center; min-height: 100vh; background: #f0f2f5;">
            <div style="background: white; padding: 3rem; border-radius: 12px;
                        box-shadow: 0 4px 24px rgba(0,0,0,0.1); max-width: 600px;">
                <h2 style="color: #c0392b;">ID-porten (Norwegian Public Auth)</h2>
                <p>ID-porten uses the same OIDC flow as Entra ID.</p>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;
                            border-left: 4px solid #c0392b; margin: 1rem 0;">
                    <strong>How it works:</strong>
                    <ol style="margin: 0.5rem 0; padding-left: 1.5rem;">
                        <li>Same Authorization Code Flow with PKCE</li>
                        <li>User chooses BankID, MinID, etc.</li>
                        <li>Security levels: substantial (MinID) or high (BankID)</li>
                        <li>Token exchange and JWT validation identical to Entra ID</li>
                    </ol>
                </div>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 1rem 0;">
                    <strong>Discovery:</strong><br>
                    <code style="font-size: 0.85rem;">{IDPORTEN_CONFIG["discovery_url"]}</code>
                </div>
                <div style="background: #fff3cd; padding: 1rem; border-radius: 8px; margin: 1rem 0;">
                    <strong>Registration required:</strong> To use ID-porten, register at
                    Samarbeidsportalen (Digitaliseringsdirektoratet).
                </div>
                <p><a href="/" style="color: #666;">Back to home</a> |
                   <a href="/login" style="color: #1b3a5c;">Log in with OIDC</a></p>
            </div>
        </body>
    </html>
    """

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "version": "0.2.0"}
