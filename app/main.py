# app/main.py
"""
Secure Auth Portal — FastAPI app with OIDC/OAuth2 authentication via Entra ID.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Secure Auth Portal", version="0.1.0")


@app.get("/", response_class=HTMLResponse)
async def home():
    """Public landing page."""
    return """
    <html>
        <head><title>Secure Auth Portal</title></head>
        <body style="font-family: sans-serif; display: flex; align-items: center;
                     justify-content: center; min-height: 100vh; background: #f0f2f5;">
            <div style="background: white; padding: 3rem; border-radius: 12px;
                        box-shadow: 0 4px 24px rgba(0,0,0,0.1); text-align: center;">
                <h1 style="color: #1b3a5c;">Secure Auth Portal</h1>
                <p style="color: #666;">OIDC/OAuth2 authentication demo</p>
                <p style="color: #999; font-size: 0.85rem;">Step 1: App is running!</p>
            </div>
        </body>
    </html>
    """


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}
