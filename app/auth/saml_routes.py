# app/auth/saml_routes.py
"""
SAML 2.0 Service Provider (SP) integration.

SAML vs OIDC:
- SAML uses XML-based assertions, OIDC uses JSON/JWT tokens
- SAML is common in enterprise/on-prem (Active Directory Federation Services)
- OIDC is common in modern cloud apps
- Both achieve SSO, but via different mechanisms

In PIT's context: SAML for legacy on-prem systems, OIDC for new cloud apps.

NOTE: This SP implementation demonstrates the SAML architecture and flow.
Full IdP integration requires:
1. Configuring the app as Enterprise Application in Entra ID with SAML SSO
2. Downloading the IdP certificate and updating saml/settings.json
3. Setting the correct tenant ID in the IdP URLs
"""

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, HTMLResponse

router = APIRouter(prefix="/saml", tags=["SAML"])


@router.get("/login")
async def saml_login(request: Request):
    """
    Initiate SAML authentication (SP-Initiated SSO).

    SAML Flow:
    1. SP generates AuthnRequest XML
    2. User redirected to IdP (e.g., ADFS or Entra ID) with the request
    3. User authenticates at IdP
    4. IdP sends signed SAML Response (XML assertion) to SP's ACS endpoint
    5. SP validates XML signature and extracts user attributes

    Key differences from OIDC:
    - XML instead of JSON
    - Signed XML assertions instead of JWTs
    - POST binding (form auto-submit) instead of query parameters
    - No access_token/refresh_token concept
    """
    return HTMLResponse("""
    <html>
        <head><title>SAML Login — Secure Auth Portal</title></head>
        <body style="font-family: sans-serif; display: flex; align-items: center;
                     justify-content: center; min-height: 100vh; background: #f0f2f5;">
            <div style="background: white; padding: 3rem; border-radius: 12px;
                        box-shadow: 0 4px 24px rgba(0,0,0,0.1); max-width: 600px;">
                <h2 style="color: #4a6741;">SAML 2.0 Service Provider</h2>
                <p>This endpoint demonstrates SAML SP-initiated SSO.</p>
                
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px;
                            border-left: 4px solid #4a6741; margin: 1rem 0;">
                    <strong>SAML Flow (SP-Initiated):</strong>
                    <ol style="margin: 0.5rem 0; padding-left: 1.5rem;">
                        <li>SP generates AuthnRequest XML</li>
                        <li>User redirected to IdP with signed request</li>
                        <li>User authenticates at IdP (e.g., ADFS, Entra ID)</li>
                        <li>IdP POSTs signed SAML assertion to /saml/acs</li>
                        <li>SP validates XML signature, checks conditions, extracts attributes</li>
                    </ol>
                </div>
                
                <div style="background: #fff3cd; padding: 1rem; border-radius: 8px; margin: 1rem 0;">
                    <strong>IdP configuration required:</strong> To complete this flow, 
                    the app must be registered as an Enterprise Application with SAML SSO 
                    in Entra ID, and the IdP certificate must be added to saml/settings.json.
                </div>

                <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 1rem 0;">
                    <strong>SAML vs OIDC:</strong>
                    <table style="width: 100%; margin-top: 0.5rem; font-size: 0.9rem;">
                        <tr><td></td><td><strong>SAML</strong></td><td><strong>OIDC</strong></td></tr>
                        <tr><td>Format</td><td>XML</td><td>JSON / JWT</td></tr>
                        <tr><td>Typical use</td><td>Enterprise / on-prem</td><td>Modern cloud apps</td></tr>
                        <tr><td>Token type</td><td>XML Assertion</td><td>JWT (ID + Access)</td></tr>
                        <tr><td>Binding</td><td>POST / Redirect</td><td>Query params</td></tr>
                    </table>
                </div>

                <p><a href="/saml/metadata" style="color: #4a6741;">View SP Metadata (XML)</a></p>
                <p><a href="/" style="color: #666;">Back to home</a> |
                   <a href="/login" style="color: #1b3a5c;">Log in with OIDC instead</a></p>
            </div>
        </body>
    </html>
    """)


@router.post("/acs")
async def saml_acs(request: Request):
    """
    Assertion Consumer Service — receives SAML Response from IdP.

    The IdP posts a signed XML assertion containing:
    - NameID (user identifier)
    - Attributes (name, email, groups)
    - Conditions (NotBefore, NotOnOrAfter, audience restriction)

    Validation steps:
    1. Verify XML signature against IdP's public certificate
    2. Check assertion is not expired
    3. Verify audience restriction matches our SP entity ID
    4. Extract user attributes
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        saml_auth = OneLogin_Saml2_Auth(
            await _prepare_saml_request_post(request),
            custom_base_path="app/auth/saml"
        )
        saml_auth.process_response()
        errors = saml_auth.get_errors()

        if errors:
            return HTMLResponse(f"SAML Error: {', '.join(errors)}", status_code=400)

        attributes = saml_auth.get_attributes()
        name_id = saml_auth.get_nameid()

        request.session["user"] = {
            "name": attributes.get("displayName", [name_id])[0],
            "email": name_id,
            "sub": name_id,
            "auth_method": "SAML",
        }

        return RedirectResponse(url="/protected", status_code=303)

    except Exception as e:
        return HTMLResponse(f"SAML ACS Error: {str(e)}", status_code=500)


@router.get("/metadata")
async def saml_metadata(request: Request):
    """
    SP Metadata endpoint — returns XML describing this Service Provider.

    An IdP admin imports this metadata to configure the trust relationship.
    Contains: entity ID, ACS URL, certificate, NameID format.
    """
    return HTMLResponse(
        content="""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="http://localhost:8000/saml/metadata">
    <md:SPSSODescriptor AuthnRequestsSigned="false"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="http://localhost:8000/saml/acs"
            index="1"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>""",
        media_type="application/xml",
    )


async def _prepare_saml_request_post(request: Request) -> dict:
    """Convert FastAPI POST request for SAML ACS."""
    form_data = await request.form()
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.url.hostname,
        "script_name": request.url.path,
        "server_port": request.url.port,
        "get_data": dict(request.query_params),
        "post_data": dict(form_data),
    }
