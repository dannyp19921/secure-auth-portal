# Troubleshooting Guide

Systematic guide for diagnosing authentication failures in the Secure Auth Portal and related OIDC/SAML environments.

## Quick Diagnosis

Run the built-in troubleshooting tool:
```bash
# Run all checks
python scripts/troubleshoot_auth.py --check all

# Analyze a specific JWT token
python scripts/troubleshoot_auth.py --check token --token eyJhbGciOi...

# Test Entra ID connectivity
python scripts/troubleshoot_auth.py --check connectivity

# Check Vault status
python scripts/troubleshoot_auth.py --check vault

# View common error reference
python scripts/troubleshoot_auth.py --check reference
```

## Root Cause Analysis Methodology

When a user reports "login doesn't work", follow this systematic approach:

### Step 1: Reproduce and classify
- **Where does it fail?** Before redirect? During redirect? On callback?
- **Error code?** Check browser URL and app response for AADSTS codes
- **Who is affected?** One user, one app, or everyone?

### Step 2: Check the basics
```bash
python scripts/troubleshoot_auth.py --check config
python scripts/troubleshoot_auth.py --check connectivity
```

### Step 3: Analyze the token (if you have one)
```bash
python scripts/troubleshoot_auth.py --check token --token <paste-jwt-here>
```

### Step 4: Check the logs
```bash
# Application logs
uvicorn app.main:app --reload --log-level debug

# Look for these key log lines:
# "Fetched OIDC discovery document" — connectivity OK
# "Token exchange successful" — code exchange OK
# "ID token validated successfully" — JWT validation OK
# "Vault error: ..." — secrets issue
```

## Common Failures and Root Causes

### OIDC / Entra ID

| Symptom | Root Cause | Fix |
|---|---|---|
| AADSTS700016 | Client ID not found in tenant | Verify `ENTRA_CLIENT_ID` matches App Registration |
| AADSTS7000218 | Expired or wrong client secret | Rotate secret in Azure portal, update Vault/.env |
| AADSTS50011 | Redirect URI mismatch | `REDIRECT_URI` must exactly match Azure config |
| AADSTS65001 | Missing consent | Grant admin consent in API permissions |
| AADSTS900023 | Invalid tenant ID | Verify `ENTRA_TENANT_ID` in Azure portal |
| "Invalid state" | Session expired or CSRF | Clear cookies, try again. Check session middleware |
| JWT signature fails | JWKS key rotation | Clear discovery cache. Keys rotate ~every 6 weeks |
| Token expired instantly | Server clock skew | Sync with NTP: `sudo ntpdate pool.ntp.org` |

### SAML

| Symptom | Root Cause | Fix |
|---|---|---|
| Signature validation failed | IdP certificate changed | Download new cert from Entra ID SAML config |
| Audience restriction failed | Entity ID mismatch | `entityId` in settings.json must match IdP config |
| Assertion expired | Clock skew or slow network | Check NotBefore/NotOnOrAfter conditions |

### Vault

| Symptom | Root Cause | Fix |
|---|---|---|
| "Vault error: Connection refused" | Vault not running | `vault server -dev -dev-root-token-id=dev-token` |
| "Vault authentication failed" | Token expired | Generate new token or restart dev server |
| Secret not found | Wrong path | `vault kv put secret/secure-auth-portal/entra client_secret=...` |

### Certificate / PKI

| Symptom | Root Cause | Fix |
|---|---|---|
| TLS handshake failed | Certificate expired | Check TTL: `vault read pki/cert/serial` |
| Certificate not trusted | CA not in trust store | Import CA cert: `curl http://127.0.0.1:8200/v1/pki/ca/pem` |
| CRL check failed | CRL endpoint unreachable | Verify CRL URL in cert and network access |

## Key Rotation Checklist

When keys or certificates need rotation:

1. **Entra ID client secret**: Azure portal > Certificates & secrets > New secret > Update in Vault
2. **JWKS signing keys**: Automatic (Entra ID rotates ~every 6 weeks). Clear discovery cache if issues arise
3. **SAML IdP certificate**: Download from Entra ID > Enterprise App > SAML > Certificate > Update `saml/settings.json`
4. **Vault PKI certificates**: `vault write pki/issue/auth-portal common_name="..." ttl=24h` (short TTL = automatic rotation)
5. **Vault token**: `vault token create -policy=auth-portal -ttl=720h`

## Supporting Development Teams

When a dev team reports an authentication issue in their application:

1. **Ask for the error** — exact error message, AADSTS code, or HTTP status
2. **Ask for the flow** — which protocol (OIDC/SAML), which IdP, which environment
3. **Run diagnostics** — `python scripts/troubleshoot_auth.py --check all`
4. **Check if it's a config issue** — 80% of auth failures are misconfiguration
5. **Check if it's an infrastructure issue** — certificate expiry, Vault down, network rules
6. **Document the fix** — add to this guide for future reference
