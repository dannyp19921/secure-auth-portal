# scripts/troubleshoot_auth.py
"""
Authentication troubleshooting tool.

Systematically diagnoses common authentication failures in OIDC/Entra ID
environments. Designed for platform engineers supporting development teams.

Usage:
    python scripts/troubleshoot_auth.py --check all
    python scripts/troubleshoot_auth.py --check token --token <JWT>
    python scripts/troubleshoot_auth.py --check connectivity
    python scripts/troubleshoot_auth.py --check config
"""

import argparse
import json
import sys
import time
import base64
from datetime import datetime, timezone

# Colors for terminal output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def header(text: str):
    print(f"\n{BOLD}{CYAN}{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}{RESET}\n")


def ok(text: str):
    print(f"  {GREEN}✓{RESET} {text}")


def warn(text: str):
    print(f"  {YELLOW}⚠{RESET} {text}")


def fail(text: str):
    print(f"  {RED}✗{RESET} {text}")


def hint(text: str):
    print(f"    {CYAN}→ {text}{RESET}")


# ──────────────────────────────────────────────
# CHECK 1: Configuration
# ──────────────────────────────────────────────
def check_config():
    """Verify environment configuration is complete and valid."""
    header("Check 1: Configuration")
    issues = 0

    # Check .env or environment variables
    import os
    required = {
        "ENTRA_TENANT_ID": os.getenv("ENTRA_TENANT_ID", ""),
        "ENTRA_CLIENT_ID": os.getenv("ENTRA_CLIENT_ID", ""),
        "ENTRA_CLIENT_SECRET": os.getenv("ENTRA_CLIENT_SECRET", ""),
    }

    for key, value in required.items():
        if not value or value.startswith("your-"):
            fail(f"{key} is not set or has placeholder value")
            hint(f"Set {key} in .env or environment variables")
            issues += 1
        else:
            # Mask the value for security
            masked = value[:8] + "..." if len(value) > 8 else "***"
            ok(f"{key} = {masked}")

    # Check redirect URI
    redirect = os.getenv("REDIRECT_URI", "http://localhost:8000/callback")
    if "localhost" in redirect:
        ok(f"REDIRECT_URI = {redirect}")
        warn("Using localhost — ensure this matches Entra ID app registration")
    else:
        ok(f"REDIRECT_URI = {redirect}")

    # Check Vault config
    vault_enabled = os.getenv("VAULT_ENABLED", "false").lower() == "true"
    if vault_enabled:
        ok("Vault integration enabled")
        vault_addr = os.getenv("VAULT_ADDR", "")
        if vault_addr:
            ok(f"VAULT_ADDR = {vault_addr}")
        else:
            fail("VAULT_ADDR not set but VAULT_ENABLED=true")
            issues += 1
    else:
        warn("Vault disabled — using .env for secrets (not recommended for production)")

    return issues


# ──────────────────────────────────────────────
# CHECK 2: Connectivity to Entra ID
# ──────────────────────────────────────────────
def check_connectivity():
    """Test connectivity to Entra ID endpoints."""
    header("Check 2: Connectivity")
    issues = 0
    import os

    tenant_id = os.getenv("ENTRA_TENANT_ID", "")
    if not tenant_id or tenant_id.startswith("your-"):
        fail("Cannot test connectivity — ENTRA_TENANT_ID not set")
        return 1

    endpoints = {
        "OIDC Discovery": f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration",
        "JWKS": None,  # Will be populated from discovery
    }

    try:
        import httpx

        # Test discovery endpoint
        print(f"  Testing OIDC discovery endpoint...")
        start = time.time()
        response = httpx.get(endpoints["OIDC Discovery"], timeout=10)
        elapsed = time.time() - start

        if response.status_code == 200:
            ok(f"OIDC Discovery reachable ({elapsed:.1f}s)")
            config = response.json()

            # Verify expected fields
            for field in ["authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"]:
                if field in config:
                    ok(f"  {field}: {config[field][:60]}...")
                else:
                    fail(f"  Missing field: {field}")
                    issues += 1

            # Test JWKS endpoint
            jwks_url = config.get("jwks_uri", "")
            if jwks_url:
                start = time.time()
                jwks_response = httpx.get(jwks_url, timeout=10)
                elapsed = time.time() - start
                if jwks_response.status_code == 200:
                    keys = jwks_response.json().get("keys", [])
                    ok(f"JWKS endpoint reachable ({elapsed:.1f}s) — {len(keys)} signing key(s)")
                    for key in keys:
                        kid = key.get("kid", "unknown")[:16]
                        kty = key.get("kty", "unknown")
                        use = key.get("use", "unknown")
                        ok(f"  Key: kid={kid}... kty={kty} use={use}")
                else:
                    fail(f"JWKS endpoint returned {jwks_response.status_code}")
                    hint("JWKS keys may have rotated or endpoint may be temporarily unavailable")
                    issues += 1
        else:
            fail(f"Discovery endpoint returned {response.status_code}")
            if response.status_code == 400:
                hint("Tenant ID may be incorrect — verify in Azure portal")
            issues += 1

    except ImportError:
        fail("httpx not installed — run: pip install httpx")
        issues += 1
    except Exception as e:
        fail(f"Connection error: {e}")
        hint("Check network connectivity and firewall rules")
        hint("Ensure login.microsoftonline.com is reachable")
        issues += 1

    return issues


# ──────────────────────────────────────────────
# CHECK 3: Token analysis
# ──────────────────────────────────────────────
def check_token(token: str):
    """Decode and analyze a JWT token without validating signature."""
    header("Check 3: Token Analysis")
    issues = 0

    if not token:
        warn("No token provided — use --token <JWT> to analyze a specific token")
        hint("Copy the id_token from browser DevTools > Network > callback response")
        return 0

    # Decode without verification (for diagnostics only)
    try:
        parts = token.split(".")
        if len(parts) != 3:
            fail(f"Invalid JWT structure — expected 3 parts, got {len(parts)}")
            hint("A JWT has format: header.payload.signature")
            return 1

        # Decode header
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        jwt_header = json.loads(base64.urlsafe_b64decode(header_b64))
        ok(f"Algorithm: {jwt_header.get('alg', 'unknown')}")
        ok(f"Key ID (kid): {jwt_header.get('kid', 'unknown')[:20]}...")

        if jwt_header.get("alg") != "RS256":
            warn(f"Unexpected algorithm: {jwt_header.get('alg')} (expected RS256)")

        # Decode payload
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))

        # Check issuer
        iss = claims.get("iss", "")
        if iss:
            ok(f"Issuer (iss): {iss}")
        else:
            fail("Missing issuer claim")
            issues += 1

        # Check audience
        aud = claims.get("aud", "")
        if aud:
            ok(f"Audience (aud): {aud}")
            import os
            expected_aud = os.getenv("ENTRA_CLIENT_ID", "")
            if expected_aud and aud != expected_aud:
                fail(f"Audience mismatch! Token aud={aud}, expected={expected_aud}")
                hint("Token was issued for a different application")
                hint("Verify ENTRA_CLIENT_ID matches the app registration")
                issues += 1
        else:
            fail("Missing audience claim")
            issues += 1

        # Check expiration
        exp = claims.get("exp")
        if exp:
            exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            if exp_dt < now:
                fail(f"Token EXPIRED at {exp_dt.isoformat()}")
                delta = now - exp_dt
                hint(f"Expired {delta.seconds // 60} minutes ago")
                hint("User needs to re-authenticate")
                issues += 1
            else:
                remaining = exp_dt - now
                ok(f"Expires: {exp_dt.isoformat()} ({remaining.seconds // 60} min remaining)")
        else:
            fail("Missing expiration claim")
            issues += 1

        # Check issued at
        iat = claims.get("iat")
        if iat:
            iat_dt = datetime.fromtimestamp(iat, tz=timezone.utc)
            ok(f"Issued at: {iat_dt.isoformat()}")

        # Check subject and name
        sub = claims.get("sub", "")
        name = claims.get("name", "")
        email = claims.get("preferred_username", "")
        if name:
            ok(f"Name: {name}")
        if email:
            ok(f"Email: {email}")
        if sub:
            ok(f"Subject: {sub[:20]}...")

        # Check for common issues
        tid = claims.get("tid", "")
        if tid:
            ok(f"Tenant ID: {tid}")

    except json.JSONDecodeError as e:
        fail(f"Failed to decode JWT payload: {e}")
        hint("Token may be corrupted or truncated")
        issues += 1
    except Exception as e:
        fail(f"Token analysis error: {e}")
        issues += 1

    return issues


# ──────────────────────────────────────────────
# CHECK 4: Vault connectivity
# ──────────────────────────────────────────────
def check_vault():
    """Test Vault connectivity and secret access."""
    header("Check 4: Vault")
    issues = 0
    import os

    vault_enabled = os.getenv("VAULT_ENABLED", "false").lower() == "true"
    if not vault_enabled:
        warn("Vault is disabled (VAULT_ENABLED=false)")
        hint("Set VAULT_ENABLED=true in .env to use Vault for secrets")
        return 0

    vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    vault_token = os.getenv("VAULT_TOKEN", "")

    if not vault_token:
        fail("VAULT_TOKEN not set")
        hint("Export VAULT_TOKEN or add to .env")
        return 1

    try:
        import hvac

        client = hvac.Client(url=vault_addr, token=vault_token)

        if client.is_authenticated():
            ok(f"Vault authenticated at {vault_addr}")
        else:
            fail("Vault authentication failed")
            hint("Token may be expired — generate a new one")
            return 1

        # Check if secret exists
        secret_path = os.getenv("VAULT_SECRET_PATH", "secure-auth-portal/entra")
        try:
            secret = client.secrets.kv.v2.read_secret_version(path=secret_path)
            keys = list(secret["data"]["data"].keys())
            ok(f"Secret at '{secret_path}' accessible — keys: {keys}")
        except Exception as e:
            fail(f"Cannot read secret at '{secret_path}': {e}")
            hint(f"Store secret: vault kv put secret/{secret_path} client_secret=YOUR_SECRET")
            issues += 1

        # Check PKI if enabled
        try:
            pki_status = client.sys.list_mounted_secrets_engines()
            if "pki/" in pki_status:
                ok("PKI secrets engine is mounted")
            else:
                warn("PKI secrets engine not mounted")
                hint("Run: ./scripts/setup_pki.sh")
        except Exception:
            warn("Could not check PKI status")

    except ImportError:
        fail("hvac not installed — run: pip install hvac")
        issues += 1
    except Exception as e:
        fail(f"Vault error: {e}")
        hint(f"Is Vault running at {vault_addr}?")
        hint("Start dev server: vault server -dev -dev-root-token-id=dev-token")
        issues += 1

    return issues


# ──────────────────────────────────────────────
# CHECK 5: Common root causes
# ──────────────────────────────────────────────
def print_common_issues():
    """Print a reference guide for common authentication failures."""
    header("Reference: Common Authentication Failures")

    problems = [
        (
            "AADSTS700016: Application not found",
            "Client ID does not match any app registration in the tenant",
            "Verify ENTRA_CLIENT_ID matches Azure portal > App registrations > Application (client) ID",
        ),
        (
            "AADSTS7000218: Invalid client secret",
            "Client secret is expired or incorrect",
            "Generate new secret in Azure portal > Certificates & secrets. Update in Vault or .env",
        ),
        (
            "AADSTS50011: Reply URL mismatch",
            "Redirect URI in request does not match app registration",
            "Ensure REDIRECT_URI exactly matches Azure portal > Authentication > Redirect URIs",
        ),
        (
            "AADSTS65001: User consent required",
            "Admin consent not granted for required permissions",
            "Azure portal > API permissions > Grant admin consent for <tenant>",
        ),
        (
            "invalid_grant: Code expired",
            "Authorization code was not exchanged within 10 minutes",
            "Ensure token exchange happens immediately after redirect. Check for network delays",
        ),
        (
            "JWT signature validation failed",
            "JWKS keys may have rotated, or token is from a different tenant",
            "Clear OIDC config cache. Verify issuer matches tenant. Check JWKS endpoint availability",
        ),
        (
            "Token expired immediately",
            "Clock skew between server and Entra ID",
            "Sync server time with NTP. Check: date -u vs actual UTC time",
        ),
        (
            "SAML assertion invalid",
            "IdP certificate has changed or assertion conditions failed",
            "Download new IdP certificate from Entra ID > SAML SSO config. Update saml/settings.json",
        ),
    ]

    for problem, cause, fix in problems:
        print(f"  {RED}{BOLD}{problem}{RESET}")
        print(f"    Root cause: {cause}")
        print(f"    {CYAN}→ Fix: {fix}{RESET}")
        print()


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Diagnose authentication issues in Secure Auth Portal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/troubleshoot_auth.py --check all
  python scripts/troubleshoot_auth.py --check token --token eyJ...
  python scripts/troubleshoot_auth.py --check connectivity
  python scripts/troubleshoot_auth.py --check vault
  python scripts/troubleshoot_auth.py --check reference
        """,
    )
    parser.add_argument(
        "--check",
        choices=["all", "config", "connectivity", "token", "vault", "reference"],
        default="all",
        help="Which check to run (default: all)",
    )
    parser.add_argument("--token", help="JWT token to analyze")

    args = parser.parse_args()

    print(f"\n{BOLD}Secure Auth Portal — Authentication Troubleshooter{RESET}")
    print(f"{'─'*50}")

    # Load .env if available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass  # dotenv not required

    total_issues = 0

    if args.check in ("all", "config"):
        total_issues += check_config()

    if args.check in ("all", "connectivity"):
        total_issues += check_connectivity()

    if args.check in ("all", "token"):
        total_issues += check_token(args.token or "")

    if args.check in ("all", "vault"):
        total_issues += check_vault()

    if args.check in ("all", "reference"):
        print_common_issues()

    # Summary
    header("Summary")
    if total_issues == 0:
        ok("All checks passed — no issues detected")
    else:
        fail(f"{total_issues} issue(s) found — review the hints above")

    return total_issues


if __name__ == "__main__":
    sys.exit(main())
