# Secure Auth Portal

A Python/FastAPI web application demonstrating OIDC/OAuth2 authentication with Microsoft Entra ID, secrets management with HashiCorp Vault, and Infrastructure as Code with Terraform.

## Technologies

| Technology | Purpose | Relevance |
|---|---|---|
| Python / FastAPI | REST API backend | Core language + HTTP/REST |
| OIDC / OAuth2 | Authentication (Authorization Code Flow + PKCE) | Core auth protocols |
| Microsoft Entra ID | Identity Provider | Cloud identity platform |
| HashiCorp Vault | Secrets management | Secure storage of credentials |
| Terraform | Infrastructure as Code | Declarative infra definition |
| Git | Version control | Conventional commits |

## Architecture
```
User -> [FastAPI App] -> [Entra ID (OIDC/OAuth2)]
                |
                +------> [Vault (secrets)]
                |
         [Terraform (IaC)] -> [Entra ID App Registration]
```

## Auth Flow

1. User clicks "Log in" — app redirects to Entra ID with PKCE challenge
2. User authenticates at Microsoft — Entra ID redirects back with authorization code
3. Backend exchanges code + code_verifier for tokens (server-to-server)
4. JWT ID token is validated: RS256 signature, issuer, audience, expiration
5. User info from token claims stored in session — access granted to protected routes

## Quick Start
```bash
# Clone and set up
git clone https://github.com/dannyp19921/secure-auth-portal.git
cd secure-auth-portal
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Fill in Entra ID values (see Entra ID Setup below)

# Run
uvicorn app.main:app --reload
# Open http://localhost:8000
```

## Entra ID Setup

1. Go to [entra.microsoft.com](https://entra.microsoft.com) > App registrations > New registration
2. Name: "Secure Auth Portal", Redirect URI: Web + `http://localhost:8000/callback`
3. Note the **Application (client) ID** and **Directory (tenant) ID**
4. Go to Certificates & secrets > New client secret > copy the value
5. Add all three values to `.env`

## Vault Integration (Optional)
```bash
# Start Vault in dev mode
vault server -dev -dev-root-token-id="dev-token" &
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-token'

# Store the client secret
vault kv put secret/secure-auth-portal/entra client_secret="YOUR-SECRET"

# Enable in .env
VAULT_ENABLED=true
```

The app automatically loads `client_secret` from Vault when `VAULT_ENABLED=true`, falling back to `.env` if Vault is unavailable.

## Terraform (IaC)

The `terraform/` directory defines the Entra ID app registration as code:
```bash
cd terraform
terraform init
terraform plan -var="tenant_id=YOUR-TENANT-ID"
terraform apply -var="tenant_id=YOUR-TENANT-ID"  # requires az login
```

## Project Structure
```
secure-auth-portal/
├── app/
│   ├── main.py              # FastAPI routes (login, callback, protected)
│   ├── config.py            # Settings with Vault integration
│   └── auth/
│       ├── oidc.py          # OIDC: discovery, PKCE, token exchange, JWT validation
│       └── dependencies.py  # Auth middleware for protected routes
├── terraform/
│   ├── main.tf              # Entra ID app registration resource
│   ├── variables.tf         # Input variables
│   └── outputs.tf           # Output values
├── .env.example             # Template for environment config
├── .gitignore
├── requirements.txt
└── README.md
```
