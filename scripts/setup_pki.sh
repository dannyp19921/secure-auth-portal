#!/bin/bash
# scripts/setup_pki.sh
# Demonstrates Vault as an internal Certificate Authority.
# This sets up a Root CA and issues certificates for internal services.
#
# Prerequisites: Vault running (vault server -dev)
# Usage: ./scripts/setup_pki.sh

set -euo pipefail

echo "=== PKI Setup: Vault as Internal CA ==="

# 1. Enable PKI secrets engine
echo "[1/5] Enabling PKI secrets engine..."
vault secrets enable pki 2>/dev/null || echo "PKI already enabled"

# 2. Set max TTL (1 year)
echo "[2/5] Configuring max certificate lifetime..."
vault secrets tune -max-lease-ttl=8760h pki

# 3. Generate Root CA
echo "[3/5] Generating Root CA certificate..."
vault write pki/root/generate/internal \
  common_name="Secure Auth Portal Internal CA" \
  ttl=8760h

# 4. Configure CA URLs (for CRL and cert distribution)
echo "[4/5] Configuring CA URLs..."
vault write pki/config/urls \
  issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" \
  crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"

# 5. Create role for issuing certs
echo "[5/5] Creating certificate role..."
vault write pki/roles/auth-portal \
  allowed_domains="auth-portal.internal" \
  allow_subdomains=true \
  max_ttl=720h

echo ""
echo "=== PKI Ready ==="
echo "Issue a certificate:"
echo '  vault write pki/issue/auth-portal common_name="api.auth-portal.internal" ttl=24h'
echo ""
echo "View CA cert:"
echo "  curl -s http://127.0.0.1:8200/v1/pki/ca/pem"
echo ""
echo "View CRL:"
echo "  curl -s http://127.0.0.1:8200/v1/pki/crl/pem"
