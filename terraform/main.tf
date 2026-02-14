# terraform/main.tf
# Infrastructure as Code for Entra ID app registration.
# This defines the same app registration you created manually in Azure portal.

terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
  }
}

provider "azuread" {
  tenant_id = var.tenant_id
}

resource "azuread_application" "auth_portal" {
  display_name     = "Secure Auth Portal"
  sign_in_audience = "AzureADMyOrg"

  web {
    redirect_uris = [
      "http://localhost:8000/callback",
    ]

    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000"

    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
      type = "Scope"
    }

    resource_access {
      id   = "14dad69e-099b-42c9-810b-d002981feec1"
      type = "Scope"
    }

    resource_access {
      id   = "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0"
      type = "Scope"
    }
  }

  tags = ["secure-auth-portal", "oidc", "demo"]
}

resource "azuread_service_principal" "auth_portal" {
  client_id = azuread_application.auth_portal.client_id
}

resource "azuread_application_password" "auth_portal" {
  application_id = azuread_application.auth_portal.id
  display_name   = "terraform-managed-secret"
  end_date       = "2026-12-31T00:00:00Z"
}
