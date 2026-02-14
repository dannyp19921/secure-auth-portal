# terraform/outputs.tf

output "client_id" {
  description = "Application (client) ID"
  value       = azuread_application.auth_portal.client_id
}

output "client_secret" {
  description = "Client secret - store in Vault, not in code!"
  value       = azuread_application_password.auth_portal.value
  sensitive   = true
}

output "tenant_id" {
  description = "Tenant ID"
  value       = var.tenant_id
}
