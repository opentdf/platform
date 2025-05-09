# policy-service.hcl

path "secrets/data/rsa_keys/*" {
  capabilities = ["read"]
}

path "secrets/data/rsa_keys/+/private" {
  capabilities = ["read"]
}
