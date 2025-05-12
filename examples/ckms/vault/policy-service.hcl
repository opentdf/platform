# policy-service.hcl

path "secrets/data/rsa_keys/*" {
  capabilities = ["list", "read"]
}

path "secrets/metadata/rsa_keys/*" {
  capabilities = ["list"]
}

path "secrets/data/rsa_keys/+/private" {
  capabilities = ["read"]
}
