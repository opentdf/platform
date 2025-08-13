# policy-service.hcl

path "secret/data/kas_keypair/*" {
  capabilities = ["list", "read"]
}

path "secret/metadata/kas_keypair/*" {
  capabilities = ["list"]
}

path "secret/data/kas_keypair/+/private" {
  capabilities = ["read"]
}
