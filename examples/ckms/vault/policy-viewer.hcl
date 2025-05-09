# policy-viewer.hcl

path "secrets/data/rsa_keys/*/public" {
  capabilities = ["read"]
}

path "secrets/metadata/rsa_keys" {
  capabilities = ["list"]
}
