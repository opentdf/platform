# policy-viewer.hcl

path "secret/data/kas_keypair/*/public" {
  capabilities = ["read"]
}

path "secret/metadata/kas_keypair" {
  capabilities = ["list"]
}
