# policy-admin.hcl

# kv v2 has paths of the form /[path]/{data,metadata,[other action]/[name]

path "secret/data/kas_keypair/*" {
  # We don't want to enable `patch`,
  # since kas does explicit rotation
  # and never reuses key identifiers.
  capabilities = ["create", "update", "delete", "list", "read"]
}

path "secret/metadata/kas_keypair/*" {
  capabilities = ["list"]
}
