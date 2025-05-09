# Sample CKMS Integration with OpenBao

This folder includes an example CKMS extension for OpenTDF.
It uses OpenBao to store KAS asymmetric key data,
provided via a `trust.KeyService` plugin.

## Starting Vault

Start up vault, configured to run in dev mode with local storage.

```sh
LOCAL_HOSTNAME=$(hostname)
mkcert -cert-file ./vault-tls.crt -key-file ./vault-tls.key "${LOCAL_HOSTNAME}"
sudo tee ./vault.hcl << EOF
listener "tcp" {
  address     = "${LOCAL_HOSTNAME}:8200"
  tls_cert_file = "${PWD}/vault-tls.crt"
  tls_key_file  = "${PWD}/vault-tls.key"
  tls_client_ca_file = "$(mkcert -CAROOT)/rootCA.pem"
}
api_addr = "https://${LOCAL_HOSTNAME}$:8200"
EOF
vault server -dev -dev-root-token-id root -config=./vault.hcl
```


Copy the configuration details somewhere.
Copy and paste the environment variable configuration into a new shell.

```sh
export VAULT_ADDR='https://127.0.0.1:8200'
export VAULT_CACERT='/var/folders/fb/.../T/vault-.../vault-ca.pem'
```

Validate vault is running, and log in

```sh
vault status
echo root | vault login -
```

Let's create some roles, policies, and tokens that apply them:

```sh
vault secrets enable -path=secrets kv-v2

vault policy write kas-admin ./examples/ckms/vault/policy-admin.hcl
vault policy write kas-service ./examples/ckms/vault/policy-service.hcl
vault policy write kas-viewer ./examples/ckms/vault/policy-viewer.hcl

vault token create -policy="kas-admin" -policy="kas-viewer"
# Use this token to create and delete KAS keys
vault login [token from above]
vault kv put secrets/rsa_keys/r1 private="$(cat kas-private.pem | base64)" public="$(cat kas-cert.pem)"


# Use this role to from within KAS
vault auth enable approle
vault write auth/approle/role/kas policies="kas-service,kas-viewer"
vault read auth/approle/role/kas/role-id
vault write -f auth/approle/role/kas/secret-id
## Use the role_id and secret_id from the above outputs to create a token with this:
vault write auth/approle/login role_id=<ROLE_ID> secret_id=<SECRET_ID>

```

vault write auth/approle/login role_id=aa034a00-04c3-edd4-a9e2-e5f28ae420b5 secret_id=e2ea9f69-5e08-b381-d186-9a24e07e2e56

sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /path/to/your/certificate.crt



### Start platform services with sample CKMS plugin

Run the example

```sh
go run examples/ckms
```

#### 
#### Add key based configuration using a new KAS key in the CKMS


### Encrypt something

