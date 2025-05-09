# Sample Key Management System Integration with OpenBao

This folder includes an example Cryptographic Key Management System (CKMS) extension for OpenTDF.
It uses Vault or OpenBao to store KAS asymmetric key data,
provided via a `trust.KeyService` plugin.

## Starting Vault

Start up vault, configured to run in dev mode with local storage.

```sh
LOCAL_HOSTNAME=$(hostname)
vault server -dev -dev-root-token-id root -dev-tls -dev-tls-cert-dir=./
```

Install the generated CA certificate into the system keychain.

```sh
sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" ./vault-ca.pem
```

Copy the configuration details somewhere.
Copy and paste the environment variable configuration into a new shell.

```sh
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="$(pwd)/vault-ca.pem"
```

Validate vault is running, and log in

```sh
vault status
echo root | vault login -
```

Let's create some roles, policies, and tokens that apply them:

```sh
vault secrets enable -path=secret kv-v2

vault policy write kas-admin ./vault/policy-admin.hcl
vault policy write kas-service ./vault/policy-service.hcl
vault policy write kas-viewer ./vault/policy-viewer.hcl

vault token create -policy="kas-admin" -policy="kas-viewer"
# Use this token to create and delete KAS keys
# export KAS_ADMIN_TOKEN=<TOKEN>
echo ${KAS_ADMIN_TOKEN} | vault login -
vault kv put secret/kas_keypair/r1 private="$(<../../kas-private.pem | base64)" public="$(<../../kas-cert.pem)" algorithm="rsa:2048""
```

```sh
echo root | vault login -

# Create a role to from within KAS
vault auth enable approle
vault write auth/approle/role/kas policies="kas-service,kas-viewer"
vault read auth/approle/role/kas/role-id
vault write -f auth/approle/role/kas/secret-id
## Use the role_id and secret_id from the above outputs to create a token with this:
# export KAS_APPROLE_ROLEID=<ROLE_ID>
# export KAS_APPROLE_SECRETID=<SECRET_ID>
vault write auth/approle/login role_id=${KAS_APPROLE_ROLEID} secret_id=${KAS_APPROLE_SECRETID}
```

Set KAS_SERVICE_TOKEN to the token returned from the above command.

```sh
echo ${KAS_SERVICE_TOKEN} | vault login -
vault kv list -mount=secret kas_keypair
```


### Start platform services with sample CKMS plugin

Run the example

```sh
go run examples/ckms
```

#### 
#### Add key based configuration using a new KAS key in the CKMS


### Encrypt something

