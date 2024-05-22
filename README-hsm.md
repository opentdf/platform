# How to enable HSM Usage (or test with SoftHSM)

The `opentdf` services can use hardware security modules (HSMs)
to protect access to high value private key data,
notably KAS private keys used for long lived identity of the server.
The services can use PKCS #11 bindings to communicate with a system or network HSM.
To configure a development environment,
we use [softHSM](https://github.com/opendnssec/SoftHSMv2).

On macOS, these can be installed with [brew](https://docs.brew.sh/Installation)

`brew install pkcs11-tools softhsm`

## Run

1. Start with a configuration the enables HSM: `cp opentdf-with-hsm.yaml opentdf.yaml`
2. Initialize temporary keys and load them: `.github/scripts/init-temp-keys.sh --hsm`
3. Build or run using the `--tags=opentdf.hsm` flag set.

### Detailed Configuration

You must have RSA and (optionally, for nanoTDF support) elliptic curve keys
to allow clients to communicate securely with KAS.
To generate them, you can use the `openssl` tool as follows:

```sh
openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -days 365 \
    -keyout kas-private.pem -out kas-cert.pem
openssl ecparam -name prime256v1 >ecparams.tmp
openssl req -x509 -nodes -newkey ec:ecparams.tmp -subj "/CN=kas" -days 365 \
     -keyout kas-ec-private.pem -out kas-ec-cert.pem
```

To enable HSM, you must have a working `PKCS #11` library on your system.
For development, we use [the SoftHSM library](https://www.softhsm.org/),
which presents a `PKCS #11` interface to on CPU cryptography libraries.

```sh
export OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN=12345
export OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH=/lib/softhsm/libsofthsm2.so
export OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_EC_LABEL=kas-ec
export OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_RSA_LABEL=kas-rsa

pkcs11-tool --module $OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH \
            --login --pin ${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN} \
            --write-object kas-private.pem --type privkey \
            --label kas-rsa
pkcs11-tool --module $OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH \
            --login --pin ${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN} \
            --write-object kas-cert.pem --type cert \
            --label kas-rsa

pkcs11-tool --module $OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH \
            --login --pin ${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN} \
            --write-object ec-private.pem --type privkey \
            --label kas-ec
pkcs11-tool --module $OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH \
            --login --pin ${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN} \
            --write-object ec-cert.pem --type cert \
            --label kas-ec
```
