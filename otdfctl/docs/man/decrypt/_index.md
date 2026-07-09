---
title: Decrypt a TDF file
command:
  name: decrypt [file]
  flags:
    - name: out
      shorthand: o
      description: 'The file destination for decrypted content to be written instead of stdout.'
      default: ''
    - name: tdf-type
      shorthand: t
      description: Deprecated. TDF type is now auto-detected.
    - name: no-verify-assertions
      description: disable verification of assertions
      default: false
    - name: session-key-algorithm
      description: >
        EXPERIMENTAL: The type of session key algorithm to use for decryption
      enum:
        - rsa:2048
        - ec:secp256r1
        - ec:secp384r1
        - ec:secp521r1
      default: rsa:2048
    - name: with-assertion-verification-keys
      description: >
        EXPERIMENTAL: path to JSON file of keys to verify signed assertions. See examples for more information.
    - name: kas-allowlist
      description: A custom allowlist of comma-separated KAS Urls, e.g. `https://example.com/kas,http://localhost:8080`. If none specified, the platform will use the list of KASes in the KAS registry. To ignore the allowlist, use a quoted wildcard e.g. `--kas-allowlist '*'` **WARNING:** Bypassing the allowlist may expose you to potential security risks, as untrusted KAS URLs could be used.
---

Decrypt a Trusted Data Format (TDF) file and output the contents to stdout or a file in the current working directory.

The first argument is the TDF file with path from the current working directory being decrypted.

## Examples

Various ways to decrypt a TDF file

```shell
# decrypt file and write to standard output
otdfctl decrypt hello.txt.tdf

# decrypt file and write to hello.txt file
otdfctl decrypt hello.txt.tdf -o hello.txt

# decrypt piped TDF content and write to hello.txt file
cat hello.txt.tdf | otdfctl decrypt -o hello.txt
```

Advanced piping is supported

```shell
$ echo "hello world" | otdfctl encrypt | otdfctl decrypt | cat
hello world
```

## Session Key Algorithm -- EXPERIMENTAL

The session-key-algorithm specifies the algorithm to use for the session key. The available options are (default: rsa:2048):

- rsa:2048
- ec:secp256r1
- ec:secp384r1
- ec:secp521r1

Example

```shell
# Decrypt a file using the ec:secp256r1 algorithm for the session key
# EXPERIMENTAL
otdfctl decrypt hello.txt --session-key-algorithm ec:secp256r1
```

### ZTDF Assertion Verification (experimental)

To verify the signed assertions (metadata bound to the TDF), you can provide verification keys. The supported assertion signing algorithms are HS256 and RS256 so the keys provided should either be an HS256 key or a public RS256 key.

```shell
# decrypt file and write to standard output
otdfctl decrypt hello.txt.tdf --with-assertion-verification-keys my_assertion_verification_keys.json
```

Where my_assertion_verification_keys.json looks like:

```json
{"keys":{"assertion1":{ "alg":"HS256","key":"k0cn4xBcY+49z5gs4OHUs/kbQ3/T8p+uUW9pIQ/9aqE="},"assertion2":{ "alg":"RS256","key":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCsgKCAQEAmr0wRsdXN0O9NiltxoGy\nC6ZYwHbdiPVzvOnm9ven5g7Fpm3HOmygdi021WX1OlSua+OSrXGPjM2xbY3LTrFH\nQXQEITjraXQRp5vlKDbBnOrtjYDaKazBXgTYVdelE4AIAuQaGoTudMasHBGiLPEW\niTL4ySec0NzHn2s72Q4hn5/KJpIJOGqj0SlNViufdNylkjrJ3apoYFv1Mhwi3EF/\niFZQ5encDDJmcG/UYF3msbuHRzArJJQ733BNRvicWF/nqixKxprvm8Ts8a54tr8N\nZ7cEu1u5G6AY/pZFGk4ml8q3v5o1ja7xw2dgpJlS8Tl88tUzs+7GG8Ib8n7mHqeP\nTQIDAQAB\n-----END PUBLIC KEY-----\n"}}}
```

If no verification keys are provided, the SDK will default to verifying using the payload key. If the assertions were not signed with the payload key, the decrypt call will fail.
