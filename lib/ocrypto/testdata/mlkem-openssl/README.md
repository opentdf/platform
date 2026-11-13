These are unencrypted, test-only ML-KEM key pairs generated with OpenSSL 4.1.0
(23 Oct 2026). The private keys use OpenSSL's default `both` encoding. They
must not be used in production.

```sh
openssl genpkey -algorithm ML-KEM-768 -out 768-private.pem
openssl pkey -in 768-private.pem -pubout -out 768-public.pem
openssl genpkey -algorithm ML-KEM-1024 -out 1024-private.pem
openssl pkey -in 1024-private.pem -pubout -out 1024-public.pem
```
