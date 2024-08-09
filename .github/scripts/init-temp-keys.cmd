@echo OFF

REM Initialize temporary keys for use with a KAS. No HSM for now.

mkdir keys

openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout keys/kas-private.pem -out keys/kas-cert.pem -days 365
openssl ecparam -name prime256v1 >ecparams.tmp
openssl req -x509 -nodes -newkey ec:ecparams.tmp -subj "/CN=kas" -keyout keys/kas-ec-private.pem -out keys/kas-ec-cert.pem -days 365

openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=ca" -keyout keys/keycloak-ca-private.pem -out keys/keycloak-ca.pem -days 365
printf "subjectAltName=DNS:localhost,IP:127.0.0.1" > keys/sanX509.conf
printf "[req]\ndistinguished_name=req_distinguished_name\n[req_distinguished_name]\n[alt_names]\nDNS.1=localhost\nIP.1=127.0.0.1" > keys/req.conf
openssl req -new -nodes -newkey rsa:2048 -keyout keys/localhost.key -out keys/localhost.req -batch -subj "/CN=localhost" -config keys/req.conf
openssl x509 -req -in keys/localhost.req -CA keys/keycloak-ca.pem  -CAkey keys/keycloak-ca-private.pem -CAcreateserial -out keys/localhost.crt -days 3650 -sha256 -extfile keys/sanX509.conf
openssl req -new -nodes -newkey rsa:2048 -keyout keys/sampleuser.key -out keys/sampleuser.req -batch -subj "/CN=sampleuser"
openssl x509 -req -in keys/sampleuser.req -CA keys/keycloak-ca.pem  -CAkey keys/keycloak-ca-private.pem -CAcreateserial -out keys/sampleuser.crt -days 3650

set "hostKeyDir=%cd%"
set hostKeyDir=%hostKeyDir%/keys
set "hostKeyDir=%hostKeyDir:\=/%"

openssl pkcs12 -export -in keys/keycloak-ca.pem -inkey keys/keycloak-ca-private.pem -out keys/ca.p12 -keypbe NONE -certpbe NONE -passout pass:
