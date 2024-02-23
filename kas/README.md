# platform/kas

Key Access Service Go implementation supporting [Trusted Data Format Protocol](https://github.com/opentdf/spec) 

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 
- [kubectl](https://kubernetes.io/docs/tasks/tools/) 
- [minikube](https://minikube.sigs.k8s.io/docs/start/) 
- [Helm](https://helm.sh/docs/intro/install/) 
- [Tilt](https://docs.tilt.dev/install.html) 
- [ctlptl](https://github.com/tilt-dev/ctlptl) 

```shell
brew install kubectl minikube helm tilt-dev/tap/tilt tilt-dev/tap/ctlptl
```

## Development

### Create cluster

#### minikube

```shell
# create
ctlptl create cluster minikube --registry=ctlptl-registry --kubernetes-version=v1.22.2
# delete
ctlptl delete cluster minikube
```

#### kind

```shell
# create
ctlptl create cluster kind --registry=ctlptl-registry
# delete
ctlptl delete cluster kind-kind
```

### Running service in k8s

Quick

```shell
tilt up
```

With Test Script:

```shell
TEST_SCRIPT=.github/workflows/roundtrip/wait-and-test.sh CI=1 tilt up
```

### Running in host OS

#### Install ingress

```shell
helm repo add nginx-stable https://helm.nginx.com/stable
helm repo update
helm install ex nginx-stable/nginx-ingress
```

#### Start database

```shell
mkdir -p data
docker run \
    --detach \
    --publish 0.0.0.0:5432:5432 \
    --volume data:/var/lib/postgresql/data \
    --env POSTGRES_PASSWORD=mysecretpassword \
    --env PGDATA=/var/lib/postgresql/data/pgdata \
    postgres
```

#### Start HSM

##### SoftHSM C Module

https://wiki.opendnssec.org/display/SoftHSMDOCS/SoftHSM+Documentation+v2

```shell
# macOS
brew install softhsm
# get module path
brew info softhsm
# /opt/homebrew/Cellar/softhsm/2.6.1  will be  /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so
# FIXME: How can we extract the path from brew???
export PKCS11_MODULE_PATH=/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so
# installs pkcs11-tool
brew install opensc
```

##### SoftHSM Keys

```shell
# enter two sets of PIN, 12345
softhsm2-util --init-token --slot 0 --label "development-token" --pin 12345 --so-pin 12345
# verify login
pkcs11-tool --module $PKCS11_MODULE_PATH --login --show-info --list-objects
# crease RSA key and cert
openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout kas-private.pem -out kas-cert.pem -days 365
# crease EC key and cert
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -subj "/CN=kas" -keyout kas-ec-private.pem -out kas-ec-cert.pem -days 365
# import RSA key to PKCS
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-private.pem --type privkey --label development-rsa-kas
# import RSA cert to PKCS
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-cert.pem --type cert --label development-rsa-kas
# import EC key to PKCS
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-ec-private.pem --type privkey --label development-ec-kas
# import EC cert to PKCS
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-ec-cert.pem --type cert  --label development-ec-kas
```

#### Start services

Manually disable KAS in the tiltfile, if desired, then:

```shell
tilt up 
```

### Start monolith service (outside kubernetes)

```shell
export POSTGRES_HOST=localhost
export POSTGRES_DATABASE=postgres
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=mysecretpassword
export PKCS11_MODULE_PATH=/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so
export PKCS11_SLOT_INDEX=0
export PKCS11_PIN=12345
export PKCS11_LABEL_PUBKEY_RSA=development-rsa-kas
export PKCS11_LABEL_PUBKEY_EC=development-ec-kas
export PRIVATE_KEY_RSA_PATH=../../kas-private.pem
export OIDC_ISSUER_URL=http://localhost:65432/auth/realms/tdf
```

#### Analyze

Development tools to check code quality and standards.

##### Prerequisite

```shell
brew install act golangci-lint
```

Tools

- https://www.docker.com
- https://github.com/nektos/act
- https://github.com/golangci/golangci-lint
- https://github.com/kaitai-io/kaitai_struct

##### Workflow

To run the `analyze` workflow used in the CI

```shell
act --container-architecture linux/amd64 --workflows .github/workflows/analyze.yaml
```

##### Lint

```shell
golangci-lint run
```

##### Unit test

```shell
go test -bench=. -benchmem ./...
```

##### Code Generation

Under `cmd/codegen`, Build kaitai image

```shell
docker build --tag ksc:0.8 --target compiler .
```

To codegen run kaitai container

```shell
docker run -it --volume "$PWD":/workdir ksc:0.8 \
    --target go \
    --outdir build/gencode \
    nanotdf.ksy
```

## References

### Helm

https://helm.sh/docs/chart_template_guide/subcharts_and_globals/  
https://faun.pub/helm-chart-how-to-create-helm-charts-from-kubernetes-k8s-yaml-from-scratch-d64901e36850  
https://github.com/kubernetes/examples/blob/master/guidelines.md  

### Go

https://github.com/powerman/go-monolith-example  
https://github.com/getkin/kin-openapi  

### Docker

https://docs.docker.com/develop/develop-images/multistage-build/  
https://medium.com/@lizrice/non-privileged-containers-based-on-the-scratch-image-a80105d6d341  

### Tilt

https://dev.to/ndrean/rails-on-kubernetes-with-minikube-and-tilt-25ka  

### PostgreSQL

https://dev.to/kushagra_mehta/postgresql-with-go-in-2021-3dfg  
https://stackoverflow.com/questions/24319662/from-inside-of-a-docker-container-how-do-i-connect-to-the-localhost-of-the-mach/24326540#24326540  

### minikube

https://minikube.sigs.k8s.io/docs/handbook/host-access/  

### OIDC

https://github.com/coreos/go-oidc  

### Ingress

https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/  

### KMIP  

https://github.com/ThalesGroup/kmip-go

### pkcs11-tool  

https://verschlüsselt.it/generate-rsa-ecc-and-aes-keys-with-opensc-pkcs11-tool/

### go-util  

https://github.com/gbolo/go-util  
https://github.com/gbolo/go-util/tree/master/pkcs11-test

### SoftHSM Docker

https://github.com/psmiraglia/docker-softhsm

### For local running please start backend following instructions

https://github.com/opentdf/opentdf/tree/main/quickstart

```shell
# additional utils commands
softhsm2-util --delete-token --serial $SERIAL_ID
softhsm2-util --show-slots

# order of commands to run app
softhsm2-util --init-token --slot 0 --label "development-token" --pin 12345 --so-pin 12345
pkcs11-tool --module $PKCS11_MODULE_PATH --login --show-info --list-objects
pkcs11-tool --module $PKCS11_MODULE_PATH --login --keypairgen --key-type rsa:2048 --label development-rsa-kas
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-private.pem --type privkey --label development-rsa-kas
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-cert.pem --type cert --label development-rsa-kas
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-ec-private.pem --type privkey --label development-ec-kas
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-ec-cert.pem --type cert --label development-ec-kas
pkcs11-tool --module $PKCS11_MODULE_PATH --login --show-info --list-objects
```

### Following that steps run the "show info" command

```shell
pkcs11-tool --module $PKCS11_MODULE_PATH --login --show-info --list-objects
```

```shell
# build
docker build --file softhsm2.Dockerfile --tag softhsm2:2.5.0 .

# run
docker run -ti --rm softhsm2:2.5.0 sh -l

softhsm2-util --init-token --slot 0 --label "development-token"

pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login -t

pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login --keypairgen --key-type rsa:2048 --id 100 --label development-rsa

pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login --read-object --type pubkey --label development -o development-public.der

openssl rsa -RSAPublicKey_in -in development-public.der -inform DER -outform PEM -out development-public.pem -RSAPublicKey_out

pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login --list-objects
```

## Troubleshooting

### inside a container

```shell
apt-get update -y
apt-get install -y netcat
nc -vz host.minikube.internal 5432

helm install postgresql bitnami/postgresql

apt-get install postgresql-client
pg_isready --dbname=postgres --host=host.minikube.internal --port=5432 --username=postgres
pg_isready --dbname=postgres --host=ex-postgresql --port=5432 --username=postgres
```
