# OpenTDF Platform Ory Hydra example

## Overview

This example shows how to integrate with [Ory Hydra](https://www.ory.sh/hydra/), a hardened and certified OAuth 2.0 and OpenID Connect provider.

The highlight of this example is to show th webhook integration.

## Setup

### Install Ory Hydra

```shell
brew install ory/tap/hydra
```

### Start both public and administrative HTTP/2 APIs.
Also, create a sqllite db

```shell
export DSN="sqlite://./db.sqlite?_fk=true"
hydra migrate sql $DSN --yes
hydra serve all --dev --config ./hydra.yaml
```

### Create clients

client `opentdf`

```shell
hydra create oauth2-client \
    --skip-tls-verify \
    --endpoint http://127.0.0.1:4445/ \
    --format json \
    --grant-type client_credentials \
    --name opentdf \
    --secret secret
```

client `opentdf-sdk`

```shell
hydra create oauth2-client \
    --skip-tls-verify \
    --endpoint http://127.0.0.1:4445/ \
    --format json \
    --grant-type client_credentials \
    --audience "http://localhost:8080" \
    --name opentdf-sdk4 \
    --secret secret
```

- Update `opentdf.yaml` with UUID client ids returned from hydra
- Update `sdk.WithClientCredentials` and `sdk.WithTokenEndpoint` in `examples/cmd`

### Start OpenTDF server

```shell
../../opentdf start
```
