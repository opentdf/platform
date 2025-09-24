# Performance

## Prerequisites

```shell
brew install k6
```

## Execute

```shell
# Basic run with default endpoints
k6 run authorization-client.js

k6 run authorization-client.js --vus 100 --duration 1m

# Run with custom endpoints
k6 run authorization-client.js --vus 100 --duration 1m \
  --env AUTH_URL=http://keycloak.example.com/auth/realms/myrealm/protocol/openid-connect/token \
  --env API_URL=https://api.example.com

# Complete configuration with all parameters
k6 run authorization-client.js --vus 100 --duration 1m \
  --env AUTH_URL=http://keycloak.example.com/auth/realms/myrealm/protocol/openid-connect/token \
  --env API_URL=https://api.example.com \
  --env TOTAL_VUS=1000 \
  --env KEYCLOAK_URL=http://keycloak.example.com \
  --env REALM=opentdf
```
