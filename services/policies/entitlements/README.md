# OpenTDF Platform OPA rego policies

## entitlements.rego

This is the default rego policy that will parse a JWT, 
traverse the subject mappings, and return the entitlements.

## entitlements-keycloak.rego

This is a rego policy for calling Keycloak to get an entity representation,
traverse the subject mappings, and return the entitlements.
