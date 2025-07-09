# Adding support for token exchange to fetch userinfo on the user

## Dev notes

### Okta

- requires private_key_jwk to do client credentials
- requires generating jwk in Okta interface (bug with datetime invalid)
- client app needs to be SPA with PKCE and DPoP enabled
    - need to assign group to the client app (starts with `opentdf`)
    - need to apply group to the user
- audience is virtru.oktapreview.com
- client scopes needed:
  - `openid`
  - `profile`
  - `email`
  - `groups` 
- server scopes needed:
  - `groups`
  - !`openid` - not allowed for server apps
- Token exchange requires `actor_token` to be set to the `private_key_jwk` of the client app
- Server client needs to be a Server App with DPoP enabled
- Client app needs to be a SPA with DPoP enabled
- Scopes needed for validating the client are different than when exchanging tokens. `okta.users.manage.self` is not valid for check, but works in exchange.

## Tasks

- [x] implement and test DPoP support
- [x] update token exchange to use the new private_key_jwk
- [x] test the various scopes needed
- [x] test dpop with okta

### Keycloak

- [ ] figure out how to configure keycloak to support private_key_jwk

### Ping

https://support.pingidentity.com/s/question/0D5UJ000005Bbfk0AC/what-are-the-steps-to-configure-oidc-ldap-activedirectory-we-are-in-the-process-of-adding-support-for-keycloak-and-pingfederate-in-our-productwe-need-a-simple-token-nothing-fancy-but-the-user-info-should-contain-group-membership

Management URL: https://localhost:9999
User: `Administrator`
Pass: `2FederateM0re`

Issuer: `https://localhost:9031`

1. Configure Ping for Oauth
   1. Create Access Token Management: `Applications > Access Token Management`
   2. Create Policy Management: `Applications > OpenID Connect Policy Management`
   3. Configure Scope Management: `System > OAuth Settings > Scope Management`
      1. Add common scopes: `profile`, `email`, `groups`
   4. Configure Authentication Methods: `System > OAuth Settings > Authentication Methods`
      1. Add `DPoP` as an authentication method
   5. Configure simple ldap Data Store: `System > Data & Credential Stores > Data Stores`
      1. Add a new LDAP data store
         1. Name: `LDAP Data Store`
         2. Description: *optional*
         3. Hostname: `test-openldap`
         4. User DN: `cn=admin,dc=example,dc=org`
         5. Password: `admin`
      2. Test connection to ensure it works
      3. Save the configuration
   6. Create Policy Contract: `Authentication > Policies > Policy Contracts`
      1. Add a new contract
         1. Name: `DPoP Contract`
         2. Description: *optional*
         3. Contract Type: `DPoP`
         4. Authentication Methods: `DPoP`
   7. Create Password Credential Validators
   8. Create Policy Contract Grant Mapping
2. Setup client credentials with private_key_jwk: `Applications > OAuth Clients`
   1. Add a new client
      1. Client ID: `dsp-platform`
      2. Client Name: `DSP Platform Client`
      3. Description: *optional*
      4. Client Authentication: `Private Key JWT`
         1. Replay Prevention: `Enabled`
         2. Signing Algorithm: `Allow Any`
      5. JWKS: *Generate and add public key*
      6. Allowed Grant Types: `Client Credentials`, `Token Exchange`
      7. Default Access Token Management: `Default` (optionally set to the desired manager if multiple are configured)
      8. Demonstration Proof-of-Possession: `Enabled` (help text is "Require DPoP")
3. Setup public client credentials: `Applications > OAuth Clients`
   1. Add a new client
      1. Client ID: `dsp-public-example`
      2. Client Name: `Public DSP Example Client`
      3. Description: *optional*
      4. Client Authentication: `None`
      5. Redirect URIs: `http://localhost:9000/pkce-demo`
         1. *It appears that Ping does not support wildcards*
      6. Allowed Grant Types: `Authorization Code`, `Refresh Token`
      7. Require offline access scope: `No` (production requirement might be different)
      8. Default Access Token Management: `Default` (optionally set to the desired manager if multiple are configured)
      9. Require Proof Key for Code Exchange (PKCE): `Yes`
      10. Demonstration Proof-of-Possession: `Enabled` (help text is "Require DPoP")