## Keycloak

- Platform Client Id
  - need to add a new platform client id that supports direct access grants
  - need to make sure this client is not overprivileged
  - need to map the groups claim so that we can get it in userinfo
- Public Client Id
  - need to enable front channel logout
  - need to add an audience claim that maps to the Platform Client Id
- App developer notes
  - need to add support for DPoP and JWT authentication
  - post-logout redirect is more complex


## Remaining tasks

- [ ] Test the platform run where the client id is not set
- [ ] Validate that the platform's client id and secret are usable with the IdP