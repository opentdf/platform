package sdk

const (
	PlatformConfigIdp                   = "idp"
	PlatformConfigIssuer                = "issuer"
	PlatformConfigAuthorizationEndpoint = "authorization_endpoint"
	PlatformConfigTokenEndpoint         = "token_endpoint"
	PlatformConfigPublicClientID        = "public_client_id"
)

func (c PlatformConfiguration) getIdpConfig() map[string]interface{} {
	idpCfg, err := c[PlatformConfigIdp].(map[string]interface{})
	if !err {
		idpCfg = map[string]interface{}{}
	}
	return idpCfg
}

func (c PlatformConfiguration) Issuer() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg[PlatformConfigIssuer].(string)
	if !ok {
		return "", ErrPlatformIssuerNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) AuthzEndpoint() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg[PlatformConfigAuthorizationEndpoint].(string)
	if !ok {
		return "", ErrPlatformAuthzEndpointNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) TokenEndpoint() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg[PlatformConfigTokenEndpoint].(string)
	if !ok {
		return "", ErrPlatformTokenEndpointNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) PublicClientID() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg[PlatformConfigPublicClientID].(string)
	if !ok {
		return "", ErrPlatformPublicClientIDNotFound
	}
	return value, nil
}
