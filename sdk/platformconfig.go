package sdk

func (c PlatformConfiguration) getIdpConfig() map[string]interface{} {
	idpCfg, err := c["idp"].(map[string]interface{})
	if !err {
		idpCfg = map[string]interface{}{}
	}
	return idpCfg
}

func (c PlatformConfiguration) Issuer() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg["issuer"].(string)
	if !ok {
		return "", ErrPlatformIssuerNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) AuthzEndpoint() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg["authorization_endpoint"].(string)
	if !ok {
		return "", ErrPlatformAuthzEndpointNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) TokenEndpoint() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg["token_endpoint"].(string)
	if !ok {
		return "", ErrPlatformTokenEndpointNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) platformEndpoint() (string, error) {
	value, ok := c["platform_endpoint"].(string)
	if !ok {
		return "", ErrPlatformEndpointNotFound
	}
	return value, nil
}
