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

func (c PlatformConfiguration) PublicClientID() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg["public_client_id"].(string)
	if !ok {
		return "", ErrPlatformPublicClientIDNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) AuthCodeFlowPort() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg["auth_code_flow_port"].(string)
	if !ok {
		return "", ErrPlatformAuthCodeFlowPort
	}
	return value, nil
}
