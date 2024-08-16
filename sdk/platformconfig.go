package sdk

import "log/slog"



func (s SDK) getIdpConfig() map[string]interface{} {
	idpCfg, err := s.config.platformConfiguration["idp"].(map[string]interface{})
	if !err {
		slog.Warn("idp configuration not found in well-known configuration")
		idpCfg = map[string]interface{}{}
	}
	return idpCfg
}

func (s SDK) PlatformIssuer() (string, error) {
	idpCfg := s.getIdpConfig()
	value, ok := idpCfg["issuer"].(string)
	if !ok {
		slog.Warn("issuer not found in well-known idp configuration")
		return "", ErrPlatformIssuerNotFound
	}
	return value, nil
}

func (s SDK) PlatformAuthzEndpoint() (string, error) {
	idpCfg := s.getIdpConfig()
	value, ok := idpCfg["authorization_endpoint"].(string)
	if !ok {
		slog.Warn("authorization_endpoint not found in well-known idp configuration")
		return "", ErrPlatformAuthzEndpointNotFound
	}
	return value, nil
}

func (s SDK) PlatformTokenEndpoint() (string, error) {
	idpCfg := s.getIdpConfig()
	value, ok := idpCfg["token_endpoint"].(string)
	if !ok {
		slog.Warn("token_endpoint not found in well-known idp configuration")
		return "", ErrPlatformTokenEndpointNotFound
	}
	return value, nil
}

func (s SDK) PlatformPublicClientID() (string, error) {
	idpCfg := s.getIdpConfig()
	value, ok := idpCfg["public_client_id"].(string)
	if !ok {
		slog.Warn("public_client_id not found in well-known idp configuration")
		return "", ErrPlatformTokenEndpointNotFound
	}
	return value, nil
}
