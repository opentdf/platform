package sdk

import (
	"log/slog"
)

func (c PlatformConfiguration) getIdpConfig() map[string]interface{} {
	idpCfg, err := c["idp"].(map[string]interface{})
	if !err {
		slog.Warn("idp configuration not found in well-known configuration")
		idpCfg = map[string]interface{}{}
	}
	return idpCfg
}

func (c PlatformConfiguration) Issuer() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg["issuer"].(string)
	if !ok {
		slog.Warn("issuer not found in well-known idp configuration")
		return "", ErrPlatformIssuerNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) AuthzEndpoint() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg["authorization_endpoint"].(string)
	if !ok {
		slog.Warn("authorization_endpoint not found in well-known idp configuration")
		return "", ErrPlatformAuthzEndpointNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) TokenEndpoint() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg["token_endpoint"].(string)
	if !ok {
		slog.Warn("token_endpoint not found in well-known idp configuration")
		return "", ErrPlatformTokenEndpointNotFound
	}
	return value, nil
}

func (c PlatformConfiguration) PublicClientID() (string, error) {
	idpCfg := c.getIdpConfig()
	value, ok := idpCfg["public_client_id"].(string)
	if !ok {
		slog.Warn("public_client_id not found in well-known idp configuration")
		return "", ErrPlatformTokenEndpointNotFound
	}
	return value, nil
}
