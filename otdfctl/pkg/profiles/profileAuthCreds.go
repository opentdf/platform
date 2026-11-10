package profiles

const (
	AuthTypeClientCredentials = "client-credentials"
	AuthTypeAccessToken       = "access-token"
)

type AuthCredentials struct {
	AuthType string `json:"authType"`
	ClientID string `json:"clientId"`
	// Used for client credentials
	ClientSecret string                     `json:"clientSecret,omitempty"`
	AccessToken  AuthCredentialsAccessToken `json:"accessToken,omitempty"`
}

type AuthCredentialsAccessToken struct {
	ClientID     string `json:"clientId"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	Expiration   int64  `json:"expiration"`
}

func (p *OtdfctlProfileStore) GetAuthCredentials() AuthCredentials {
	return p.config.AuthCredentials
}

func (p *OtdfctlProfileStore) SetAuthCredentials(authCredentials AuthCredentials) error {
	p.config.AuthCredentials = authCredentials
	return p.store.Save()
}
