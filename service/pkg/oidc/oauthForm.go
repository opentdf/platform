package oidc

import (
	"net/url"
	"strings"
)

// OAuthFormType defines the type of OAuth form to build
// e.g. ClientCredentials, TokenExchange
// Add more types as needed
type OAuthFormType int

const (
	OAuthFormClientCredentials OAuthFormType = iota
	OAuthFormTokenExchange
)

// OAuthFormParams holds parameters for building an OAuth form
// Only relevant fields for the form type need to be set
type OAuthFormParams struct {
	FormType  OAuthFormType
	GrantType string

	ClientID            string
	ClientAssertionType string
	ClientAssertion     string

	Scopes []string

	// TokenExchange specific
	ActorToken     string
	ActorTokenType string

	Audience []string

	SubjectToken     string
	SubjectTokenType string
}

// BuildOAuthForm builds a url.Values form for the given OAuth flow
func BuildOAuthForm(params OAuthFormParams) url.Values {
	form := url.Values{}
	switch params.FormType {
	case OAuthFormClientCredentials:
		form.Set("grant_type", "client_credentials")

		form.Set("client_id", params.ClientID)
		form.Set("client_assertion", params.ClientAssertion)
		if params.ClientAssertionType != "" {
			form.Set("client_assertion_type", params.ClientAssertionType)
		} else {
			form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		}

		form.Set("scope", strings.Join(params.Scopes, " "))

	case OAuthFormTokenExchange:
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")

		form.Set("client_id", params.ClientID)
		form.Set("client_assertion", params.ClientAssertion)
		if params.ClientAssertionType != "" {
			form.Set("client_assertion_type", params.ClientAssertionType)
		} else {
			form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		}

		form.Set("subject_token", params.SubjectToken)
		if params.SubjectTokenType != "" {
			form.Set("subject_token_type", params.SubjectTokenType)
		} else {
			form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
		}

		form.Set("actor_token", params.ActorToken)
		form.Set("actor_token_type", params.ActorTokenType)

		form.Set("scope", strings.Join(params.Scopes, " "))

		// Audience
		for _, a := range params.Audience {
			form.Add("audience", a)
		}
	}
	return form
}
