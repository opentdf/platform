// Unit tests for BuildOAuthForm
package oidc

import (
	"net/url"
	"reflect"
	"testing"
)

func TestBuildOAuthForm_ClientCredentials(t *testing.T) {
	params := OAuthFormParams{
		FormType:            OAuthFormClientCredentials,
		ClientID:            "client-id",
		ClientAssertion:     "assertion",
		ClientAssertionType: "custom-type",
		Scopes:              []string{"openid", "email"},
	}
	form := BuildOAuthForm(params)
	want := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {"client-id"},
		"client_assertion":      {"assertion"},
		"client_assertion_type": {"custom-type"},
		"scope":                 {"openid email"},
	}
	if !reflect.DeepEqual(form, want) {
		t.Errorf("form mismatch\ngot:  %v\nwant: %v", form, want)
	}
}

func TestBuildOAuthForm_ClientCredentials_DefaultType(t *testing.T) {
	params := OAuthFormParams{
		FormType:        OAuthFormClientCredentials,
		ClientID:        "client-id",
		ClientAssertion: "assertion",
		Scopes:          []string{"openid"},
	}
	form := BuildOAuthForm(params)
	if form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("expected default client_assertion_type, got %q", form.Get("client_assertion_type"))
	}
}

func TestBuildOAuthForm_TokenExchange(t *testing.T) {
	params := OAuthFormParams{
		FormType:            OAuthFormTokenExchange,
		ClientID:            "cid",
		ClientAssertion:     "assertion",
		ClientAssertionType: "type",
		SubjectToken:        "subtok",
		SubjectTokenType:    "subtype",
		ActorToken:          "actok",
		ActorTokenType:      "actype",
		Scopes:              []string{"openid", "profile"},
		Audience:            []string{"aud1", "aud2"},
	}
	form := BuildOAuthForm(params)
	want := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":             {"cid"},
		"client_assertion":      {"assertion"},
		"client_assertion_type": {"type"},
		"subject_token":         {"subtok"},
		"subject_token_type":    {"subtype"},
		"actor_token":           {"actok"},
		"actor_token_type":      {"actype"},
		"scope":                 {"openid profile"},
		"audience":              {"aud1", "aud2"},
	}
	if !reflect.DeepEqual(form, want) {
		t.Errorf("form mismatch\ngot:  %v\nwant: %v", form, want)
	}
}

func TestBuildOAuthForm_TokenExchange_DefaultTypes(t *testing.T) {
	params := OAuthFormParams{
		FormType:     OAuthFormTokenExchange,
		ClientID:     "cid",
		SubjectToken: "subtok",
		Scopes:       []string{"openid"},
		Audience:     []string{"aud"},
	}
	form := BuildOAuthForm(params)
	if form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("expected default client_assertion_type, got %q", form.Get("client_assertion_type"))
	}
	if form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("expected default subject_token_type, got %q", form.Get("subject_token_type"))
	}
}
