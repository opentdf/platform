package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func mustGenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func Test_Token_Expired(t *testing.T) {
	expiredToken := Token{
		received:  time.Now().Add(-10 * time.Second),
		ExpiresIn: 5,
	}
	if !expiredToken.Expired() {
		t.Fatalf("token should be expired")
	}

	goodToken := Token{
		received:  time.Now(),
		ExpiresIn: 60,
	}

	if goodToken.Expired() {
		t.Fatalf("token should not be expired")
	}

	nearExpiryToken := Token{
		received:         time.Now(),
		ExpiresIn:        5,
		ExpirationBuffer: 90 * time.Second,
	}

	if nearExpiryToken.Expired() {
		t.Fatalf("token should not be expired")
	}
	if (Token{received: time.Now().Add(-time.Hour)}).Expired() {
		t.Fatal("token without expires_in should not expire")
	}
}

func Test_Token_ShouldRenew(t *testing.T) {
	tests := []struct {
		name      string
		remaining time.Duration
		buffer    time.Duration
		renew     bool
	}{
		{name: "WithinCustomWindow", remaining: time.Minute, buffer: 90 * time.Second, renew: true},
		{name: "OutsideCustomWindow", remaining: 2 * time.Minute, buffer: 90 * time.Second},
		{name: "OutsideTenSecondWindow", remaining: time.Minute, buffer: 10 * time.Second},
		{name: "ZeroBufferValid", remaining: 5 * time.Second},
		{name: "ZeroBufferExpired", remaining: -time.Second, renew: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := Token{
				received:         time.Now().Add(test.remaining - time.Hour),
				ExpiresIn:        3600,
				ExpirationBuffer: test.buffer,
			}
			if renew := token.ShouldRenew(); renew != test.renew {
				t.Fatalf("ShouldRenew() = %t, want %t", renew, test.renew)
			}
		})
	}

	t.Run("MissingExpiry", func(t *testing.T) {
		token := Token{received: time.Now().Add(-time.Hour), ExpirationBuffer: 90 * time.Second}
		if token.ShouldRenew() {
			t.Fatal("token without expires_in should not expire")
		}
	})
}

func Test_Token_ProcessResponse_DefaultsExpirationBuffer(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"access_token":"test-token","expires_in":5}`)),
	}
	token, err := processResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if token.ExpirationBuffer != 10*time.Second {
		t.Fatalf("ExpirationBuffer = %s, want 10s", token.ExpirationBuffer)
	}
	if !token.ShouldRenew() || token.Expired() {
		t.Fatal("token should need renewal without being expired")
	}
}

// TestGetTokenExchangeRequest_SubjectTokenType verifies that the RFC 8693 required
// field subject_token_type is present in the token exchange POST body and defaults
// to access_token when not explicitly set.
func TestGetTokenExchangeRequest_SubjectTokenType(t *testing.T) {
	makeKey := func(t *testing.T) jwk.Key {
		t.Helper()
		raw, err := jwk.FromRaw(mustGenerateRSAKey(t))
		if err != nil {
			t.Fatalf("jwk.FromRaw: %v", err)
		}
		if err := raw.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
			t.Fatalf("set algorithm: %v", err)
		}
		return raw
	}

	parseForm := func(t *testing.T, info TokenExchangeInfo) url.Values {
		t.Helper()
		key := makeKey(t)
		req, err := getTokenExchangeRequest(
			t.Context(),
			"https://idp.example.com/token",
			"",
			[]string{"openid"},
			ClientCredentials{ClientID: "test-client", ClientAuth: "test-secret"},
			info,
			&key,
		)
		if err != nil {
			t.Fatalf("getTokenExchangeRequest: %v", err)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parse form: %v", err)
		}
		return form
	}

	const idTokenURN = "urn:ietf:params:oauth:token-type:id_token"

	t.Run("defaults to access_token when SubjectTokenType is empty", func(t *testing.T) {
		form := parseForm(t, TokenExchangeInfo{SubjectToken: "tok"})
		if got := form.Get("subject_token_type"); got != defaultSubjectTokenType {
			t.Errorf("subject_token_type = %q, want %q", got, defaultSubjectTokenType)
		}
	})

	t.Run("uses caller-supplied SubjectTokenType", func(t *testing.T) {
		form := parseForm(t, TokenExchangeInfo{SubjectToken: "tok", SubjectTokenType: idTokenURN})
		if got := form.Get("subject_token_type"); got != idTokenURN {
			t.Errorf("subject_token_type = %q, want %q", got, idTokenURN)
		}
	})

	t.Run("required RFC 8693 fields are present", func(t *testing.T) {
		form := parseForm(t, TokenExchangeInfo{SubjectToken: "my-subject-token"})
		if got := form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
			t.Errorf("grant_type = %q, want token-exchange URN", got)
		}
		if got := form.Get("subject_token"); got != "my-subject-token" {
			t.Errorf("subject_token = %q, want %q", got, "my-subject-token")
		}
		if got := form.Get("subject_token_type"); got == "" {
			t.Error("subject_token_type must not be empty")
		}
	})
}
