package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/url"
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

func TestTokenExpiration_RespectsLeeway(t *testing.T) {
	expiredToken := Token{
		received:  time.Now().Add(-DefaultTokenExpirationBuffer - 10*time.Second),
		ExpiresIn: 5,
	}
	if !expiredToken.Expired() {
		t.Fatalf("token should be expired")
	}

	goodToken := Token{
		received:  time.Now(),
		ExpiresIn: 2 * int64(DefaultTokenExpirationBuffer/time.Second),
	}

	if goodToken.Expired() {
		t.Fatalf("token should not be expired")
	}

	justOverBorderToken := Token{
		received:  time.Now(),
		ExpiresIn: int64(DefaultTokenExpirationBuffer/time.Second) - 1,
	}

	if !justOverBorderToken.Expired() {
		t.Fatalf("token should not be expired")
	}
}

func Test_Token_ExpiredWithBuffer(t *testing.T) {
	tests := []struct {
		name      string
		remaining time.Duration
		buffer    time.Duration
		expired   bool
	}{
		{name: "WithinCustomWindow", remaining: time.Minute, buffer: 90 * time.Second, expired: true},
		{name: "OutsideCustomWindow", remaining: 2 * time.Minute, buffer: 90 * time.Second},
		{name: "OutsideDefaultWindow", remaining: time.Minute, buffer: DefaultTokenExpirationBuffer},
		{name: "ZeroBufferValid", remaining: 5 * time.Second},
		{name: "ZeroBufferExpired", remaining: -time.Second, expired: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := Token{
				received:  time.Now().Add(test.remaining - time.Hour),
				ExpiresIn: 3600,
			}
			if expired := token.ExpiredWithBuffer(test.buffer); expired != test.expired {
				t.Fatalf("ExpiredWithBuffer(%s) = %t, want %t", test.buffer, expired, test.expired)
			}
		})
	}

	t.Run("MissingExpiry", func(t *testing.T) {
		token := Token{received: time.Now().Add(-time.Hour)}
		if token.ExpiredWithBuffer(90 * time.Second) {
			t.Fatal("token without expires_in should not expire")
		}
	})
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
