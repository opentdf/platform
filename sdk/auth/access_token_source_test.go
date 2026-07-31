package auth

import "testing"

func TestTokenTypeFromOAuthTokenType(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tokenType string
		want      TokenType
	}{
		{name: "dpop", tokenType: "DPoP", want: TokenTypeDPoP},
		{name: "bearer", tokenType: "Bearer", want: TokenTypeBearer},
		{name: "lowercase dpop is not a token type", tokenType: "dpop", want: TokenTypeBearer},
		{name: "missing token type", want: TokenTypeBearer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TokenTypeFromOAuthTokenType(tc.tokenType); got != tc.want {
				t.Errorf("TokenTypeFromOAuthTokenType(%q) = %q, want %q", tc.tokenType, got, tc.want)
			}
		})
	}
}
