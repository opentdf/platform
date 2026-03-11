package oauth

import (
	"testing"
	"time"
)

func TestTokenExpiration_RespectsLeeway(t *testing.T) {
	expiredToken := Token{
		received:  time.Now().Add(-tokenExpirationBuffer - 10*time.Second),
		ExpiresIn: 5,
	}
	if !expiredToken.Expired() {
		t.Fatalf("token should be expired")
	}

	goodToken := Token{
		received:  time.Now(),
		ExpiresIn: 2 * int64(tokenExpirationBuffer/time.Second),
	}

	if goodToken.Expired() {
		t.Fatalf("token should not be expired")
	}

	justOverBorderToken := Token{
		received:  time.Now(),
		ExpiresIn: int64(tokenExpirationBuffer/time.Second) - 1,
	}

	if !justOverBorderToken.Expired() {
		t.Fatalf("token should not be expired")
	}
}
