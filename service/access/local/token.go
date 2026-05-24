package local

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// AuthorizationDetailsClaim is the JWT claim name carrying the materialized
// grant set, per RFC 9396 §7.1.
const AuthorizationDetailsClaim = "authorization_details"

// ErrClaimMissing is returned when the access token does not carry any
// authorization_details — the caller has nothing to evaluate against.
var ErrClaimMissing = errors.New("local: authorization_details claim missing")

// GrantsFromToken extracts and validates the materialized grant set from a
// parsed JWT. The caller is responsible for verifying the token's signature
// first (typically via jwt.Parse(..., jwt.WithKeySet(issuerJWKS))).
func GrantsFromToken(token jwt.Token) ([]Grant, error) {
	if token == nil {
		return nil, ErrClaimMissing
	}
	raw, ok := token.Get(AuthorizationDetailsClaim)
	if !ok {
		return nil, ErrClaimMissing
	}
	// jwx stores arbitrary claims as map[string]interface{} / []interface{}.
	// Round-tripping through JSON is the simplest robust path back to typed
	// grants and keeps the parser tolerant of issuer-side ordering quirks.
	buf, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("local: re-encode authorization_details: %w", err)
	}
	return UnmarshalGrants(buf)
}
