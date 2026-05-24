package authorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// RARSigner mints RFC 9396 access tokens signed with an Ed25519 keypair.
// The keypair is held in memory; rotating it invalidates every previously
// issued token, which is the intended behaviour for a POC.
type RARSigner struct {
	mu         sync.RWMutex
	privateKey ed25519.PrivateKey
	jwkPrivate jwk.Key
	jwkPublic  jwk.Key
	jwks       jwk.Set
	issuer     string
	tokenTTL   time.Duration
}

// NewEphemeralRARSigner generates a fresh Ed25519 keypair. The kid is a UUID,
// so each process gets a unique signing identity.
func NewEphemeralRARSigner(issuer string, ttl time.Duration) (*RARSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("rar: generate signing key: %w", err)
	}
	privJWK, err := jwk.FromRaw(priv)
	if err != nil {
		return nil, fmt.Errorf("rar: import private key: %w", err)
	}
	pubJWK, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, fmt.Errorf("rar: import public key: %w", err)
	}
	kid := uuid.NewString()
	for _, k := range []jwk.Key{privJWK, pubJWK} {
		if err := k.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, fmt.Errorf("rar: set kid: %w", err)
		}
		if err := k.Set(jwk.AlgorithmKey, jwa.EdDSA); err != nil {
			return nil, fmt.Errorf("rar: set alg: %w", err)
		}
		if err := k.Set(jwk.KeyUsageKey, "sig"); err != nil {
			return nil, fmt.Errorf("rar: set use: %w", err)
		}
	}
	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		return nil, fmt.Errorf("rar: register public key: %w", err)
	}
	return &RARSigner{
		privateKey: priv,
		jwkPrivate: privJWK,
		jwkPublic:  pubJWK,
		jwks:       set,
		issuer:     issuer,
		tokenTTL:   ttl,
	}, nil
}

// Issue mints a signed JWT carrying the RFC 9396 authorization_details claim
// plus the standard subject/audience/expiry framing.
func (s *RARSigner) Issue(subject, audience string, details []AuthorizationDetail) (string, time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	exp := now.Add(s.tokenTTL)
	tok := jwt.New()
	if err := tok.Set(jwt.IssuerKey, s.issuer); err != nil {
		return "", time.Time{}, err
	}
	if err := tok.Set(jwt.SubjectKey, subject); err != nil {
		return "", time.Time{}, err
	}
	if audience != "" {
		if err := tok.Set(jwt.AudienceKey, audience); err != nil {
			return "", time.Time{}, err
		}
	}
	if err := tok.Set(jwt.IssuedAtKey, now); err != nil {
		return "", time.Time{}, err
	}
	if err := tok.Set(jwt.NotBeforeKey, now); err != nil {
		return "", time.Time{}, err
	}
	if err := tok.Set(jwt.ExpirationKey, exp); err != nil {
		return "", time.Time{}, err
	}
	if err := tok.Set(jwt.JwtIDKey, uuid.NewString()); err != nil {
		return "", time.Time{}, err
	}
	if len(details) > 0 {
		// Round-trip through JSON so the claim is plain map[string]any —
		// jwx's serializer chokes on typed structs in custom claims.
		payload, err := json.Marshal(details)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("rar: marshal authorization_details: %w", err)
		}
		var generic []map[string]any
		if err := json.Unmarshal(payload, &generic); err != nil {
			return "", time.Time{}, fmt.Errorf("rar: re-decode authorization_details: %w", err)
		}
		if err := tok.Set("authorization_details", generic); err != nil {
			return "", time.Time{}, err
		}
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, s.jwkPrivate, jws.WithProtectedHeaders(s.protectedHeaders())))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("rar: sign: %w", err)
	}
	return string(signed), exp, nil
}

// JWKS returns the public JWK Set so resource servers can verify issued tokens.
func (s *RARSigner) JWKS() jwk.Set {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwks
}

func (s *RARSigner) protectedHeaders() jws.Headers {
	h := jws.NewHeaders()
	if kid, ok := s.jwkPrivate.Get(jwk.KeyIDKey); ok {
		_ = h.Set(jws.KeyIDKey, kid)
	}
	_ = h.Set(jws.TypeKey, "JWT")
	return h
}

// ErrSignerNotConfigured is returned when the RAR endpoint is called but
// signing has not been initialised (e.g. feature flag off).
var ErrSignerNotConfigured = errors.New("rar: signer not configured")
