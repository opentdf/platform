// Package authorization — RAR CWT signer.
//
// Mints RFC 8392 CWTs (COSE_Sign1 / ES256) carrying the materialized RFC 9396
// authorization_details payload. Mirrors RARSigner but emits CBOR instead of
// JWT/JWS so consumers that prefer CWT throughout (e.g. an authnz-rs-issued
// CWT subject token round-tripping back as a CWT access token) don't have to
// straddle two encodings.
//
// Wire shape:
//
//	CWT payload (CBOR map):
//	  1 (iss):  configured issuer
//	  2 (sub):  entity subject string
//	  3 (aud):  caller-supplied audience (omitted if empty)
//	  4 (exp):  unix seconds
//	  5 (nbf):  unix seconds
//	  6 (iat):  unix seconds
//	  7 (cti):  16-byte UUID
//	  "authorization_details": [ {type, actions[], locations[], obligations[]}, ... ]
//
// Signing key is an ephemeral ES256 (P-256) keypair generated at construction.
// The public half is published via COSEKeySet() — the COSE Key Set CBOR shape
// authnz-rs already serves at /.well-known/cose-keys, so PEPs can use one
// verifier code path for both the subject-side and access-side tokens.
package authorization

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/veraison/go-cose"

	"github.com/opentdf/platform/service/access/local"
)

// COSE Key Set labels (RFC 9052 §7) used when building the published key.
const (
	coseKtyLabel = 1
	coseKidLabel = 2
	coseAlgLabel = 3
	coseCrvLabel = -1
	coseXLabel   = -2
	coseYLabel   = -3
	coseKtyEC2   = 2
	coseAlgES256 = -7
	coseCrvP256  = 1
)

// CWT integer claim labels (RFC 8392 §4).
const (
	cwtClaimIss = 1
	cwtClaimSub = 2
	cwtClaimAud = 3
	cwtClaimExp = 4
	cwtClaimNbf = 5
	cwtClaimIat = 6
	cwtClaimCti = 7
)

// p256CoordLen is the byte length of an X9.62 P-256 coordinate.
const p256CoordLen = 32

// ErrCWTSignerNotConfigured is returned when the RAR endpoint is asked for a
// CWT response token but the CWT signer was never built.
var ErrCWTSignerNotConfigured = errors.New("rar: CWT signer not configured")

// RARCWTSigner mints RFC 8392 CWTs over an ephemeral ES256 keypair. The
// matching public key is published via COSEKeySet().
type RARCWTSigner struct {
	mu     sync.RWMutex
	priv   *ecdsa.PrivateKey
	kid    []byte
	issuer string
	ttl    time.Duration
}

// NewEphemeralRARCWTSigner generates a fresh ES256 (P-256) keypair and
// returns a ready-to-use signer. The kid is a UUID, so each process gets a
// unique signing identity (matching RARSigner's behavior).
func NewEphemeralRARCWTSigner(issuer string, ttl time.Duration) (*RARCWTSigner, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("rar cwt: generate signing key: %w", err)
	}
	kid, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("rar cwt: marshal kid: %w", err)
	}
	return &RARCWTSigner{
		priv:   priv,
		kid:    kid,
		issuer: issuer,
		ttl:    ttl,
	}, nil
}

// Issue mints a CWT carrying the supplied authorization_details grant set.
// Returns the raw CBOR bytes of the (tagged) COSE_Sign1 plus the absolute
// expiry time so callers can populate response framing if needed.
func (s *RARCWTSigner) Issue(subject, audience string, grants []local.Grant) ([]byte, time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	exp := now.Add(s.ttl)
	cti, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("rar cwt: cti: %w", err)
	}

	claims := map[any]any{
		cwtClaimIss: s.issuer,
		cwtClaimSub: subject,
		cwtClaimExp: exp.Unix(),
		cwtClaimNbf: now.Unix(),
		cwtClaimIat: now.Unix(),
		cwtClaimCti: cti,
	}
	if audience != "" {
		claims[cwtClaimAud] = audience
	}
	if len(grants) > 0 {
		// authorization_details lives at a text label, matching the JSON
		// claim name. Each grant becomes a CBOR map with string keys so a
		// CBOR-aware PEP gets the same shape it would from JSON.
		claims[local.AuthorizationDetailsClaim] = grantsToCBOR(grants)
	}

	payload, err := cbor.Marshal(claims)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("rar cwt: encode claims: %w", err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, s.priv)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("rar cwt: new signer: %w", err)
	}
	msg := cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
				cose.HeaderLabelKeyID:     s.kid,
			},
		},
		Payload: payload,
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, time.Time{}, fmt.Errorf("rar cwt: sign: %w", err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("rar cwt: marshal: %w", err)
	}
	// Wrap in CWT tag #61 per RFC 8392 §6 so naive consumers can detect the
	// payload type without inspecting the structure.
	tagged := append([]byte{0xd8, 0x3d}, raw...)
	return tagged, exp, nil
}

// COSEKeySet returns the CBOR-encoded one-entry COSE Key Set (RFC 9052 §7)
// containing this signer's public key, suitable for serving at the
// /v2/authorization/cose-keys endpoint.
func (s *RARCWTSigner) COSEKeySet() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	x := padCoord(s.priv.X.Bytes())
	y := padCoord(s.priv.Y.Bytes())
	key := map[int64]any{
		coseKtyLabel: int64(coseKtyEC2),
		coseAlgLabel: int64(coseAlgES256),
		coseCrvLabel: int64(coseCrvP256),
		coseXLabel:   x,
		coseYLabel:   y,
		coseKidLabel: s.kid,
	}
	buf, err := cbor.Marshal([]map[int64]any{key})
	if err != nil {
		return nil, fmt.Errorf("rar cwt: marshal cose key set: %w", err)
	}
	return buf, nil
}

// grantsToCBOR converts a Grant slice to a CBOR array-of-maps with string
// keys so the wire shape mirrors the JSON shape exactly.
func grantsToCBOR(grants []local.Grant) []map[string]any {
	out := make([]map[string]any, 0, len(grants))
	for _, g := range grants {
		m := map[string]any{
			"type":      g.Type,
			"actions":   g.Actions,
			"locations": g.Locations,
		}
		if len(g.Obligations) > 0 {
			m["obligations"] = g.Obligations
		}
		out = append(out, m)
	}
	return out
}

// padCoord left-pads an X9.62 EC coordinate to the fixed P-256 length so
// COSE consumers don't have to handle short-form integers.
func padCoord(b []byte) []byte {
	if len(b) >= p256CoordLen {
		return b[len(b)-p256CoordLen:]
	}
	out := make([]byte, p256CoordLen)
	copy(out[p256CoordLen-len(b):], b)
	return out
}
