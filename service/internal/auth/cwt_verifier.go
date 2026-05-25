// Package auth — CWT subject-token verifier for the RFC 8693 token-exchange
// endpoint at /v2/authorization/token.
//
// The verifier accepts base64url-encoded RFC 8392 CWTs (COSE_Sign1 over CBOR,
// ES256 today) issued by an IdP that publishes its signing keys at a
// /.well-known/cose-keys endpoint (RFC 9052 COSE Key Set in CBOR). It
// verifies the signature, validates the standard claims (iss / aud / exp /
// nbf), and returns:
//
//  1. A `jwt.Token` populated from the verified CWT claims, used by the RAR
//     endpoint for subject and audit-context extraction. CWT integer label
//     claims (1=iss, 2=sub, 3=aud, 4=exp, 5=nbf, 6=iat, 7=cti) are mapped to
//     their JWT-equivalent string keys; arkavo-rs text-label custom claims
//     are passed through unchanged.
//
//  2. An *unsigned* JWT serialization (`alg=none`) of the same claims. The
//     downstream claims-mode ERS calls `jwt.ParseString(..., WithVerify(false),
//     WithValidate(false))` to extract claims — it does not re-verify — so an
//     unsigned representation is a safe and cheap bridge. The RAR endpoint
//     has already enforced trust on the CWT signature.
//
// Refresh and caching of the COSE Key Set is bounded by CacheTTL.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/veraison/go-cose"

	"github.com/opentdf/platform/service/logger"
)

// CWT integer claim labels (RFC 8392 §4) and other small constants. Centralized
// to keep the per-label switch readable and to silence the magic-number lint.
const (
	cwtLabelIss = 1
	cwtLabelSub = 2
	cwtLabelAud = 3
	cwtLabelExp = 4
	cwtLabelNbf = 5
	cwtLabelIat = 6
	cwtLabelCti = 7
	cwtLabelCnf = 8

	// COSE Key Set labels (RFC 9052 §7) for EC2 keys.
	coseKeyLabelKty = 1
	coseKeyLabelKid = 2
	coseKeyLabelAlg = 3
	coseKeyLabelCrv = -1
	coseKeyLabelX   = -2
	coseKeyLabelY   = -3
	coseKtyEC2      = 2
	coseCrvP256     = 1

	// CWT CBOR tag (RFC 8392 §6) is encoded as the 2-byte prefix 0xd8, 0x3d.
	cwtCBORTagHeaderLen = 2

	// algorithmES256 is the only COSE algorithm the verifier supports today.
	algorithmES256     = "ES256"
	defaultCWTCacheTTL = 10 * time.Minute
)

// CWTSubjectTokenVerifier verifies a CWT subject token presented to the RAR
// endpoint. Returns the verified claims as a jwt.Token (for the RAR
// endpoint's own use) and an unsigned-JWT string suitable for the
// claims-mode ERS to parse.
type CWTSubjectTokenVerifier interface {
	VerifyCWTSubjectToken(ctx context.Context, subjectToken string) (jwt.Token, string, error)
}

// CWTVerifierConfig is the verifier's runtime configuration. Mirrors the
// authorization-service config struct of the same name but lives here so
// the auth package has no dependency on the authorization package.
type CWTVerifierConfig struct {
	COSEKeysURL string
	Issuer      string
	Audience    string
	Algorithm   string        // currently only "ES256"
	CacheTTL    time.Duration // how long to cache the fetched key set
	// HTTPClient is overridable for tests. Defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// CWTVerifier is the concrete CWTSubjectTokenVerifier implementation.
type CWTVerifier struct {
	cfg CWTVerifierConfig
	log *logger.Logger

	mu        sync.RWMutex
	cachedAt  time.Time
	cachedSet []coseEC2Key
}

// NewCWTVerifier constructs a verifier from config. Performs an eager fetch
// of the COSE Key Set so misconfiguration fails fast at startup. Errors are
// not fatal for the cache (the verifier will retry on demand) but invalid
// algorithms or empty issuer/audience are.
func NewCWTVerifier(ctx context.Context, cfg CWTVerifierConfig, log *logger.Logger) (*CWTVerifier, error) {
	if cfg.COSEKeysURL == "" {
		return nil, errors.New("cwt verifier: cose_keys_url is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("cwt verifier: issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("cwt verifier: audience is required")
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = algorithmES256
	}
	if cfg.Algorithm != algorithmES256 {
		return nil, fmt.Errorf("cwt verifier: unsupported algorithm %q (only ES256 today)", cfg.Algorithm)
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultCWTCacheTTL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}

	v := &CWTVerifier{cfg: cfg, log: log}
	// Eager fetch — if the URL is unreachable we want startup to log it; an
	// error here doesn't prevent the verifier from being constructed because
	// the cache is refreshed lazily on first use, but we surface the warning.
	if _, err := v.keys(ctx); err != nil && log != nil {
		log.WarnContext(ctx, "initial COSE key set fetch failed; will retry on first verification",
			slog.String("url", cfg.COSEKeysURL),
			slog.Any("error", err),
		)
	}
	return v, nil
}

// VerifyAccessToken satisfies AccessTokenVerifier so *CWTVerifier can serve
// as the inbound bearer-token verifier for the auth middleware. The
// unsigned-JWT string returned by VerifyCWTSubjectToken is only useful at
// the RAR-endpoint boundary (which bridges to the claims-mode ERS); for
// bearer auth on every other request we only need the jwt.Token.
func (v *CWTVerifier) VerifyAccessToken(ctx context.Context, tokenRaw string) (jwt.Token, error) {
	tok, _, err := v.VerifyCWTSubjectToken(ctx, tokenRaw)
	return tok, err
}

// VerifyCWTSubjectToken verifies the base64url-encoded CWT and returns the
// verified claims as both a jwt.Token (for direct use) and an unsigned-JWT
// string (for the claims-mode ERS).
func (v *CWTVerifier) VerifyCWTSubjectToken(ctx context.Context, subjectToken string) (jwt.Token, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(subjectToken)
	if err != nil {
		// Some clients pad. Accept either form.
		raw, err = base64.StdEncoding.DecodeString(subjectToken)
		if err != nil {
			return nil, "", fmt.Errorf("cwt: subject_token is not valid base64url: %w", err)
		}
	}

	// CWTs may be wrapped in CBOR tag #61 (RFC 8392 §6); strip the 2-byte
	// tag header if present so go-cose sees the bare COSE_Sign1.
	if len(raw) >= cwtCBORTagHeaderLen && raw[0] == 0xd8 && raw[1] == 0x3d {
		raw = raw[cwtCBORTagHeaderLen:]
	}

	// RFC 8392 §6 lets the inner message be either a tagged COSE_Sign1
	// (tag 18) or an untagged COSE_Sign1 array. Go's veraison/go-cose
	// splits these into two types — Sign1Message wants the tag, while
	// UntaggedSign1Message wants the bare array. Try tagged first (matches
	// our own test fixtures) and fall back to untagged (matches what
	// coset's `sign1.to_vec()` emits, used by authnz-rs).
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(raw); err != nil {
		var untagged cose.UntaggedSign1Message
		if uErr := untagged.UnmarshalCBOR(raw); uErr != nil {
			return nil, "", fmt.Errorf("cwt: not a COSE_Sign1 (tagged: %v; untagged: %w)", err, uErr)
		}
		msg = cose.Sign1Message(untagged)
	}

	keys, err := v.keys(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("cwt: cannot fetch COSE Key Set: %w", err)
	}

	kid, _ := msg.Headers.Protected[cose.HeaderLabelKeyID].([]byte)
	if kid == nil {
		// Try unprotected header as a fallback.
		kid, _ = msg.Headers.Unprotected[cose.HeaderLabelKeyID].([]byte)
	}

	verifierFound := false
	for _, k := range keys {
		if len(kid) > 0 && !bytesEqual(k.kid, kid) {
			continue
		}
		ecdsaKey, err := k.toECDSA()
		if err != nil {
			continue
		}
		coseVerifier, err := cose.NewVerifier(cose.AlgorithmES256, ecdsaKey)
		if err != nil {
			continue
		}
		if err := msg.Verify(nil, coseVerifier); err == nil {
			verifierFound = true
			break
		}
	}
	if !verifierFound {
		return nil, "", errors.New("cwt: signature does not verify against any cached COSE key")
	}

	claims, err := decodeCWTClaims(msg.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("cwt: decode claims: %w", err)
	}

	if err := v.validateStandardClaims(claims); err != nil {
		return nil, "", err
	}

	tok, err := claimsToJWTToken(claims)
	if err != nil {
		return nil, "", fmt.Errorf("cwt: build jwt.Token: %w", err)
	}
	unsigned, err := encodeUnsignedJWT(claims)
	if err != nil {
		return nil, "", fmt.Errorf("cwt: encode unsigned JWT: %w", err)
	}
	return tok, unsigned, nil
}

// validateStandardClaims enforces iss / aud / exp / nbf per RFC 8392 §3.
func (v *CWTVerifier) validateStandardClaims(c map[string]any) error {
	if iss, _ := c["iss"].(string); iss != v.cfg.Issuer {
		return fmt.Errorf("cwt: iss mismatch (got %q, want %q)", iss, v.cfg.Issuer)
	}
	if !audienceContains(c["aud"], v.cfg.Audience) {
		return fmt.Errorf("cwt: aud does not contain %q", v.cfg.Audience)
	}
	now := time.Now().Unix()
	if exp, ok := claimInt64(c["exp"]); ok && now >= exp {
		return errors.New("cwt: token expired")
	}
	if nbf, ok := claimInt64(c["nbf"]); ok && now < nbf {
		return errors.New("cwt: token not yet valid")
	}
	return nil
}

// keys returns the currently cached COSE Key Set, refreshing it from
// cose_keys_url if the cache is stale or empty.
func (v *CWTVerifier) keys(ctx context.Context) ([]coseEC2Key, error) {
	v.mu.RLock()
	if len(v.cachedSet) > 0 && time.Since(v.cachedAt) < v.cfg.CacheTTL {
		defer v.mu.RUnlock()
		return v.cachedSet, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	// Double-check after acquiring the write lock.
	if len(v.cachedSet) > 0 && time.Since(v.cachedAt) < v.cfg.CacheTTL {
		return v.cachedSet, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.COSEKeysURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/cose-key-set+cbor")
	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cose key set fetch returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	set, err := decodeCOSEKeySet(body)
	if err != nil {
		return nil, err
	}
	v.cachedSet = set
	v.cachedAt = time.Now()
	return set, nil
}

// --- CWT claims decoding -----------------------------------------------------

// decodeCWTClaims parses a CBOR claims map (RFC 8392 §3) into a string-keyed
// Go map suitable for downstream JWT serialization. Standard integer-label
// claims are renamed to their JWT equivalents.
func decodeCWTClaims(payload []byte) (map[string]any, error) {
	var generic map[any]any
	if err := cbor.Unmarshal(payload, &generic); err != nil {
		return nil, err
	}
	out := make(map[string]any, len(generic))
	for k, v := range generic {
		switch key := k.(type) {
		case int64:
			name, ok := cwtIntLabelToName(key)
			if !ok {
				out["cwt:"+strconv.FormatInt(key, 10)] = normalizeCBOR(v)
				continue
			}
			out[name] = normalizeCBOR(v)
		case uint64:
			name, ok := cwtIntLabelToName(int64(key))
			if !ok {
				out["cwt:"+strconv.FormatUint(key, 10)] = normalizeCBOR(v)
				continue
			}
			out[name] = normalizeCBOR(v)
		case string:
			out[key] = normalizeCBOR(v)
		default:
			// Unknown key type — skip.
		}
	}
	// `cti` (label 7) is bytes; surface as base64url so it survives JSON.
	if cti, ok := out["cti"].([]byte); ok {
		out["cti"] = base64.RawURLEncoding.EncodeToString(cti)
	}
	// `jti` is the JWT equivalent of cti; populate both for compatibility.
	if _, hasCti := out["cti"]; hasCti {
		if _, hasJti := out["jti"]; !hasJti {
			out["jti"] = out["cti"]
		}
	}
	return out, nil
}

// cwtIntLabelToName maps CWT integer claim labels (RFC 8392 §4) to JWT
// claim names so downstream code can read them with familiar keys.
func cwtIntLabelToName(label int64) (string, bool) {
	switch label {
	case cwtLabelIss:
		return "iss", true
	case cwtLabelSub:
		return "sub", true
	case cwtLabelAud:
		return "aud", true
	case cwtLabelExp:
		return "exp", true
	case cwtLabelNbf:
		return "nbf", true
	case cwtLabelIat:
		return "iat", true
	case cwtLabelCti:
		return "cti", true
	case cwtLabelCnf:
		return "cnf", true
	default:
		return "", false
	}
}

// normalizeCBOR converts the CBOR generic types (map[any]any, []any with
// int64 / uint64 / []byte / string elements) into Go-idiomatic types
// (map[string]any, []any) so json.Marshal produces sensible output.
func normalizeCBOR(v any) any {
	switch x := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, vv := range x {
			switch key := k.(type) {
			case string:
				m[key] = normalizeCBOR(vv)
			case int64:
				m[strconv.FormatInt(key, 10)] = normalizeCBOR(vv)
			case uint64:
				m[strconv.FormatUint(key, 10)] = normalizeCBOR(vv)
			}
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeCBOR(e)
		}
		return out
	case uint64:
		return int64(x)
	default:
		return v
	}
}

// --- unsigned JWT bridge -----------------------------------------------------

// encodeUnsignedJWT serializes the claims map as an alg=none JWT
// (`base64url(header).base64url(claims).`). The claims-mode ERS parses with
// `jwt.WithVerify(false)`, so an unsigned representation is the cheapest
// safe bridge from a verified CWT to the existing JWT-shaped pipeline.
func encodeUnsignedJWT(claims map[string]any) (string, error) {
	header := `{"alg":"none","typ":"JWT"}`
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(header)) +
		"." + base64.RawURLEncoding.EncodeToString(body) +
		".", nil
}

// claimsToJWTToken hydrates a jwt.Token from the JSON-shaped claims map.
func claimsToJWTToken(claims map[string]any) (jwt.Token, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	tok, err := jwt.Parse(body, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// --- COSE Key Set decoding ---------------------------------------------------

// coseEC2Key is the subset of an RFC 9052 COSE_Key (EC2) we use. The
// platform only needs the public coordinates to build an *ecdsa.PublicKey.
type coseEC2Key struct {
	kid []byte
	x   *big.Int
	y   *big.Int
	crv elliptic.Curve
}

func (k coseEC2Key) toECDSA() (*ecdsa.PublicKey, error) {
	if k.x == nil || k.y == nil || k.crv == nil {
		return nil, errors.New("incomplete EC2 key")
	}
	return &ecdsa.PublicKey{Curve: k.crv, X: k.x, Y: k.y}, nil
}

// decodeCOSEKeySet parses a COSE Key Set per RFC 9052 §7 — a CBOR array of
// COSE_Keys. Only EC2 (kty=2) keys on P-256 are returned today; other key
// types are silently skipped.
func decodeCOSEKeySet(payload []byte) ([]coseEC2Key, error) {
	var raw []map[int64]any
	if err := cbor.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("cbor decode COSE Key Set: %w", err)
	}
	out := make([]coseEC2Key, 0, len(raw))
	for _, m := range raw {
		key, ok := parseCOSEEC2Key(m)
		if !ok {
			continue
		}
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, errors.New("COSE Key Set contains no usable EC2 P-256 keys")
	}
	return out, nil
}

func parseCOSEEC2Key(m map[int64]any) (coseEC2Key, bool) {
	kty, _ := claimInt64(m[coseKeyLabelKty])
	if kty != coseKtyEC2 {
		return coseEC2Key{}, false
	}
	crvLabel, _ := claimInt64(m[coseKeyLabelCrv])
	var curve elliptic.Curve
	switch crvLabel {
	case coseCrvP256:
		curve = elliptic.P256()
	default:
		return coseEC2Key{}, false
	}
	xBytes, _ := m[coseKeyLabelX].([]byte)
	yBytes, _ := m[coseKeyLabelY].([]byte)
	if len(xBytes) == 0 || len(yBytes) == 0 {
		return coseEC2Key{}, false
	}
	kid, _ := m[coseKeyLabelKid].([]byte)
	return coseEC2Key{
		kid: kid,
		x:   new(big.Int).SetBytes(xBytes),
		y:   new(big.Int).SetBytes(yBytes),
		crv: curve,
	}, true
}

// --- small helpers -----------------------------------------------------------

func claimInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case uint64:
		return int64(x), true
	case int:
		return int64(x), true
	case float64:
		return int64(x), true
	default:
		return 0, false
	}
}

func audienceContains(claim any, want string) bool {
	switch x := claim.(type) {
	case string:
		return x == want
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range x {
			if s == want {
				return true
			}
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
