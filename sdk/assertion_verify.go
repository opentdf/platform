package sdk

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
)

// This file implements assertion verification under the ZTDF assertions
// specification, Sections 5 to 8. The verification key always comes from
// the reader's configuration or, when nothing is configured, from the
// payload key. A key embedded in the binding's JWS header (jwk or x5c) can
// only be checked against that key; it is never used to verify, and the
// header never chooses the algorithm. The JWS is checked here rather than by
// a JOSE library so that no header can select or fetch a key.

// JWK key types (RFC 7518 Section 6.1, RFC 8037).
const (
	ktyRSA = "RSA"
	ktyEC  = "EC"
	ktyOKP = "OKP"
)

// jwsCompactParts is the number of parts in a JWS compact serialization.
const jwsCompactParts = 3

// jwsHeaderCapture keeps the header members and their values, including the
// members of an embedded jwk and the entries of an embedded x5c.
const jwsHeaderCapture = 3

// jwsPayloadCapture keeps the claims and their values.
const jwsPayloadCapture = 2

// assertionVerifier is a configured or payload key, checked and normalized
// for one algorithm.
type assertionVerifier struct {
	alg     AssertionKeyAlg
	hmacKey []byte
	rsaKey  *rsa.PublicKey
}

// newAssertionVerifier checks that key can verify bindings with its
// algorithm. The error never includes key material.
func newAssertionVerifier(key AssertionKey) (assertionVerifier, error) {
	if isNilKey(key.Key) {
		return assertionVerifier{}, errors.New("verification key is empty")
	}
	switch key.Alg {
	case AssertionKeyAlgHS256:
		secret, err := hmacSecretFrom(key.Key)
		if err != nil {
			return assertionVerifier{}, err
		}
		return assertionVerifier{alg: key.Alg, hmacKey: secret}, nil
	case AssertionKeyAlgRS256:
		pub, err := rsaPublicKeyFrom(key.Key)
		if err != nil {
			return assertionVerifier{}, err
		}
		return assertionVerifier{alg: key.Alg, rsaKey: pub}, nil
	default:
		return assertionVerifier{}, fmt.Errorf("unsupported verification algorithm %q", key.Alg)
	}
}

// newConfiguredVerifier is newAssertionVerifier for a key the caller
// configured. Such a key must also not be PEM text used as an HS256 secret,
// so that public-key bytes are never accepted as an HMAC key (spec Section 7).
func newConfiguredVerifier(key AssertionKey) (assertionVerifier, error) {
	v, err := newAssertionVerifier(key)
	if err != nil {
		return assertionVerifier{}, err
	}
	if v.alg == AssertionKeyAlgHS256 && bytes.Contains(v.hmacKey, []byte("-----BEGIN")) {
		return assertionVerifier{}, errors.New("HS256 verification key is PEM text, not a shared secret")
	}
	return v, nil
}

// isNilKey reports whether k is nil or a nil pointer, which would otherwise
// panic when a key method is called on it.
func isNilKey(k any) bool {
	if k == nil {
		return true
	}
	v := reflect.ValueOf(k)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// hmacSecretFrom accepts what the SDK has always accepted for HS256: the
// secret bytes, or a symmetric jwk.Key. Public-key material is refused.
func hmacSecretFrom(k any) ([]byte, error) {
	switch v := k.(type) {
	case []byte:
		if len(v) == 0 {
			return nil, errors.New("HS256 verification key is empty")
		}
		return v, nil
	case jwk.Key:
		if v.KeyType() != jwa.OctetSeq {
			return nil, fmt.Errorf("HS256 verification key is a %s JWK, not a symmetric key", v.KeyType())
		}
		var raw []byte
		if err := v.Raw(&raw); err != nil {
			return nil, errors.New("HS256 verification key: unreadable symmetric JWK")
		}
		return hmacSecretFrom(raw)
	default:
		return nil, fmt.Errorf("HS256 verification key has type %T, want []byte", k)
	}
}

// rsaPublicKeyFrom accepts what the SDK has always accepted for RS256: an RSA
// public or private key, by value or pointer, a crypto.Signer with an RSA
// public key, or an RSA jwk.Key.
func rsaPublicKeyFrom(k any) (*rsa.PublicKey, error) {
	var pub *rsa.PublicKey
	switch v := k.(type) {
	case *rsa.PublicKey:
		pub = v
	case rsa.PublicKey:
		pub = &v
	case *rsa.PrivateKey:
		pub = &v.PublicKey
	case rsa.PrivateKey:
		pub = &v.PublicKey
	case jwk.Key:
		raw, err := jwk.PublicRawKeyOf(v)
		if err != nil {
			return nil, errors.New("RS256 verification key: unreadable JWK")
		}
		if _, isJWK := raw.(jwk.Key); isJWK {
			return nil, errors.New("RS256 verification key: unreadable JWK")
		}
		return rsaPublicKeyFrom(raw)
	case crypto.Signer:
		if p, ok := v.Public().(*rsa.PublicKey); ok {
			pub = p
		} else {
			return nil, fmt.Errorf("RS256 verification key is a crypto.Signer with a %T public key", v.Public())
		}
	default:
		return nil, fmt.Errorf("RS256 verification key has type %T, want an RSA public key", k)
	}
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.E <= 1 {
		return nil, errors.New("RS256 verification key is empty or malformed")
	}
	return pub, nil
}

// verifySignature checks sig over input with the selected key and its
// configured algorithm, and nothing else.
func (v assertionVerifier) verifySignature(input, sig []byte) bool {
	switch v.alg {
	case AssertionKeyAlgHS256:
		mac := hmac.New(sha256.New, v.hmacKey)
		mac.Write(input)
		return hmac.Equal(mac.Sum(nil), sig)
	case AssertionKeyAlgRS256:
		digest := sha256.Sum256(input)
		return rsa.VerifyPKCS1v15(v.rsaKey, crypto.SHA256, digest[:], sig) == nil
	default:
		return false
	}
}

// selectVerifier selects the verification key for the assertion with the
// exact id under spec Section 6.1, once: the per-ID key, else the default
// key, else the payload key with HS256. A selected entry that cannot be used
// fails with configuration-error; no other source is tried.
func (k AssertionVerificationKeys) selectVerifier(id string, payloadKey []byte) (assertionVerifier, error) {
	key, err := k.Get(id)
	if err != nil {
		return assertionVerifier{}, err
	}
	if key.IsEmpty() {
		key = AssertionKey{Alg: AssertionKeyAlgHS256, Key: payloadKey}
	}
	v, err := newAssertionVerifier(key)
	if err != nil {
		return assertionVerifier{}, assertionFailureCause(id, AssertionReasonConfigurationError, "verification key", err)
	}
	return v, nil
}

// verifyManifestAssertion verifies one manifest assertion under spec
// Section 8, step 3: the exact id, key selection, then the binding.
func verifyManifestAssertion(keys AssertionVerificationKeys, a Assertion, payloadKey, aggregateHash []byte, legacy bool) error {
	w, err := a.wire()
	if err != nil {
		return err
	}
	id, ok := w.exactID()
	if !ok {
		return assertionFailure("", AssertionReasonInvalidID, "assertion id must be a nonempty JSON string")
	}
	v, err := keys.selectVerifier(id, payloadKey)
	if err != nil {
		return err
	}
	return w.verify(id, v, aggregateHash, legacy)
}

// verify runs spec Section 8 steps 3.3 to 3.9 with an already selected key.
func (w *assertionWire) verify(id string, v assertionVerifier, aggregateHash []byte, legacy bool) error {
	compact, err := w.jwsBinding(id)
	if err != nil {
		return err
	}
	hashClaim, sigClaim, err := verifyBindingJWS(id, compact, v)
	if err != nil {
		return err
	}
	computed, err := w.hash()
	if err != nil {
		return err
	}
	if hashClaim != computed {
		return assertionFailure(id, AssertionReasonBindingMismatch, "assertionHash does not match the assertion")
	}
	expected, err := assertionSigFor(aggregateHash, computed, legacy)
	if err != nil {
		return assertionFailureCause(id, AssertionReasonBindingMismatch, "computing assertionSig", err)
	}
	if sigClaim != expected {
		return assertionFailure(id, AssertionReasonBindingMismatch, "failed integrity check on assertionSig")
	}
	return nil
}

// assertionSigFor returns the expected assertionSig claim (spec Section 5.3):
// standard base64 of the aggregate hash followed by the assertion hash, as
// raw bytes or, under the legacy encoding, as its hex text.
func assertionSigFor(aggregateHash []byte, hashHex string, legacy bool) (string, error) {
	h := []byte(hashHex)
	if !legacy {
		var err error
		if h, err = hex.DecodeString(hashHex); err != nil {
			return "", err
		}
	}
	complete := make([]byte, 0, len(aggregateHash)+len(h))
	complete = append(complete, aggregateHash...)
	complete = append(complete, h...)
	return string(ocrypto.Base64Encode(complete)), nil
}

// jwsBinding determines the binding form under spec Section 5.1 and returns
// the compact JWS of a JWS binding.
func (w *assertionWire) jwsBinding(id string) (string, error) {
	b, ok := w.root.member(bindingMember)
	switch {
	case !ok:
		return "", assertionFailure(id, AssertionReasonInvalidBinding, "assertion has no binding")
	case b.kind != jsonObject:
		return "", assertionFailure(id, AssertionReasonInvalidBinding, "binding is not a JSON object")
	}
	sig, hasSig := b.member("signature")
	_, hasBDO := b.member("bdo")
	switch {
	case hasSig && hasBDO:
		return "", assertionFailure(id, AssertionReasonInvalidBinding, "binding has both a signature and a bdo")
	case !hasSig && !hasBDO:
		return "", assertionFailure(id, AssertionReasonInvalidBinding, "binding has neither a signature nor a bdo")
	case hasBDO:
		return "", assertionFailure(id, AssertionReasonUnsupportedBinding, "STANAG 4778 binding objects are not supported")
	}
	method, hasMethod := b.member("method")
	if hasMethod && method.kind != jsonString {
		return "", assertionFailure(id, AssertionReasonInvalidBinding, "binding method is not a string")
	}
	if sig.kind != jsonString {
		return "", assertionFailure(id, AssertionReasonInvalidBinding, "binding signature is not a string")
	}
	// A missing method means jws. Java writers emit JWS.
	if hasMethod && method.str != JWS.String() && method.str != "JWS" {
		return "", assertionFailure(id, AssertionReasonUnsupportedBinding, fmt.Sprintf("binding method %q is not supported", method.str))
	}
	return sig.str, nil
}

// decodeJOSESegment decodes one base64url part of a compact JWS.
func decodeJOSESegment(s string) ([]byte, error) {
	return decodeBase64URLStrict(s)
}

// decodeBase64URLStrict decodes unpadded base64url (RFC 7515 Section 2),
// refusing padding, whitespace, line breaks, the standard alphabet, and
// non-zero trailing bits, so each value has exactly one encoding.
func decodeBase64URLStrict(s string) ([]byte, error) {
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return nil, errors.New("not unpadded base64url")
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// decodeBase64Strict decodes padded standard base64 (RFC 4648 Section 4), as
// x5c entries use, refusing whitespace, line breaks, and non-zero trailing
// bits.
func decodeBase64Strict(s string) ([]byte, error) {
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
		default:
			return nil, errors.New("not base64")
		}
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

// parseJOSEObject decodes a base64url JWS part that must hold a JSON object.
// Duplicate members are refused, as RFC 7515 Section 4 allows.
func parseJOSEObject(part string, capture int) (jsonNode, error) {
	data, err := decodeJOSESegment(part)
	if err != nil {
		return jsonNode{}, errors.New("not base64url")
	}
	node, err := parseStrictJSON(data, levelOther, capture)
	var se *jsonSyntaxError
	switch {
	case errors.As(err, &se):
		return jsonNode{}, errors.New("not JSON")
	case err != nil:
		// Outside assertion objects the scanner reports only duplicate
		// members and invalid UTF-8.
		var failure ErrAssertionFailure
		if errors.As(err, &failure) && failure.Reason == AssertionReasonInvalidJSON {
			return jsonNode{}, errors.New("not UTF-8")
		}
		return jsonNode{}, errors.New("duplicate member names")
	}
	if node.kind != jsonObject {
		return jsonNode{}, errors.New("not a JSON object")
	}
	return node, nil
}

// verifyBindingJWS runs spec Section 8 steps 3.4 to 3.7 on a compact JWS: its
// structure and header, embedded keys, the signature under v, and the claims.
// It returns the assertionHash and assertionSig claims.
func verifyBindingJWS(id, compact string, v assertionVerifier) (string, string, error) {
	// Step 3.4: structure and header.
	if strings.HasPrefix(strings.TrimSpace(compact), "{") {
		return "", "", assertionFailure(id, AssertionReasonInvalidBinding, "JWS JSON serialization is not supported")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != jwsCompactParts {
		return "", "", assertionFailure(id, AssertionReasonInvalidBinding, "binding is not a JWS compact serialization")
	}
	header, err := parseJOSEObject(parts[0], jwsHeaderCapture)
	if err != nil {
		return "", "", assertionFailureCause(id, AssertionReasonInvalidBinding, "JWS protected header", err)
	}
	payload, err := parseJOSEObject(parts[1], jwsPayloadCapture)
	if err != nil {
		return "", "", assertionFailureCause(id, AssertionReasonInvalidBinding, "JWS payload", err)
	}
	if _, ok := header.member("crit"); ok {
		return "", "", assertionFailure(id, AssertionReasonInvalidBinding, "JWS crit header is not supported")
	}
	alg, ok := header.member("alg")
	if !ok || alg.kind != jsonString {
		return "", "", assertionFailure(id, AssertionReasonUnsupportedAlgorithm, "JWS alg header is missing or not a string")
	}
	if alg.str != string(AssertionKeyAlgRS256) && alg.str != string(AssertionKeyAlgHS256) {
		return "", "", assertionFailure(id, AssertionReasonUnsupportedAlgorithm, fmt.Sprintf("JWS alg %q is not supported", alg.str))
	}
	if alg.str != string(v.alg) {
		return "", "", assertionFailure(id, AssertionReasonAlgorithmMismatch,
			fmt.Sprintf("JWS alg %s does not match the selected key's %s", alg.str, v.alg))
	}

	// Step 3.5: embedded keys may only match the selected key.
	if err := checkEmbeddedKeys(id, header, v); err != nil {
		return "", "", err
	}

	// Step 3.6: the signature, with the selected key and its algorithm. A
	// signature that does not decode does not verify.
	signature, err := decodeJOSESegment(parts[2])
	if err != nil || !v.verifySignature([]byte(parts[0]+"."+parts[1]), signature) {
		return "", "", assertionFailure(id, AssertionReasonSignatureInvalid, "failed integrity check on the binding signature with the selected key")
	}

	// Step 3.7: the claims. Other claims are ignored.
	hashClaim, ok := payload.member(kAssertionHash)
	if !ok || hashClaim.kind != jsonString {
		return "", "", assertionFailure(id, AssertionReasonBindingMismatch, "assertionHash claim is missing or not a string")
	}
	sigClaim, ok := payload.member(kAssertionSignature)
	if !ok || sigClaim.kind != jsonString {
		return "", "", assertionFailure(id, AssertionReasonBindingMismatch, "assertionSig claim is missing or not a string")
	}
	return hashClaim.str, sigClaim.str, nil
}

// checkEmbeddedKeys applies spec Section 6.2 to the jwk and x5c headers.
func checkEmbeddedKeys(id string, header jsonNode, v assertionVerifier) error {
	jwkNode, hasJWK := header.member("jwk")
	x5cNode, hasX5C := header.member("x5c")
	if !hasJWK && !hasX5C {
		return nil
	}
	if v.alg == AssertionKeyAlgHS256 {
		return assertionFailure(id, AssertionReasonInvalidEmbeddedKey, "an embedded jwk or x5c is not allowed with an HMAC key")
	}

	var embedded []byte
	if hasJWK {
		tp, err := embeddedJWKThumbprint(jwkNode)
		if err != nil {
			return assertionFailureCause(id, AssertionReasonInvalidEmbeddedKey, "embedded jwk", err)
		}
		embedded = tp
	}
	if hasX5C {
		tp, err := embeddedX5CThumbprint(x5cNode)
		if err != nil {
			return assertionFailureCause(id, AssertionReasonInvalidEmbeddedKey, "embedded x5c", err)
		}
		if embedded != nil && !bytes.Equal(embedded, tp) {
			return assertionFailure(id, AssertionReasonInvalidEmbeddedKey, "embedded jwk and x5c hold different public keys")
		}
		embedded = tp
	}

	if !bytes.Equal(embedded, rsaThumbprint(v.rsaKey.N, big.NewInt(int64(v.rsaKey.E)))) {
		return assertionFailure(id, AssertionReasonSignerNotPermitted, "embedded key is not the configured verification key")
	}
	return nil
}

// rsaThumbprint is the RFC 7638 SHA-256 thumbprint of an RSA public key: the
// hash of its required members, in lexical order, as unpadded base64url of
// the minimal big-endian integers.
func rsaThumbprint(n, e *big.Int) []byte {
	return jwkThumbprint(map[string]string{
		"e": base64.RawURLEncoding.EncodeToString(e.Bytes()), "kty": ktyRSA,
		"n": base64.RawURLEncoding.EncodeToString(n.Bytes()),
	})
}

// publicKeyThumbprint is the RFC 7638 thumbprint of the public key of a
// certificate, computed the same way as for an embedded jwk. A key with no
// such JWK form gets a digest of its SPKI instead, which cannot equal any
// thumbprint.
func publicKeyThumbprint(cert *x509.Certificate) []byte {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsaThumbprint(pub.N, big.NewInt(int64(pub.E)))
	case *ecdsa.PublicKey:
		if point, err := pub.ECDH(); err == nil {
			raw := point.Bytes()       // 0x04 || x || y
			size := (len(raw) - 1) / 2 //nolint:mnd // two coordinates
			return jwkThumbprint(map[string]string{
				"crv": pub.Curve.Params().Name, "kty": ktyEC,
				"x": base64.RawURLEncoding.EncodeToString(raw[1 : 1+size]),
				"y": base64.RawURLEncoding.EncodeToString(raw[1+size:]),
			})
		}
	case ed25519.PublicKey:
		return jwkThumbprint(map[string]string{"crv": "Ed25519", "kty": ktyOKP, "x": base64.RawURLEncoding.EncodeToString(pub)})
	}
	sum := sha256.Sum256(append([]byte("SPKI:"), cert.RawSubjectPublicKeyInfo...))
	return sum[:]
}

// embeddedJWKThumbprint returns the RFC 7638 thumbprint of an embedded jwk,
// refusing symmetric and private keys and malformed RSA keys.
func embeddedJWKThumbprint(node jsonNode) ([]byte, error) {
	if node.kind != jsonObject {
		return nil, errors.New("not a JSON object")
	}
	kty, ok := node.member("kty")
	if !ok || kty.kind != jsonString {
		return nil, errors.New("kty is missing or not a string")
	}
	if kty.str == "oct" {
		return nil, errors.New("symmetric keys are not allowed")
	}
	// Members that carry private key material (RFC 7518 Section 6).
	for _, name := range [...]string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
		if _, private := node.member(name); private {
			return nil, fmt.Errorf("private member %q is not allowed", name)
		}
	}
	switch kty.str {
	case ktyRSA:
		n, err := jwkUint(node, "n")
		if err != nil {
			return nil, err
		}
		e, err := jwkUint(node, "e")
		if err != nil {
			return nil, err
		}
		return rsaThumbprint(n, e), nil
	case ktyEC:
		return ecThumbprint(node)
	case ktyOKP:
		return okpThumbprint(node)
	default:
		return nil, fmt.Errorf("unsupported kty %q", kty.str)
	}
}

// jwkBytes reads a base64url-encoded JWK member: a nonempty string in strict
// unpadded base64url.
func jwkBytes(node jsonNode, name string) ([]byte, error) {
	v, ok := node.member(name)
	if !ok || v.kind != jsonString {
		return nil, fmt.Errorf("%q is missing or not a string", name)
	}
	b, err := decodeBase64URLStrict(v.str)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("%q is not strict base64url", name)
	}
	return b, nil
}

// jwkUint reads an RSA JWK integer member, which RFC 7518 Section 6.3.1
// encodes in the minimum number of octets: a leading zero octet is refused,
// so no other spelling of the configured key can compare equal to it.
func jwkUint(node jsonNode, name string) (*big.Int, error) {
	b, err := jwkBytes(node, name)
	if err != nil {
		return nil, err
	}
	if b[0] == 0 {
		return nil, fmt.Errorf("%q has a leading zero octet", name)
	}
	return new(big.Int).SetBytes(b), nil
}

// ecThumbprint returns the RFC 7638 thumbprint of an EC JWK, which is well
// formed only on P-256, P-384 or P-521, with x and y exactly the curve's
// coordinate length (RFC 7518 Section 6.2.1.2) and the point on the curve.
func ecThumbprint(node jsonNode) ([]byte, error) {
	crv, ok := node.member("crv")
	if !ok || crv.kind != jsonString {
		return nil, errors.New(`"crv" is missing or not a string`)
	}
	var curve ecdh.Curve
	var size int
	switch crv.str {
	case "P-256":
		curve, size = ecdh.P256(), 32
	case "P-384":
		curve, size = ecdh.P384(), 48
	case "P-521":
		curve, size = ecdh.P521(), 66
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", crv.str)
	}
	x, err := jwkBytes(node, "x")
	if err != nil {
		return nil, err
	}
	y, err := jwkBytes(node, "y")
	if err != nil {
		return nil, err
	}
	if len(x) != size || len(y) != size {
		return nil, fmt.Errorf("coordinates are not the %d octets that %s requires", size, crv.str)
	}
	// NewPublicKey refuses a point that is not on the curve.
	point := append(append([]byte{4}, x...), y...)
	if _, err := curve.NewPublicKey(point); err != nil {
		return nil, errors.New("point is not on the curve")
	}
	return jwkThumbprint(map[string]string{
		"crv": crv.str, "kty": ktyEC,
		"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y),
	}), nil
}

// okpThumbprint returns the RFC 7638 thumbprint of an OKP JWK, which is well
// formed only for Ed25519 or Ed448 with x exactly the key length (RFC 8037).
func okpThumbprint(node jsonNode) ([]byte, error) {
	crv, ok := node.member("crv")
	if !ok || crv.kind != jsonString {
		return nil, errors.New(`"crv" is missing or not a string`)
	}
	var size int
	switch crv.str {
	case "Ed25519":
		size = 32
	case "Ed448":
		size = 57
	default:
		return nil, fmt.Errorf("unsupported OKP curve %q", crv.str)
	}
	x, err := jwkBytes(node, "x")
	if err != nil {
		return nil, err
	}
	if len(x) != size {
		return nil, fmt.Errorf("x is not the %d octets that %s requires", size, crv.str)
	}
	return jwkThumbprint(map[string]string{"crv": crv.str, "kty": ktyOKP, "x": base64.RawURLEncoding.EncodeToString(x)}), nil
}

// jwkThumbprint is the RFC 7638 SHA-256 thumbprint of a JWK's required
// members: their JSON object with names in lexical order and no whitespace.
// encoding/json writes map keys sorted, and every value here is ASCII.
func jwkThumbprint(required map[string]string) []byte {
	members, err := json.Marshal(required)
	if err != nil {
		panic(err) // a map of strings always encodes
	}
	sum := sha256.Sum256(members)
	return sum[:]
}

// embeddedX5CThumbprint returns the RFC 7638 thumbprint of the public key of
// the leaf certificate of an embedded x5c. Every entry must be padded
// standard base64 (RFC 7515 Section 4.1.6); only the leaf is parsed as a
// certificate. The rest of the chain is not validated and grants nothing.
func embeddedX5CThumbprint(node jsonNode) ([]byte, error) {
	if node.kind != jsonArray || len(node.elems) == 0 {
		return nil, errors.New("not a nonempty array")
	}
	var leafDER []byte
	for i, e := range node.elems {
		if e.kind != jsonString {
			return nil, fmt.Errorf("entry %d is not a string", i)
		}
		der, err := decodeBase64Strict(e.str)
		if err != nil {
			return nil, fmt.Errorf("entry %d is not padded standard base64", i)
		}
		if i == 0 {
			leafDER = der
		}
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, errors.New("leaf certificate is not parseable")
	}
	return publicKeyThumbprint(leaf), nil
}
