package sdk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	SystemMetadataAssertionID = "system-metadata"
	SystemMetadataSchemaV1    = "system-metadata-v1"
)

// AssertionConfig is a shadow of Assertion with the addition of the signing key.
// It is used on creation
type AssertionConfig struct {
	ID             string         `validate:"required"`
	Type           AssertionType  `validate:"required"`
	Scope          Scope          `validate:"required"`
	AppliesToState AppliesToState `validate:"required"`
	Statement      Statement
	SigningKey     AssertionKey
}

// Assertion is one entry of a manifest's assertions array.
//
// An Assertion decoded from JSON also keeps the exact bytes it was decoded
// from. Hashing and verification use those bytes, as the ZTDF assertions
// specification requires, so members this type does not model are covered
// and an object-valued statement value is hashed as an object. Changing the
// fields of a decoded Assertion therefore does not change its hash or what
// it verifies. The typed fields are a view of the received object: ID is
// empty when the received id is not a JSON string, and Binding is empty when
// the received binding is not an object holding string members.
type Assertion struct {
	ID             string         `json:"id"`
	Type           AssertionType  `json:"type"`
	Scope          Scope          `json:"scope"`
	AppliesToState AppliesToState `json:"appliesToState,omitempty"`
	Statement      Statement      `json:"statement"`
	Binding        Binding        `json:"binding,omitempty"`

	// raw is the JSON this assertion was decoded from, or nil for an
	// assertion built in code.
	raw []byte
}

// UnmarshalJSON decodes an assertion and keeps a copy of data, the assertion
// as received, for hashing and verification.
//
// The id and binding members are decoded leniently: a value of the wrong JSON
// type leaves the typed field empty instead of failing, so that a manifest
// with such an assertion can still be loaded with verification disabled, and
// verification reports the problem with its own reason.
func (a *Assertion) UnmarshalJSON(data []byte) error {
	// encoding/json passes null to non-pointer values; by convention, a no-op
	// for the typed fields. Keep it as received so verification sees it.
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		a.raw = []byte("null")
		return nil
	}

	type assertionFields Assertion // no methods, so no recursion
	aux := struct {
		ID      json.RawMessage `json:"id"`
		Binding json.RawMessage `json:"binding"`
		*assertionFields
	}{assertionFields: (*assertionFields)(a)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	a.ID = jsonStringOrEmpty(aux.ID)
	a.Binding = lenientBinding(aux.Binding)
	a.raw = bytes.Clone(data)
	return nil
}

// lenientBinding returns the typed view of a binding member: its method and
// signature when they are strings, and nothing for any other value.
func lenientBinding(raw json.RawMessage) Binding {
	var fields struct {
		Method    json.RawMessage `json:"method"`
		Signature json.RawMessage `json:"signature"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Binding{}
	}
	return Binding{Method: jsonStringOrEmpty(fields.Method), Signature: jsonStringOrEmpty(fields.Signature)}
}

// signAssertions builds and signs the manifest assertion list.
//
// Each assertion is bound to the payload by signing the aggregate hash of all
// segment hashes followed by the assertion's own hash. Pre-4.3.0 writers append
// the hex form of the assertion hash rather than its raw bytes, so useHex
// selects between the two encodings.
//
// Assertions are signed with HS256 over defaultKey unless the config supplies
// its own signing key. Returns nil when there are no assertions to sign.
func signAssertions(aggregateHash []byte, configs []AssertionConfig, defaultKey []byte, useHex bool) ([]Assertion, error) {
	var signed []Assertion
	for _, assertion := range configs {
		// Hash the wire object this writer emits, minus its binding, with
		// the same function readers use. The manifest serializes the same
		// struct, so the bytes written are the bytes hashed.
		tmpAssertion, wireJSON, err := writableAssertion(assertion)
		if err != nil {
			return nil, err
		}
		hashHex, err := ComputeAssertionHash(wireJSON)
		if err != nil {
			return nil, err
		}
		hashOfAssertionAsHex := []byte(hashHex)

		hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
		if _, err := hex.Decode(hashOfAssertion, hashOfAssertionAsHex); err != nil {
			return nil, fmt.Errorf("error decoding hex string: %w", err)
		}

		completeHash := make([]byte, 0, len(aggregateHash)+len(hashOfAssertionAsHex))
		completeHash = append(completeHash, aggregateHash...)
		if useHex {
			completeHash = append(completeHash, hashOfAssertionAsHex...)
		} else {
			completeHash = append(completeHash, hashOfAssertion...)
		}

		encoded := ocrypto.Base64Encode(completeHash)

		// Default to HS256 over the payload key unless the caller supplied a key.
		assertionSigningKey := AssertionKey{
			Alg: AssertionKeyAlgHS256,
			Key: defaultKey,
		}
		if !assertion.SigningKey.IsEmpty() {
			assertionSigningKey = assertion.SigningKey
		}

		if err := tmpAssertion.Sign(string(hashOfAssertionAsHex), string(encoded), assertionSigningKey); err != nil {
			return nil, fmt.Errorf("failed to sign assertion: %w", err)
		}

		signed = append(signed, tmpAssertion)
	}
	return signed, nil
}

// writableAssertion returns the unsigned assertion a writer emits for config, and
// its JSON. It refuses, with ErrInvalidAssertion, an assertion that readers
// would reject while parsing it: an empty id (spec Section 3.3), or JSON that
// breaks the Section 3 rules, such as a string holding a noncharacter.
func writableAssertion(config AssertionConfig) (Assertion, []byte, error) {
	a := Assertion{
		ID:             config.ID,
		Type:           config.Type,
		Scope:          config.Scope,
		Statement:      config.Statement,
		AppliesToState: config.AppliesToState,
	}
	wireJSON, err := json.Marshal(a)
	if err != nil {
		return Assertion{}, nil, fmt.Errorf("%w: encoding assertion %q: %w", ErrInvalidAssertion, config.ID, err)
	}
	w, err := parseAssertionWire(wireJSON)
	if err != nil {
		return Assertion{}, nil, fmt.Errorf("%w: assertion %q: %s", ErrInvalidAssertion, config.ID, failureDetail(err))
	}
	if _, ok := w.exactID(); !ok {
		return Assertion{}, nil, fmt.Errorf("%w: assertion id must be a nonempty string", ErrInvalidAssertion)
	}
	return a, wireJSON, nil
}

// failureDetail describes an ErrAssertionFailure without its tamper wording,
// for errors that are not about a received TDF.
func failureDetail(err error) string {
	var failure ErrAssertionFailure
	if !errors.As(err, &failure) {
		return err.Error()
	}
	detail := strings.TrimPrefix(err.Error(), failure.Error()+": ")
	return fmt.Sprintf("%s (%s)", detail, failure.Reason)
}

// Sign signs the assertion with the given hash and signature using the key.
// It returns an error if the signing fails.
// The assertion binding is updated with the method and the signature.
func (a *Assertion) Sign(hash, sig string, key AssertionKey) error {
	tok := jwt.New()
	if err := tok.Set(kAssertionHash, hash); err != nil {
		return fmt.Errorf("failed to set assertion hash: %w", err)
	}
	if err := tok.Set(kAssertionSignature, sig); err != nil {
		return fmt.Errorf("failed to set assertion signature: %w", err)
	}

	// sign the hash and signature
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key))
	if err != nil {
		return fmt.Errorf("signing assertion failed: %w", err)
	}

	// set the binding
	a.Binding.Method = JWS.String()
	a.Binding.Signature = string(signedTok)

	return nil
}

// Verify checks the binding signature of the assertion and
// returns the hash and the signature. It returns an error if the verification fails.
func (a Assertion) Verify(key AssertionKey) (string, string, error) {
	parseOptions := []jwt.ParseOption{
		jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key),
	}

	// Try to get a key from the JWS protected header if it exists
	if decodedSig, err := jws.Parse([]byte(a.Binding.Signature)); err == nil && len(decodedSig.Signatures()) > 0 { //nolint:nestif // many keys
		sig := decodedSig.Signatures()[0]
		// First, try to get a JWK from the header
		if jwkKey := sig.ProtectedHeaders().JWK(); jwkKey != nil {
			var rawKey interface{}
			if err := jwkKey.Raw(&rawKey); err == nil {
				parseOptions = append(parseOptions, jwt.WithKey(sig.ProtectedHeaders().Algorithm(), rawKey))
			}
		}
		// Also try to get a key from x5c (certificate chain) header
		if x5cChain := sig.ProtectedHeaders().X509CertChain(); x5cChain != nil && x5cChain.Len() > 0 {
			// Get the first certificate (the signing certificate)
			certBytes, ok := x5cChain.Get(0)
			if ok {
				// Parse the certificate to extract the public key
				x509Cert, err := cert.Parse(certBytes)
				if err == nil && x509Cert != nil {
					parseOptions = append(parseOptions, jwt.WithKey(sig.ProtectedHeaders().Algorithm(), x509Cert.PublicKey))
				}
			}
		}
	}

	tok, err := jwt.Parse([]byte(a.Binding.Signature), parseOptions...)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", errAssertionVerifyKeyFailure, err)
	}
	hashClaim, found := tok.Get(kAssertionHash)
	if !found {
		return "", "", errors.New("hash claim not found")
	}
	hash, ok := hashClaim.(string)
	if !ok {
		return "", "", errors.New("hash claim is not a string")
	}

	sigClaim, found := tok.Get(kAssertionSignature)
	if !found {
		return "", "", errors.New("signature claim not found")
	}
	sig, ok := sigClaim.(string)
	if !ok {
		return "", "", errors.New("signature claim is not a string")
	}
	return hash, sig, nil
}

// GetHash returns the assertion's assertionHash in lowercase hex, computed
// as ComputeAssertionHash does. For an assertion decoded from JSON it hashes
// the bytes as received; for one built in code, the object this SDK writes.
// The binding is never part of the hash.
func (a Assertion) GetHash() ([]byte, error) {
	w, err := a.wire()
	if err != nil {
		return nil, err
	}
	h, err := w.hash()
	if err != nil {
		return nil, err
	}
	return []byte(h), nil
}

// wire returns the assertion as received or, for an assertion built in code,
// as this SDK writes it.
func (a Assertion) wire() (*assertionWire, error) {
	raw := a.raw
	if raw == nil {
		var err error
		if raw, err = json.Marshal(a); err != nil {
			return nil, assertionFailureCause(a.ID, AssertionReasonInvalidJSON, "encoding the assertion", err)
		}
	}
	return parseAssertionWire(raw)
}

var errAssertionVerifyKeyFailure = errors.New("assertion: failed to verify with provided key")

func (s *Statement) UnmarshalJSON(data []byte) error {
	// encoding/json passes null to non-pointer fields; by convention, a no-op.
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}

	// Define a custom struct for deserialization
	type Alias Statement
	aux := &struct {
		Value json.RawMessage `json:"value,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}

	// Not &aux: decoding null through a pointer-to-pointer would nil aux.
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// Attempt to decode Value as an object
	var temp map[string]interface{}
	if json.Unmarshal(aux.Value, &temp) == nil {
		// Re-encode the object as a string and assign to Value
		objAsString, err := json.Marshal(temp)
		if err != nil {
			return err
		}
		s.Value = string(objAsString)
	} else {
		// Assign raw string to Value
		var str string
		if err := json.Unmarshal(aux.Value, &str); err != nil {
			return fmt.Errorf("value is neither a valid JSON object nor a string: %s", string(aux.Value))
		}
		s.Value = str
	}

	return nil
}

// Statement includes information applying to the scope of the assertion.
// It could contain rights, handling instructions, or general metadata.
type Statement struct {
	// Format describes the payload encoding format. (e.g. json)
	Format string `json:"format,omitempty" validate:"required"`
	// Schema describes the schema of the payload. (e.g. tdf)
	Schema string `json:"schema,omitempty" validate:"required"`
	// Value is the payload of the assertion.
	Value string `json:"value,omitempty"  validate:"required"`
}

// Binding enforces cryptographic integrity of the assertion.
// So the can't be modified or copied to another tdf.
type Binding struct {
	// Method used to bind the assertion. (e.g. jws)
	Method string `json:"method,omitempty"`
	// Signature of the assertion.
	Signature string `json:"signature,omitempty"`
}

// AssertionType represents the type of the assertion.
type AssertionType string

const (
	HandlingAssertion AssertionType = "handling"
	BaseAssertion     AssertionType = "other"
)

// String returns the string representation of the assertion type.
func (at AssertionType) String() string {
	return string(at)
}

// Scope represents the object which the assertion applies to.
type Scope string

const (
	TrustedDataObjScope Scope = "tdo"
	PayloadScope        Scope = "payload"
)

// String returns the string representation of the scope.
func (s Scope) String() string {
	return string(s)
}

// AppliesToState indicates whether the assertion applies to encrypted or unencrypted data.
type AppliesToState string

const (
	Encrypted   AppliesToState = "encrypted"
	Unencrypted AppliesToState = "unencrypted"
)

// String returns the string representation of the applies to state.
func (ats AppliesToState) String() string {
	return string(ats)
}

// BindingMethod represents the method used to bind the assertion.
type BindingMethod string

const (
	JWS BindingMethod = "jws"
)

// String returns the string representation of the binding method.
func (bm BindingMethod) String() string {
	return string(bm)
}

// AssertionKeyAlg represents the algorithm of an assertion key.
type AssertionKeyAlg string

const (
	AssertionKeyAlgRS256 AssertionKeyAlg = "RS256"
	AssertionKeyAlgHS256 AssertionKeyAlg = "HS256"
)

// String returns the string representation of the algorithm.
func (a AssertionKeyAlg) String() string {
	return string(a)
}

// AssertionKey represents a key for assertions.
type AssertionKey struct {
	// Algorithm of the key.
	Alg AssertionKeyAlg
	// Key value. Can be raw key material or a crypto.Signer for hardware-backed keys (HSM/KMS).
	Key interface{}
}

// Algorithm returns the algorithm of the key.
func (k AssertionKey) Algorithm() AssertionKeyAlg {
	return k.Alg
}

// IsEmpty returns true if the key and the algorithm are empty.
func (k AssertionKey) IsEmpty() bool {
	return k.Key == nil && k.Alg == ""
}

// AssertionVerificationKeys represents the verification keys for assertions.
type AssertionVerificationKeys struct {
	// Default key to use if the key for the assertion ID is not found.
	DefaultKey AssertionKey
	// Map of assertion ID to key.
	Keys map[string]AssertionKey
}

// Get returns the key for the given assertion ID or the default key if the key is not found.
// If the default key is not set, it returns an empty key.
func (k AssertionVerificationKeys) Get(assertionID string) (AssertionKey, error) {
	if key, ok := k.Keys[assertionID]; ok {
		return key, nil
	}
	if k.DefaultKey.IsEmpty() {
		return AssertionKey{}, nil
	}
	return k.DefaultKey, nil
}

// IsEmpty returns true if the default key and the keys map are empty.
func (k AssertionVerificationKeys) IsEmpty() bool {
	return k.DefaultKey.IsEmpty() && len(k.Keys) == 0
}

// GetSystemMetadataAssertionConfig returns a default assertion configuration with predefined values.
func GetSystemMetadataAssertionConfig() (AssertionConfig, error) {
	// Define the JSON structure
	type Metadata struct {
		TDFSpecVersion string `json:"tdf_spec_version,omitempty"`
		CreationDate   string `json:"creation_date,omitempty"`
		OS             string `json:"operating_system,omitempty"`
		SDKVersion     string `json:"sdk_version,omitempty"`
		GoVersion      string `json:"go_version,omitempty"`
		Architecture   string `json:"architecture,omitempty"`
	}

	// Populate the metadata
	metadata := Metadata{
		TDFSpecVersion: TDFSpecVersion,
		CreationDate:   time.Now().Format(time.RFC3339),
		OS:             runtime.GOOS,
		SDKVersion:     "Go-" + Version,
		GoVersion:      runtime.Version(),
		Architecture:   runtime.GOARCH,
	}

	// Marshal the metadata to JSON
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return AssertionConfig{}, fmt.Errorf("failed to marshal system metadata: %w", err)
	}

	return AssertionConfig{
		ID:             SystemMetadataAssertionID,
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "json",
			Schema: SystemMetadataSchemaV1,
			Value:  string(metadataJSON),
		},
	}, nil
}
