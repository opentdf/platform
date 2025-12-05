package sdk

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gowebpki/jcs"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
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

type Assertion struct {
	ID             string         `json:"id"`
	Type           AssertionType  `json:"type"`
	Scope          Scope          `json:"scope"`
	AppliesToState AppliesToState `json:"appliesToState,omitempty"`
	Statement      Statement      `json:"statement"`
	Binding        Binding        `json:"binding,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for Assertion.
// It omits the binding field entirely when it's empty, rather than including it as {}.
func (a *Assertion) MarshalJSON() ([]byte, error) {
	type Alias Assertion
	if a.Binding.IsEmpty() {
		// Marshal without the binding field
		return json.Marshal(&struct {
			*Alias
			Binding *Binding `json:"binding,omitempty"`
		}{
			Alias:   (*Alias)(a),
			Binding: nil,
		})
	}
	// Marshal normally with binding
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(a),
	})
}

var errAssertionVerifyKeyFailure = errors.New("assertion: failed to verify with provided key")

// Sign signs the assertion with the given hash and signature using the key.
// It returns an error if the signing fails.
// The assertion binding is updated with the method and the signature.
// Optional JWS protected headers can be passed (e.g., for including public key as jwk).
func (a *Assertion) Sign(hash, sig string, key AssertionKey, headers ...jws.Headers) error {
	if key.IsEmpty() {
		return errors.New("signing key not configured")
	}
	// Configure JWT with assertion hash and signature claims
	tok := jwt.New()
	if err := tok.Set(kAssertionHash, hash); err != nil {
		return fmt.Errorf("failed to set assertion hash: %w", err)
	}
	// Note: sig is already base64-encoded when it comes from manifest.RootSignature.Signature
	// so we store it directly without additional encoding
	if err := tok.Set(kAssertionSignature, sig); err != nil {
		return fmt.Errorf("failed to set assertion signature: %w", err)
	}

	// TODO SECURITY: Add schema claim to cryptographically bind schema to assertion
	// This prevents schema substitution attacks where an attacker changes Statement.Schema
	// to route the assertion to a different validator with weaker security checks.
	// The schema is included in both the JWT (signed) and the Statement (hashed),
	// providing defense-in-depth against tampering.
	// if err := tok.Set("assertionSchema", a.Statement.Schema); err != nil {
	// 	return fmt.Errorf("failed to set assertion schema: %w", err)
	// }

	// Build signing options
	alg := jwa.KeyAlgorithmFrom(key.Alg.String())
	var signOpts []jwt.SignOption
	signOpts = append(signOpts, jwt.WithKey(alg, key.Key))

	// Add protected headers if provided (e.g., public key as jwk for RSA/ECC)
	if len(headers) > 0 {
		signOpts = append(signOpts, jwt.WithKey(alg, key.Key, jws.WithProtectedHeaders(headers[0])))
		signOpts = signOpts[1:] // Remove the first WithKey, keep only the one with headers
	}

	// Sign the token with the configured key
	signedTok, err := jwt.Sign(tok, signOpts...)
	if err != nil {
		return fmt.Errorf("signing assertion failed: %w", err)
	}

	// set the binding
	a.Binding.Method = JWS.String()
	a.Binding.Signature = string(signedTok)

	return nil
}

// Verify verifies the assertion binding signature using the given key.
// It returns the hash and signature claims from the assertion binding.
func (a *Assertion) Verify(key AssertionKey) ([]byte, []byte, error) {
	tok, err := jwt.Parse([]byte(a.Binding.Signature),
		jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errAssertionVerifyKeyFailure, err)
	}
	hashClaim, found := tok.Get(kAssertionHash)
	if !found {
		return nil, nil, errors.New("hash claim not found")
	}
	verifiedHash, ok := hashClaim.(string)
	if !ok {
		return nil, nil, errors.New("hash claim is not a string")
	}

	sigClaim, found := tok.Get(kAssertionSignature)
	if !found {
		return nil, nil, errors.New("signature claim not found")
	}
	verifiedSignature, ok := sigClaim.(string)
	if !ok {
		return nil, nil, errors.New("signature claim is not a string")
	}
	// Note: signature is stored as base64-encoded string (matching manifest.RootSignature.Signature format)
	// so we return it directly without decoding
	return []byte(verifiedHash), []byte(verifiedSignature), nil
}

// GetHash returns the hash of the assertion in hex format.
// The binding field is excluded from the hash calculation.
func (a *Assertion) GetHash() ([]byte, error) {
	// Marshal the assertion to JSON (custom MarshalJSON handles binding omission)
	assertionJSON, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	// Unmarshal the JSON into a map to ensure binding is removed
	var jsonObject map[string]interface{}
	if err := json.Unmarshal(assertionJSON, &jsonObject); err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}

	// Explicitly remove the binding key if present
	delete(jsonObject, "binding")

	// Marshal the map back to JSON
	assertionJSON, err = json.Marshal(jsonObject)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	// Transform the JSON using JCS
	transformedJSON, err := jcs.Transform(assertionJSON)
	if err != nil {
		return nil, fmt.Errorf("jcs.Transform failed: %w", err)
	}

	return ocrypto.SHA256AsHex(transformedJSON), nil
}

func (s *Statement) UnmarshalJSON(data []byte) error {
	// Define a custom struct for deserialization
	type Alias Statement
	aux := &struct {
		Value json.RawMessage `json:"value,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
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

const (
	// StatementFormatJSON is a marshaled JSON object into a string
	StatementFormatJSON   = "json"
	StatementFormatString = "string"
)

// Statement includes information applying to the scope of the assertion.
// It could contain rights, handling instructions, or general metadata.
type Statement struct {
	// Format describes the payload encoding format. (e.g. json-structured, string)
	Format string `json:"format,omitempty" validate:"required"`
	// Schema URI identifying the schema or standard that defines the structure and semantics of the value.
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

// IsEmpty returns true if both Method and Signature are empty.
func (b Binding) IsEmpty() bool {
	return b.Method == "" && b.Signature == ""
}

// AssertionType represents the type of the assertion.  Categorizes the assertion's purpose. Common values include handling (e.g., caveats, dissemination controls) or metadata (general information).
type AssertionType string

const (
	HandlingAssertion AssertionType = "handling"
	MetadataAssertion AssertionType = "metadata"
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
	// Key value.
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
// If the default key is not set, it returns error.
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
