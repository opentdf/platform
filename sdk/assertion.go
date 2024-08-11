package sdk

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
	"github.com/lestrrat-go/jwx/v2/jwa"
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
	SigningKey     AssertionKey `validate:"optional"`
}

type Assertion struct {
	ID             string         `json:"id"`
	Type           AssertionType  `json:"type"`
	Scope          Scope          `json:"scope"`
	AppliesToState AppliesToState `json:"appliesToState,omitempty"`
	Statement      Statement      `json:"statement"`
	Binding        Binding        `json:"binding"`
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
	tok, err := jwt.Parse([]byte(a.Binding.Signature),
		jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key),
	)
	if err != nil {
		return "", "", err
	}
	hashClaim, found := tok.Get(kAssertionHash)
	if !found {
		return "", "", fmt.Errorf("hash claim not found")
	}
	hash, ok := hashClaim.(string)
	if !ok {
		return "", "", fmt.Errorf("hash claim is not a string")
	}

	sigClaim, found := tok.Get(kAssertionSignature)
	if !found {
		return "", "", fmt.Errorf("signature claim not found")
	}
	sig, ok := sigClaim.(string)
	if !ok {
		return "", "", fmt.Errorf("signature claim is not a string")
	}
	return hash, sig, nil
}

// GetHash returns the hash of the assertion in hex format.
func (a Assertion) GetHash() ([]byte, error) {
	// clear out the binding
	a.Binding.Method = ""
	a.Binding.Signature = ""

	assertionJSON, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed:%w", err)
	}

	transformedJSON, err := jcs.Transform(assertionJSON)
	if err != nil {
		return nil, fmt.Errorf("jcs.Transform failed:%w", err)
	}

	return ocrypto.SHA256AsHex(transformedJSON), nil
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
	TrustedDataObj Scope = "tdo"
	Paylaod        Scope = "payload"
)

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

// Returns the key for the given assertion ID or the default key if the key is not found.
// If the default key is not set, it returns error.
func (k AssertionVerificationKeys) Get(assertionID string) (AssertionKey, error) {
	if key, ok := k.Keys[assertionID]; ok {
		return key, nil
	}
	if k.DefaultKey.IsEmpty() {
		return AssertionKey{}, fmt.Errorf("default key not set and key not found for assertion ID %q", assertionID)
	}
	return k.DefaultKey, nil
}

// IsEmpty returns true if the default key and the keys map are empty.
func (k AssertionVerificationKeys) IsEmpty() bool {
	return k.DefaultKey.IsEmpty() && len(k.Keys) == 0
}
