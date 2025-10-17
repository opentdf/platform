// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gowebpki/jcs"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	// SystemMetadataAssertionID is the standard ID for system metadata assertions
	SystemMetadataAssertionID = "system-metadata"
	// SystemMetadataSchemaV1 defines the schema version for system metadata
	SystemMetadataSchemaV1 = "system-metadata-v1"
	// kAssertionSignature is the JWT claim key for assertion signatures
	kAssertionSignature = "assertionSig"
	// kAssertionHash is the JWT claim key for assertion hashes
	kAssertionHash = "assertionHash"
)

// AssertionConfig defines an assertion to be included in the TDF during creation.
//
// AssertionConfig extends Assertion with a signing key, enabling creation
// of cryptographically signed assertions. The signing key is used during
// TDF creation but is not stored in the final TDF.
//
// Required fields:
//   - ID: Unique identifier for the assertion
//   - Type: The kind of assertion (BaseAssertion, HandlingAssertion)
//   - Scope: What the assertion applies to (PayloadScope, TrustedDataObjScope)
//   - AppliesToState: When the assertion is relevant (Encrypted, Unencrypted)
//   - Statement: The assertion content and metadata
//
// Optional fields:
//   - SigningKey: Custom signing key (defaults to DEK with HS256)
//
// Example:
//
//	assertion := AssertionConfig{
//		ID:             "retention-policy",
//		Type:           HandlingAssertion,
//		Scope:          PayloadScope,
//		AppliesToState: Unencrypted,
//		Statement: Statement{
//			Format: "json",
//			Schema: "retention-v1",
//			Value:  `{"retain_days": 90, "auto_delete": true}`,
//		},
//	}
type AssertionConfig struct {
	ID             string         `validate:"required"`
	Type           AssertionType  `validate:"required"`
	Scope          Scope          `validate:"required"`
	AppliesToState AppliesToState `validate:"required"`
	Statement      Statement
	SigningKey     AssertionKey
}

// Assertion represents a cryptographically signed assertion in the TDF manifest.
//
// Assertions provide integrity verification and handling instructions that are
// cryptographically bound to the TDF. They cannot be modified or copied to
// another TDF without detection due to the cryptographic binding.
//
// The assertion structure includes:
//   - Metadata: ID, type, scope, and state applicability
//   - Statement: The actual assertion content in structured format
//   - Binding: Cryptographic signature ensuring integrity
//
// Assertions are verified during TDF reading to ensure they haven't been
// tampered with since TDF creation.
type Assertion struct {
	ID             string         `json:"id"`
	Type           AssertionType  `json:"type"`
	Scope          Scope          `json:"scope"`
	AppliesToState AppliesToState `json:"appliesToState,omitempty"`
	Statement      Statement      `json:"statement"`
	Binding        Binding        `json:"binding,omitempty"`
}

var errAssertionVerifyKeyFailure = errors.New("assertion: failed to verify with provided key")

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

// GetHash returns the hash of the assertion in hex format.
// The binding field is excluded from the hash calculation.
func (a Assertion) GetHash() ([]byte, error) {
	// Marshal the assertion to JSON
	assertionJSON, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	// Unmarshal the JSON into a map to manipulate it
	var jsonObject map[string]interface{}
	if err := json.Unmarshal(assertionJSON, &jsonObject); err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}

	// Remove the binding key if present
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

// AssertionType represents the category of assertion being made.
//
// Different assertion types serve different purposes in TDF handling:
//   - HandlingAssertion: Instructions for data processing, retention, deletion
//   - BaseAssertion: General-purpose assertions including metadata, audit info
type AssertionType string

const (
	// HandlingAssertion provides instructions for data handling and processing.
	// Examples: retention policies, deletion schedules, processing requirements
	HandlingAssertion AssertionType = "handling"
	// BaseAssertion is a general-purpose assertion type for metadata and other content.
	// Examples: audit information, system metadata, custom business logic
	BaseAssertion AssertionType = "other"
)

// String returns the string representation of the assertion type.
func (at AssertionType) String() string {
	return string(at)
}

// Scope defines what component of the TDF the assertion applies to.
//
// Scope determines which part of the TDF structure the assertion governs:
//   - TrustedDataObjScope: Assertion applies to the entire TDF object
//   - PayloadScope: Assertion applies only to the encrypted payload data
type Scope string

const (
	// TrustedDataObjScope indicates the assertion applies to the complete TDF object.
	// This includes manifest, key access objects, and payload.
	TrustedDataObjScope Scope = "tdo"
	// PayloadScope indicates the assertion applies only to the payload data.
	// This is the most common scope for data handling assertions.
	PayloadScope Scope = "payload"
)

// String returns the string representation of the scope.
func (s Scope) String() string {
	return string(s)
}

// AppliesToState indicates when the assertion is relevant in the TDF lifecycle.
//
// This determines whether the assertion should be processed before or after
// decryption, enabling different handling patterns:
//   - Encrypted: Process before decryption (e.g., access logging)
//   - Unencrypted: Process after decryption (e.g., content filtering)
type AppliesToState string

const (
	// Encrypted means the assertion should be processed before payload decryption.
	// Used for access control, audit logging, and pre-processing requirements.
	Encrypted AppliesToState = "encrypted"
	// Unencrypted means the assertion should be processed after payload decryption.
	// Used for content analysis, post-processing, and data handling requirements.
	Unencrypted AppliesToState = "unencrypted"
)

// String returns the string representation of the applies to state.
func (ats AppliesToState) String() string {
	return string(ats)
}

// BindingMethod represents the cryptographic method used to bind assertions to the TDF.
//
// The binding method ensures assertions cannot be modified or transferred
// to other TDFs without detection.
type BindingMethod string

const (
	// JWS (JSON Web Signature) is the standard method for assertion binding.
	// Uses JWT-based cryptographic signatures for tamper detection.
	JWS BindingMethod = "jws"
)

// String returns the string representation of the binding method.
func (bm BindingMethod) String() string {
	return string(bm)
}

// AssertionKeyAlg represents the cryptographic algorithm for assertion signing keys.
//
// Different algorithms provide different security and compatibility characteristics:
//   - RS256: RSA-based signatures, widely supported, good for public key scenarios
//   - HS256: HMAC-based signatures, simpler, good for shared key scenarios
type AssertionKeyAlg string

const (
	// AssertionKeyAlgRS256 uses RSA-SHA256 for assertion signatures.
	// Suitable when assertions need to be verified by parties without access to signing keys.
	AssertionKeyAlgRS256 AssertionKeyAlg = "RS256"
	// AssertionKeyAlgHS256 uses HMAC-SHA256 for assertion signatures.
	// More efficient, suitable when the same key used for TDF encryption can sign assertions.
	AssertionKeyAlgHS256 AssertionKeyAlg = "HS256"
)

// String returns the string representation of the algorithm.
func (a AssertionKeyAlg) String() string {
	return string(a)
}

// AssertionKey represents a cryptographic key for signing and verifying assertions.
//
// The key can be either RSA or HMAC-based depending on the algorithm:
//   - RS256: Key should be an RSA private key (*rsa.PrivateKey or jwk.Key)
//   - HS256: Key should be a byte slice containing the shared secret
//
// Example usage:
//
//	// HMAC key using TDF's Data Encryption Key
//	hmacKey := AssertionKey{
//		Alg: AssertionKeyAlgHS256,
//		Key: dek, // 32-byte AES key
//	}
//
//	// RSA key for public key scenarios
//	rsaKey := AssertionKey{
//		Alg: AssertionKeyAlgRS256,
//		Key: privateKey, // *rsa.PrivateKey
//	}
type AssertionKey struct {
	// Alg specifies the cryptographic algorithm for this key
	Alg AssertionKeyAlg
	// Key contains the actual key material (type depends on algorithm)
	Key interface{}
}

// Algorithm returns the cryptographic algorithm of the key.
func (k AssertionKey) Algorithm() AssertionKeyAlg {
	return k.Alg
}

// IsEmpty returns true if the key has no algorithm or key material configured.
// Used to check if a default signing key should be used instead.
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
