package sdk

// ============================================
// QUANTUM-SAFE ADDITION - Hackathon 2025
// Adds ML-DSA (FIPS-204) support for quantum-resistant assertions
// Original RSA/HS256 functionality preserved
// ============================================

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/gowebpki/jcs"
	"github.com/lestrrat-go/jwx/v2/jwa"
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
	if key.Alg == AssertionKeyAlgMLDSA44 {
		mldsaKey, ok := key.Key.(*mldsa44.PrivateKey)
		if !ok {
			return errors.New("invalid ML-DSA-44 private key")
		}

		// Create message containing hash and sig
		message := fmt.Sprintf("%s.%s", hash, sig)
		messageBytes := []byte(message)

		// Sign with ML-DSA-44
		signature := make([]byte, mldsa44.SignatureSize)
		err := mldsa44.SignTo(mldsaKey, messageBytes, nil, true, signature)
		if err != nil {
			return fmt.Errorf("ML-DSA-44 signing failed: %w", err)
		}

		// Store both message and signature in a structured format
		// Format: base64(message).base64(signature)
		a.Binding.Method = JWS.String()
		a.Binding.Signature = fmt.Sprintf("%s.%s",
			base64.StdEncoding.EncodeToString(messageBytes),
			base64.StdEncoding.EncodeToString(signature))

		return nil
	}

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

	if key.Alg == AssertionKeyAlgMLDSA44 {
		mldsaKey, ok := key.Key.(*mldsa44.PublicKey)
		if !ok {
			return "", "", errors.New("invalid ML-DSA-44 public key")
		}

		// Split the binding signature into message and signature parts
		parts := strings.Split(a.Binding.Signature, ".")
		if len(parts) != 2 {
			return "", "", errors.New("invalid ML-DSA-44 signature format")
		}

		// Decode message and signature
		message, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return "", "", fmt.Errorf("failed to decode message: %w", err)
		}

		signature, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", "", fmt.Errorf("failed to decode signature: %w", err)
		}

		// Now actually use mldsaKey and signature to verify
		if !mldsa44.Verify(mldsaKey, message, nil, signature) {
			return "", "", errAssertionVerifyKeyFailure
		}

		// Extract hash and sig from the verified message
		messageParts := strings.Split(string(message), ".")
		if len(messageParts) != 2 {
			return "", "", errors.New("invalid message format")
		}

		return messageParts[0], messageParts[1], nil
	}

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
func (a Assertion) GetHash() ([]byte, error) {
	// Clear out the binding
	a.Binding = Binding{}

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

	// Remove the binding key
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

	//ML-DSA algorithms
	AssertionKeyAlgMLDSA44 AssertionKeyAlg = "ML-DSA-44"
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

func (a *Assertion) signWithMLDSA(hash, sig string, key AssertionKey) error {
	if key.Alg != AssertionKeyAlgMLDSA44 {
		return fmt.Errorf("unsupported ML-DSA algorithm: %s", key.Alg)
	}

	// Create a new token
	tok := jwt.New()
	if err := tok.Set(kAssertionHash, hash); err != nil {
		return fmt.Errorf("failed to set assertion hash: %w", err)
	}
	if err := tok.Set(kAssertionSignature, sig); err != nil {
		return fmt.Errorf("failed to set assertion signature: %w", err)
	}

	// Sign the token using the ML-DSA algorithm
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.Ed25519, key.Key))
	if err != nil {
		return fmt.Errorf("signing assertion with ML-DSA failed: %w", err)
	}

	// Set the binding
	a.Binding.Method = JWS.String()
	a.Binding.Signature = string(signedTok)

	return nil
} //check implementation of ML-DSA signing
// Note: The ML-DSA signing implementation is a placeholder and should be replaced with the actual signing logic using the mldsa44 package or similar.
// The mldsa44 package provides

func (a Assertion) verifyWithMLDSA(key AssertionKey) (string, string, error) {
	if key.Alg != AssertionKeyAlgMLDSA44 {
		return "", "", fmt.Errorf("unsupported ML-DSA algorithm: %s", key.Alg)
	}

	tok, err := jwt.Parse([]byte(a.Binding.Signature),
		jwt.WithKey(jwa.Ed25519, key.Key),
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
} //check implementation of ML-DSA verification
