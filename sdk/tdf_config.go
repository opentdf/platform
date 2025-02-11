package sdk

import (
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	tdf3KeySize        = 2048
	defaultSegmentSize = 2 * 1024 * 1024 // 2mb
	maxSegmentSize     = defaultSegmentSize * 2
	minSegmentSize     = 16 * 1024
	kasPublicKeyPath   = "/kas_public_key"
	DefaultRSAKeySize  = 2048
	ECKeySize256       = 256
	ECKeySize384       = 384
	ECKeySize521       = 521
)

type TDFFormat = int

const (
	JSONFormat = iota
	XMLFormat
)

type IntegrityAlgorithm = int

const (
	HS256 = iota
	GMAC
)

// KASInfo contains Key Access Server information.
type KASInfo struct {
	// URL of the KAS server
	URL string
	// Public key can be empty.
	// If it is empty, the public key will be fetched from the KAS server.
	PublicKey string
	// Key identifier associated with the given key, if present.
	KID string
	// The algorithm associated with this key
	Algorithm string
	// If this KAS should be used as the default for 'encrypt' calls
	Default bool
}

type TDFOption func(*TDFConfig) error

// TDFConfig Internal config struct for building TDF options.
type TDFConfig struct {
	autoconfigure             bool
	defaultSegmentSize        int64
	enableEncryption          bool
	tdfFormat                 TDFFormat
	tdfPublicKey              string // TODO: Remove it
	tdfPrivateKey             string
	metaData                  string
	mimeType                  string
	integrityAlgorithm        IntegrityAlgorithm
	segmentIntegrityAlgorithm IntegrityAlgorithm
	assertions                []AssertionConfig
	attributes                []AttributeValueFQN
	attributeValues           []*policy.Value
	kasInfoList               []KASInfo
	splitPlan                 []keySplitStep
	keyType                   ocrypto.KeyType
}

func newTDFConfig(opt ...TDFOption) (*TDFConfig, error) {
	c := &TDFConfig{
		autoconfigure:             true,
		defaultSegmentSize:        defaultSegmentSize,
		enableEncryption:          true,
		tdfFormat:                 JSONFormat,
		integrityAlgorithm:        HS256,
		segmentIntegrityAlgorithm: GMAC,
		keyType:                   ocrypto.RSA2048Key, // default to RSA
	}

	for _, o := range opt {
		err := o(c)
		if err != nil {
			return nil, err
		}
	}

	publicKey, privateKey, err := generateKeyPair(c.keyType)
	if err != nil {
		return nil, err
	}

	c.tdfPrivateKey = privateKey
	c.tdfPublicKey = publicKey

	return c, nil
}

func generateKeyPair(keyType ocrypto.KeyType) (string, string, error) {
	switch keyType {
	case ocrypto.RSA2048Key:
		ks, err := ocrypto.RSAKeyTypeToBits(keyType)
		if err != nil {
			return "", "", err
		}
		return generateRSAKeyPair(ks)
	case ocrypto.EC256Key, ocrypto.EC384Key, ocrypto.EC521Key:
		mode, err := ocrypto.ECKeyTypeToMode(keyType)
		if err != nil {
			return "", "", err
		}
		return generateECKeyPair(mode)
	default:
		return "", "", fmt.Errorf("unsupported key type")
	}
}

func generateRSAKeyPair(keySize int) (string, string, error) {
	rsaKeyPair, err := ocrypto.NewRSAKeyPair(keySize)
	if err != nil {
		return "", "", fmt.Errorf("ocrypto.NewRSAKeyPair failed: %w", err)
	}
	publicKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return "", "", fmt.Errorf("ocrypto.PublicKeyInPemFormat failed: %w", err)
	}
	privateKey, err := rsaKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return "", "", fmt.Errorf("ocrypto.PrivateKeyInPemFormat failed: %w", err)
	}
	return publicKey, privateKey, nil
}

func generateECKeyPair(mode ocrypto.ECCMode) (string, string, error) {
	ecKeyPair, err := ocrypto.NewECKeyPair(mode)
	if err != nil {
		return "", "", fmt.Errorf("ocrypto.NewECKeyPair failed: %w", err)
	}
	publicKey, err := ecKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return "", "", fmt.Errorf("ocrypto.PublicKeyInPemFormat failed: %w", err)
	}
	privateKey, err := ecKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return "", "", fmt.Errorf("ocrypto.PrivateKeyInPemFormat failed: %w", err)
	}
	return publicKey, privateKey, nil
}

// WithDataAttributes appends the given data attributes to the bound policy
func WithDataAttributes(attributes ...string) TDFOption {
	return func(c *TDFConfig) error {
		c.attributeValues = nil
		for _, a := range attributes {
			v, err := NewAttributeValueFQN(a)
			if err != nil {
				return err
			}
			c.attributes = append(c.attributes, v)
		}
		return nil
	}
}

// WithDataAttributeValues appends the given data attributes to the bound policy.
// Unlike `WithDataAttributes`, this will not trigger an attribute definition lookup
// during autoconfigure. That is, to use autoconfigure in an 'offline' context,
// you must first store the relevant attribute information locally and load
// it to the `CreateTDF` method with this option.
func WithDataAttributeValues(attributes ...*policy.Value) TDFOption {
	return func(c *TDFConfig) error {
		c.attributes = make([]AttributeValueFQN, len(attributes))
		c.attributeValues = make([]*policy.Value, len(attributes))
		for i, a := range attributes {
			c.attributeValues[i] = a
			afqn, err := NewAttributeValueFQN(a.GetFqn())
			if err != nil {
				// TODO: update service to validate and encode FQNs properly
				return err
			}
			c.attributes[i] = afqn
		}
		return nil
	}
}

// WithKasInformation adds all the kas urls and their corresponding public keys
// that is required to create and read the tdf.
// For writing TDFs, this is optional, but adding it can bypass key lookup.
//
// During creation, if the public key is set, the kas will not be contacted for the latest key.
// Please make sure to set the KID if the PublicKey is set to include a KID in any key wrappers.
func WithKasInformation(kasInfoList ...KASInfo) TDFOption {
	return func(c *TDFConfig) error {
		newKasInfos := make([]KASInfo, 0)
		newKasInfos = append(newKasInfos, kasInfoList...)
		c.kasInfoList = newKasInfos

		return nil
	}
}

func withSplitPlan(p ...keySplitStep) TDFOption {
	return func(c *TDFConfig) error {
		c.splitPlan = make([]keySplitStep, len(p))
		copy(c.splitPlan, p)
		c.autoconfigure = false
		return nil
	}
}

// WithMetaData returns an Option that add metadata to TDF.
func WithMetaData(metaData string) TDFOption {
	return func(c *TDFConfig) error {
		c.metaData = metaData
		return nil
	}
}

func WithMimeType(mimeType string) TDFOption {
	return func(c *TDFConfig) error {
		c.mimeType = mimeType
		return nil
	}
}

// WithSegmentSize returns an Option that set the default segment size within the TDF. Any excessively large or small
// values will be replaced with a supported value.
func WithSegmentSize(size int64) TDFOption {
	if size > maxSegmentSize {
		size = maxSegmentSize
	} else if size < minSegmentSize {
		size = minSegmentSize
	}
	return func(c *TDFConfig) error {
		c.defaultSegmentSize = size
		return nil
	}
}

// WithAssertions returns an Option that add assertions to TDF.
func WithAssertions(assertionList ...AssertionConfig) TDFOption {
	return func(c *TDFConfig) error {
		c.assertions = append(c.assertions, assertionList...)
		return nil
	}
}

// WithAutoconfigure toggles inferring KAS info for encrypt from data attributes.
// This will use the Attributes service to look up key access grants.
// These are KAS URLs associated with attributes.
// Defaults to enabled.
func WithAutoconfigure(enable bool) TDFOption {
	return func(c *TDFConfig) error {
		c.autoconfigure = enable
		c.splitPlan = nil
		return nil
	}
}

func WithWrappingKeyAlg(keyType ocrypto.KeyType) TDFOption {
	return func(c *TDFConfig) error {
		if c.keyType == "" {
			return fmt.Errorf("key type missing")
		}
		c.keyType = keyType
		return nil
	}
}

// Schema Validation where 0 = none (skip), 1 = lax (allowing novel entries, 'falsy' values for unkowns), 2 = strict (rejecting novel entries, strict match to manifest schema)
type SchemaValidationIntensity int

const (
	Skip SchemaValidationIntensity = iota
	Lax
	Strict
	unreasonable = 100
)

type TDFReaderOption func(*TDFReaderConfig) error

type TDFReaderConfig struct {
	verifiers                    AssertionVerificationKeys
	disableAssertionVerification bool

	schemaValidationIntensity SchemaValidationIntensity
	kasSessionKey             ocrypto.KeyPair
	keyType                   ocrypto.KeyType
	keySize                   int // For RSA this is key size, for EC this is curve size
}

func newTDFReaderConfig(opt ...TDFReaderOption) (*TDFReaderConfig, error) {
	var err error
	c := &TDFReaderConfig{
		disableAssertionVerification: false,
		keyType:                      ocrypto.RSA2048Key,
		keySize:                      DefaultRSAKeySize,
	}

	for _, o := range opt {
		err := o(c)
		if err != nil {
			return nil, err
		}
	}

	if c.keyType == ocrypto.RSA2048Key {
		c.kasSessionKey, err = ocrypto.NewRSAKeyPair(c.keySize)
		if err != nil {
			return nil, fmt.Errorf("failed to create RSA key pair: %w", err)
		}
	} else {
		var eccMode ocrypto.ECCMode
		eccMode, err = ocrypto.ECSizeToMode(c.keySize)
		if err != nil {
			return nil, err
		}
		c.kasSessionKey, err = ocrypto.NewECKeyPair(eccMode)
		if err != nil {
			return nil, fmt.Errorf("failed to create EC key pair: %w", err)
		}
	}

	return c, nil
}

func WithAssertionVerificationKeys(keys AssertionVerificationKeys) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.verifiers = keys
		return nil
	}
}

func WithSchemaValidation(intensity SchemaValidationIntensity) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.schemaValidationIntensity = intensity
		return nil
	}
}

func WithDisableAssertionVerification(disable bool) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.disableAssertionVerification = disable
		return nil
	}
}

func WithSessionKeyType(keyType ocrypto.KeyType) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		if c.keyType == "" {
			return fmt.Errorf("key type missing")
		}
		c.keyType = keyType
		return nil
	}
}
