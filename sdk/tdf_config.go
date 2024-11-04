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
}

func newTDFConfig(opt ...TDFOption) (*TDFConfig, error) {
	rsaKeyPair, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewRSAKeyPair failed: %w", err)
	}

	publicKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PublicKeyInPemFormat failed: %w", err)
	}

	privateKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PrivateKeyInPemFormat failed: %w", err)
	}

	c := &TDFConfig{
		autoconfigure:             true,
		tdfPrivateKey:             privateKey,
		tdfPublicKey:              publicKey,
		defaultSegmentSize:        defaultSegmentSize,
		enableEncryption:          true,
		tdfFormat:                 JSONFormat,
		integrityAlgorithm:        HS256,
		segmentIntegrityAlgorithm: GMAC,
	}

	for _, o := range opt {
		err := o(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
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

type TDFReaderOption func(*TDFReaderConfig) error

type TDFReaderConfig struct {
	// Optional Map of Assertion Verification Keys
	AssertionVerificationKeys    AssertionVerificationKeys
	disableAssertionVerification bool
}

func newTDFReaderConfig(opt ...TDFReaderOption) (*TDFReaderConfig, error) {
	c := &TDFReaderConfig{
		disableAssertionVerification: false,
	}
	for _, o := range opt {
		err := o(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func WithAssertionVerificationKeys(keys AssertionVerificationKeys) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.AssertionVerificationKeys = keys
		return nil
	}
}

func WithDisableAssertionVerification(disable bool) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.disableAssertionVerification = disable
		return nil
	}
}
