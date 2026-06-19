package sdk

import (
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
)

// Error types
var (
	ErrNanoTDFNoMetadata        = errors.New("nanotdf cannot be created with metadata, use ztdf")
	ErrNanoTDFNoMimeType        = errors.New("nanotdf cannot be created with mime type, use ztdf")
	ErrNanoTDFNoSegmentSize     = errors.New("nanotdf cannot be created with segment size, use ztdf")
	ErrNanoTDFKasInfoLen        = errors.New("nanotdf supports only one kas")
	ErrNanoTDFNoAssertions      = errors.New("nanotdf cannot be created with assertions, use ztdf")
	ErrNanoTDFNoAutoconfigure   = errors.New("nanotdf cannot be created with autoconfigure, use ztdf")
	ErrNanoTDFNoSplitPlan       = errors.New("nanotdf cannot be created with split plan, use ztdf")
	ErrZTDFNoECDSAPolicyBinding = errors.New("ztdf cannot be created with ecdsa policy binding, use nanotdf")
)

// TDFType represents the type of TDF to be created
type TDFType int

const (
	ZTDF TDFType = iota
	NanoTDF
)

// tdfOptions contains all the options specific to ZTDF
type tdfOptions struct {
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
	attributeValues           []*policy.Value
	splitPlan                 []keySplitStep
}

// nanoTDFOptions contains all the options specific to NanoTDF
type nanoTDFOptions struct {
	keyPair      ocrypto.ECKeyPair
	kasPublicKey *ecdh.PublicKey
	cipher       CipherMode
	kasURL       ResourceLocator
	sigCfg       signatureConfig
	policy       policyInfo
	bindCfg      bindingConfig
}

// TDFFormatConfig is a wrapper that can create both TDF and NanoTDF configurations
type TDFFormatConfig struct {
	tdfType TDFType

	// Common options
	attributes  []AttributeValueFQN
	kasInfoList []KASInfo

	// TDF-specific options
	tdfOptions *tdfOptions

	// NanoTDF-specific options
	nanoTDFOptions *nanoTDFOptions
}

// TDFFormatOption is a function that modifies TDFFormatConfig
type TDFFormatOption func(*TDFFormatConfig) error

// NewUnifiedTDFConfig creates a new UnifiedTDFConfig with the given options
func NewUnifiedTDFConfig(tdfType TDFType, opts ...TDFFormatOption) (*TDFFormatConfig, error) {
	c := &TDFFormatConfig{tdfType: tdfType}

	if err := c.initializeDefaultConfig(); err != nil {
		return nil, fmt.Errorf("failed to initialize default config: %w", err)
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return c, nil
}

func (c *TDFFormatConfig) initializeDefaultConfig() error {
	switch c.tdfType {
	case ZTDF:
		return c.initializeZTDFConfig()
	case NanoTDF:
		return c.initializeNanoTDFConfig()
	default:
		return fmt.Errorf("unknown TDF type: %v", c.tdfType)
	}
}

func (c *TDFFormatConfig) initializeZTDFConfig() error {
	rsaKeyPair, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return fmt.Errorf("failed to create RSA key pair: %w", err)
	}

	publicKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return fmt.Errorf("failed to get public key in PEM format: %w", err)
	}

	privateKey, err := rsaKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return fmt.Errorf("failed to get private key in PEM format: %w", err)
	}

	c.tdfOptions = &tdfOptions{
		autoconfigure:             true,
		defaultSegmentSize:        defaultSegmentSize,
		enableEncryption:          true,
		tdfFormat:                 JSONFormat,
		tdfPublicKey:              publicKey,
		tdfPrivateKey:             privateKey,
		integrityAlgorithm:        HS256,
		segmentIntegrityAlgorithm: GMAC,
	}

	return nil
}

func (c *TDFFormatConfig) initializeNanoTDFConfig() error {
	newECKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		return fmt.Errorf("failed to create EC key pair: %w", err)
	}

	c.nanoTDFOptions = &nanoTDFOptions{
		keyPair: newECKeyPair,
		bindCfg: bindingConfig{
			useEcdsaBinding: false,
			eccMode:         ocrypto.ECCModeSecp256r1,
		},
		cipher: kCipher96AuthTagSize,
		sigCfg: signatureConfig{
			hasSignature:  false,
			signatureMode: ocrypto.ECCModeSecp256r1,
			cipher:        cipherModeAes256gcm96Bit,
		},
	}

	return nil
}

// WithTDFSplitPlan sets the split plan for ZTDF
func WithTDFSplitPlan(p ...keySplitStep) TDFFormatOption {
	return func(c *TDFFormatConfig) error {
		if c.tdfType == NanoTDF {
			return ErrNanoTDFNoSplitPlan
		}

		c.tdfOptions.splitPlan = make([]keySplitStep, len(p))
		copy(c.tdfOptions.splitPlan, p)
		c.tdfOptions.autoconfigure = false
		return nil
	}
}

// WithTDFAttributes sets the attributes for both TDF and NanoTDF
func WithTDFAttributes(attributes ...string) TDFFormatOption {
	return func(c *TDFFormatConfig) error {
		c.tdfOptions.attributeValues = nil
		for _, a := range attributes {
			v, err := NewAttributeValueFQN(a)
			if err != nil {
				return fmt.Errorf("failed to create attribute value: %w", err)
			}
			c.attributes = append(c.attributes, v)
		}
		return nil
	}
}

// WithTDFKasInformation sets the KAS information for both TDF and NanoTDF
func WithTDFKasInformation(kasInfoList ...KASInfo) TDFFormatOption {
	return func(c *TDFFormatConfig) error {
		if c.tdfType == ZTDF {
			c.kasInfoList = append([]KASInfo{}, kasInfoList...)
			return nil
		}

		if len(kasInfoList) != 1 {
			return ErrNanoTDFKasInfoLen
		}

		kasInfo := kasInfoList[0]
		if err := c.nanoTDFOptions.kasURL.setURL(kasInfo.URL); err != nil {
			return fmt.Errorf("failed to set KAS URL: %w", err)
		}

		if kasInfo.PublicKey != "" {
			var err error
			c.nanoTDFOptions.kasPublicKey, err = ocrypto.ECPubKeyFromPem([]byte(kasInfo.PublicKey))
			if err != nil {
				return fmt.Errorf("failed to parse KAS public key: %w", err)
			}
		}

		return nil
	}
}

// WithTDFMetaData sets the metadata for TDF only
func WithTDFMetaData(metaData string) TDFFormatOption {
	return func(c *TDFFormatConfig) error {
		if c.tdfType == NanoTDF {
			return ErrNanoTDFNoMetadata
		}
		c.tdfOptions.metaData = metaData
		return nil
	}
}

// WithTDFMimeType sets the MIME type for TDF only
func WithTDFMimeType(mimeType string) TDFFormatOption {
	return func(c *TDFFormatConfig) error {
		if c.tdfType == NanoTDF {
			return ErrNanoTDFNoMimeType
		}
		c.tdfOptions.mimeType = mimeType
		return nil
	}
}

// WithTDFSegmentSize sets the default segment size within the TDF
func WithTDFSegmentSize(size int64) TDFFormatOption {
	return func(c *TDFFormatConfig) error {
		if c.tdfType == NanoTDF {
			return ErrNanoTDFNoSegmentSize
		}
		c.tdfOptions.defaultSegmentSize = normalizeSegmentSize(size)
		return nil
	}
}

// normalizeSegmentSize ensures the segment size is within the allowed range
func normalizeSegmentSize(size int64) int64 {
	if size > maxSegmentSize {
		return maxSegmentSize
	}
	if size < minSegmentSize {
		return minSegmentSize
	}
	return size
}

// WithTDFAssertions adds assertions to TDF
func WithTDFAssertions(assertionList ...AssertionConfig) TDFFormatOption {
	return func(c *TDFFormatConfig) error {
		if c.tdfType == NanoTDF {
			return ErrNanoTDFNoAssertions
		}
		c.tdfOptions.assertions = append(c.tdfOptions.assertions, assertionList...)
		return nil
	}
}

// WithTDFAutoconfigure toggles inferring KAS info for encrypt from data attributes
func WithTDFAutoconfigure(enable bool) TDFFormatOption {
	return func(c *TDFFormatConfig) error {
		if c.tdfType == NanoTDF {
			return ErrNanoTDFNoAutoconfigure
		}
		c.tdfOptions.autoconfigure = enable
		c.tdfOptions.splitPlan = nil
		return nil
	}
}

// WithTDFECDSAPolicyBinding toggles ECDSA policy binding for NanoTDF
func WithTDFECDSAPolicyBinding(enable bool) TDFFormatOption {
	return func(c *TDFFormatConfig) error {
		if c.tdfType == ZTDF {
			return ErrZTDFNoECDSAPolicyBinding
		}
		c.nanoTDFOptions.bindCfg.useEcdsaBinding = enable
		return nil
	}
}
