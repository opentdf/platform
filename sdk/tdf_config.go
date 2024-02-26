package sdk

import (
	"fmt"

	"github.com/opentdf/platform/sdk/internal/crypto"
)

const (
	tdf3KeySize        = 2048
	defaultSegmentSize = 2 * 1024 * 1024 // 2mb
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

const kHTTPOk = 200

type KASInfo struct {
	url       string
	publicKey string // Public key can be empty.
}

func NewKasInfo(url string) KASInfo {
	return KASInfo{url: url}
}

type TDFOption func(*TDFConfig) error

// TDFConfig Internal config struct for building TDF options.
type TDFConfig struct {
	defaultSegmentSize        int64
	enableEncryption          bool
	tdfFormat                 TDFFormat
	tdfPublicKey              string // TODO: Remove it
	tdfPrivateKey             string
	metaData                  string
	integrityAlgorithm        IntegrityAlgorithm
	segmentIntegrityAlgorithm IntegrityAlgorithm
	assertions                []Assertion //nolint:unused // TODO
	attributes                []string
	kasInfoList               []KASInfo
}

// NewTDFConfig CreateTDF a new instance of tdf config.
func NewTDFConfig(opt ...TDFOption) (*TDFConfig, error) {
	rsaKeyPair, err := crypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewRSAKeyPair failed: %w", err)
	}

	publicKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PublicKeyInPemFormat failed: %w", err)
	}

	privateKey, err := rsaKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PublicKeyInPemFormat failed: %w", err)
	}

	c := &TDFConfig{
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
		c.attributes = append(c.attributes, attributes...)
		return nil
	}
}

// WithKasInformation adds all the kas urls and their corresponding public keys
// that is required to create and read the tdf.
func WithKasInformation(kasInfoList ...KASInfo) TDFOption { //nolint:gocognit
	return func(c *TDFConfig) error {
		newKasInfos := make([]KASInfo, 0)
		newKasInfos = append(newKasInfos, kasInfoList...)
		c.kasInfoList = newKasInfos

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

// WithSegmentSize returns an Option that set the default segment size to TDF.
func WithSegmentSize(size int64) TDFOption {
	return func(c *TDFConfig) error {
		c.defaultSegmentSize = size
		return nil
	}
}
