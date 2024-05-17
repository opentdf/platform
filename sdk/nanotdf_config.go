package sdk

import (
	"fmt"
	"github.com/opentdf/platform/lib/ocrypto"
)

// ============================================================================================================
// Pat Mancuso May 2024
// Support for specifying configuration information for nanoTDF operations
//
// The config information in this structure is referenced once at the beginning of the nanoTDF
// operation, and is not consulted again.  It is safe to create a config, use it in one operation, modify it,
// and use it again in a second operation.  The modification will only affect the second operation in that case.
//
// ============================================================================================================

type NanoTDFConfig struct {
	datasetMode        bool
	maxKeyIterations   uint64
	keyIterationCount  uint64
	eccMode            ocrypto.ECCMode
	keyPair            ocrypto.ECKeyPair
	privateKey         string
	publicKey          string
	attributes         []string
	bufferSize         uint64
	signerPrivateKey   []byte
	cipher             cipherMode
	kasURL             ResourceLocator
	mKasPublicKey      string
	mDefaultSalt       []byte
	EphemeralPublicKey eccKey
	sigCfg             signatureConfig
	policy             policyInfo

	binding bindingCfg
}

type NanoTDFOption func(*NanoTDFConfig) error

// NewNanoTDFConfig - Create a new instance of a nanoTDF config
func NewNanoTDFConfig(opt ...NanoTDFOption) (*NanoTDFConfig, error) {
	// TODO FIXME - how to pass in mode value and use here before 'c' is initialized?
	newECKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewRSAKeyPair failed: %w", err)
	}

	publicKeyInPemFormat, err := newECKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PublicKeyInPemFormat failed: %w", err)
	}

	privateKeyInPemFormat, err := newECKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("ocrypto.PrivateKeyInPemFormat failed: %w", err)
	}

	c := &NanoTDFConfig{
		keyPair:    newECKeyPair,
		publicKey:  publicKeyInPemFormat,
		privateKey: privateKeyInPemFormat,
	}

	for _, o := range opt {
		err := o(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

// SetKasUrl - set the URL of the KAS endpoint to be used for this nanoTDF
func (config *NanoTDFConfig) SetKasUrl(url string) error {
	return config.kasURL.setUrl(url)
}

// SetAttributes - set the attributes to be used for this nanoTDF
func (config *NanoTDFConfig) SetAttributes(attributes []string) {
	config.attributes = attributes
}
