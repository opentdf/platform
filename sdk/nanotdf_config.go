package sdk

import (
	"crypto/ecdh"
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
	keyPair      ocrypto.ECKeyPair
	kasPublicKey *ecdh.PublicKey
	attributes   []string
	cipher       cipherMode
	kasURL       ResourceLocator
	sigCfg       signatureConfig
	policy       policyInfo
	bindCfg      bindingConfig
}

type NanoTDFOption func(*NanoTDFConfig) error

// NewNanoTDFConfig - Create a new instance of a nanoTDF config
func NewNanoTDFConfig() (*NanoTDFConfig, error) {
	// TODO FIXME - how to pass in mode value and use here before 'c' is initialized?
	newECKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewRSAKeyPair failed: %w", err)
	}

	// TODO: This need come form KAS
	kasPubKey := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhwi1B2OLMxYlVfvgvfgBTJBC9oBv
jm8jeB4u2MJfBjDzgD3EHSHlJKE3fb7m/T3Lko9tyPP6S1c7Nt6oXn6FHw==
-----END PUBLIC KEY-----`

	kasPublicKey, err := ocrypto.ECPubKeyFromPem([]byte(kasPubKey))
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ECPubKeyFromPem failed: %w", err)
	}

	c := &NanoTDFConfig{
		keyPair:      newECKeyPair,
		kasPublicKey: kasPublicKey,
		bindCfg: bindingConfig{
			useEcdsaBinding: false,
			padding:         0,
			eccMode:         ocrypto.ECCModeSecp256r1,
		},
		cipher: kCipher96AuthTagSize,
		sigCfg: signatureConfig{
			hasSignature:  false,
			signatureMode: ocrypto.ECCModeSecp256r1,
			cipher:        cipherModeAes256gcm96Bit,
		},
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
