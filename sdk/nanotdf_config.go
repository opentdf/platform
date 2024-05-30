package sdk

import (
	"crypto/ecdh"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
)

// ============================================================================================================
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
	cipher       CipherMode
	kasURL       ResourceLocator
	sigCfg       signatureConfig
	policy       policyInfo
	bindCfg      bindingConfig
}

type NanoTDFOption func(*NanoTDFConfig) error

// NewNanoTDFConfig - Create a new instance of a nanoTDF config
func (s SDK) NewNanoTDFConfig() (*NanoTDFConfig, error) {
	// TODO FIXME - how to pass in mode value and use here before 'c' is initialized?
	newECKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewRSAKeyPair failed: %w", err)
	}

	c := &NanoTDFConfig{
		keyPair: newECKeyPair,
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

// SetKasURL - set the URL of the KAS endpoint to be used for this nanoTDF
func (config *NanoTDFConfig) SetKasURL(url string) error {
	return config.kasURL.setURL(url)
}

// SetAttributes - set the attributes to be used for this nanoTDF
func (config *NanoTDFConfig) SetAttributes(attributes []string) {
	config.attributes = attributes
}

// WithNanoDataAttributes appends the given data attributes to the bound policy
func WithNanoDataAttributes(attributes ...string) NanoTDFOption {
	return func(c *NanoTDFConfig) error {
		c.attributes = append(c.attributes, attributes...)
		return nil
	}
}

type NanoKASInfo struct {
	kasPublicKeyPem string
	kasURL          string
}

// WithNanoKasInformation adds the first kas url and its corresponding public key
// that is required to create and read the nanotdf.  Note that only the first
// entry is used, as multi-kas is not supported for nanotdf
func WithNanoKasInformation(kasInfoList ...NanoKASInfo) NanoTDFOption {
	return func(c *NanoTDFConfig) error {
		newKasInfos := make([]NanoKASInfo, 0)
		newKasInfos = append(newKasInfos, kasInfoList...)
		err := c.kasURL.setURL(newKasInfos[0].kasURL)
		if err != nil {
			return err
		}
		c.kasPublicKey, err = ocrypto.ECPubKeyFromPem([]byte(newKasInfos[0].kasPublicKeyPem))
		if err != nil {
			return err
		}
		return nil
	}
}
