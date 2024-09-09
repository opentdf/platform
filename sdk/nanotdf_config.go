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
	attributes   []AttributeValueFQN
	cipher       CipherMode
	kasURL       ResourceLocator
	sigCfg       signatureConfig
	policy       policyInfo
	bindCfg      bindingConfig
}

type NanoTDFOption func(*NanoTDFConfig) error

// newNanoTDFConfig - Create a new instance of a nanoTDF config
func newNanoTDFConfig(opt ...NanoTDFOption) (*NanoTDFConfig, error) {
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

	for _, o := range opt {
		err := o(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

// WithKasURL - set the URL of the KAS endpoint to be used for this nanoTDF
func WithKasURL(url string) NanoTDFOption {
	return func(c *NanoTDFConfig) error {
		return c.kasURL.setURL(url)
	}q
}

// WithKasURLAndIdentifier - set the URL of the KAS endpoint and the identifier to be used for this nanoTDF
func WithKasURLAndIdentifier(url string, identifier string) NanoTDFOption {
	return func(c *NanoTDFConfig) error {
		return c.kasURL.setURLWithIdentifier(url, identifier)
	}
}

// WithNanoDataAttributes appends the given data attributes to the bound policyq
func WithNanoDataAttributes(attributes []string) NanoTDFOption {
	return func(c *NanoTDFConfig) error {
		c.attributes = make([]AttributeValueFQN, len(attributes))
		for i, a := range attributes {
			v, err := NewAttributeValueFQN(a)
			if err != nil {
				return err
			}
			c.attributes[i] = v
		}
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

// WithECDSAPolicyBinding enable ecdsa policy binding
func WithECDSAPolicyBinding() NanoTDFOption {
	return func(c *NanoTDFConfig) error {
		c.bindCfg.useEcdsaBinding = true
		return nil
	}
}
