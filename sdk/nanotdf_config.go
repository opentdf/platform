package sdk

import (
	"crypto/ecdh"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/internal/autoconfigure"
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
	attributes   []autoconfigure.AttributeValueFQN
	cipher       CipherMode
	kasURL       ResourceLocator
	sigCfg       signatureConfig
	policy       policyInfo
	bindCfg      bindingConfig
}

type NanoTDFOption func(*NanoTDFConfig) error

func (s SDK) initializeNanoTDFConfig() (*NanoTDFConfig, error) {
	newECKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.NewECKeyPair failed: %w", err)
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

// NewNanoTDFConfig - Create a new instance of a nanoTDF config
// Deprecated: Use NanoTDFOptions with CreateNanoTDFOpts
func (s SDK) NewNanoTDFConfig() (*NanoTDFConfig, error) {
	return s.initializeNanoTDFConfig()
}

// newNanoTDFConfig - Create a new instance of a nanoTDF config
func (s SDK) newNanoTDFConfig(opt ...NanoTDFOption) (*NanoTDFConfig, error) {
	c, err := s.initializeNanoTDFConfig()
	if err != nil {
		return nil, err
	}

	for _, o := range opt {
		err = o(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

// SetKasURL - set the URL of the KAS endpoint to be used for this nanoTDF
func (config *NanoTDFConfig) SetKasURL(url string) error {
	return config.kasURL.setURL(url)
}

// SetAttributes - set the attributes to be used for this nanoTDF
func (config *NanoTDFConfig) SetAttributes(attributes []string) error {
	config.attributes = make([]autoconfigure.AttributeValueFQN, len(attributes))
	for i, a := range attributes {
		v, err := autoconfigure.NewAttributeValueFQN(a)
		if err != nil {
			return err
		}
		config.attributes[i] = v
	}
	return nil
}

// EnableECDSAPolicyBinding enable ecdsa policy binding
func (config *NanoTDFConfig) EnableECDSAPolicyBinding() {
	config.bindCfg.useEcdsaBinding = true
}

// WithNanoDataAttributes appends the given data attributes to the bound policy
func WithNanoDataAttributes(attributes ...string) NanoTDFOption {
	return func(c *NanoTDFConfig) error {
		for _, a := range attributes {
			v, err := autoconfigure.NewAttributeValueFQN(a)
			if err != nil {
				return err
			}
			c.attributes = append(c.attributes, v)
		}
		return nil
	}
}

type NanoKASInfo struct {
	KasPublicKeyPem string
	KasURL          string
}

// WithNanoKasInformation adds the first kas url and its corresponding public key
// that is required to create and read the nanotdf.  Note that only the first
// entry is used, as multi-kas is not supported for nanotdf
func WithNanoKasInformation(kasInfoList ...NanoKASInfo) NanoTDFOption {
	return func(c *NanoTDFConfig) error {
		newKasInfos := make([]NanoKASInfo, 0)
		newKasInfos = append(newKasInfos, kasInfoList...)
		err := c.kasURL.setURL(newKasInfos[0].KasURL)
		if err != nil {
			return err
		}
		if newKasInfos[0].KasPublicKeyPem != "" {
			c.kasPublicKey, err = ocrypto.ECPubKeyFromPem([]byte(newKasInfos[0].KasPublicKeyPem))
			if err != nil {
				return err
			}
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
