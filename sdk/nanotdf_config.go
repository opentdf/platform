package sdk

import (
	"crypto/ecdh"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/nanobuilder"
)

// ============================================================================================================
// Support for specifying configuration information for nanoTDF operations
//
// The config information in this structure is referenced once at the beginning of the nanoTDF
// operation, and is not consulted again.  It is safe to create a config, use it in one operation, modify it,
// and use it again in a second operation.  The modification will only affect the second operation in that case.
//
// ============================================================================================================

type policyInfo struct {
	body PolicyBody
	//	binding *eccSignature
}

const (
	kCipher64AuthTagSize  = 8
	kCipher96AuthTagSize  = 12
	kCipher104AuthTagSize = 13
	kCipher112AuthTagSize = 14
	kCipher120AuthTagSize = 15
	kCipher128AuthTagSize = 16
)

type NanoTDFConfig struct {
	keyPair       ocrypto.ECKeyPair
	kasPublicKey  *ecdh.PublicKey
	attributes    []AttributeValueFQN
	cipher        CipherMode
	kasURL        ResourceLocator
	sigCfg        signatureConfig
	policy        policyInfo
	bindCfg       bindingConfig
	collectionCfg *collectionConfig
	policyMode    nanobuilder.PolicyType // Added field for policy mode
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
			eccMode:         ocrypto.ECCModeSecp256r1,
		},
		cipher: kCipher96AuthTagSize,
		sigCfg: signatureConfig{
			hasSignature:  false,
			signatureMode: ocrypto.ECCModeSecp256r1,
			cipher:        cipherModeAes256gcm96Bit,
		},
		collectionCfg: &collectionConfig{
			iterations:    0,
			useCollection: false,
			header:        []byte{},
		},
		policyMode: nanobuilder.PolicyModeDefault,
	}

	return c, nil
}

// SetKasURL - set the URL of the KAS endpoint to be used for this nanoTDF
func (config *NanoTDFConfig) SetKasURL(url string) error {
	return config.kasURL.setURL(url)
}

// SetAttributes - set the attributes to be used for this nanoTDF
func (config *NanoTDFConfig) SetAttributes(attributes []string) error {
	config.attributes = make([]AttributeValueFQN, len(attributes))
	for i, a := range attributes {
		v, err := NewAttributeValueFQN(a)
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

// EnableCollection Experimental: Enables Collection in NanoTDFConfig.
// Reuse NanoTDFConfig to add nTDFs to a Collection.
func (config *NanoTDFConfig) EnableCollection() {
	config.collectionCfg.useCollection = true
}

// SetPolicyMode sets whether the policy should be encrypted or plaintext
func (config *NanoTDFConfig) SetPolicyMode(mode nanobuilder.PolicyType) error {
	if err := validNanoTDFPolicyMode(mode); err != nil {
		return err
	}
	config.policyMode = mode
	return nil
}

// WithNanoDataAttributes appends the given data attributes to the bound policy
func WithNanoDataAttributes(attributes ...string) NanoTDFOption {
	return func(c *NanoTDFConfig) error {
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

// WithECDSAPolicyBinding enable ecdsa policy binding
func WithECDSAPolicyBinding() NanoTDFOption {
	return func(c *NanoTDFConfig) error {
		c.bindCfg.useEcdsaBinding = true
		return nil
	}
}

type NanoTDFReaderConfig struct {
	kasAllowlist              AllowList
	ignoreAllowList           bool
	fulfillableObligationFQNs []string
	rewrapper                 nanobuilder.Rewrapper
}

func newNanoTDFReaderConfig(opt ...NanoTDFReaderOption) (*NanoTDFReaderConfig, error) {
	c := &NanoTDFReaderConfig{}

	for _, o := range opt {
		err := o(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

type NanoTDFReaderOption func(*NanoTDFReaderConfig) error

func WithNanoKasAllowlist(kasList []string) NanoTDFReaderOption {
	return func(c *NanoTDFReaderConfig) error {
		allowlist, err := newAllowList(kasList)
		if err != nil {
			return fmt.Errorf("failed to create kas allowlist: %w", err)
		}
		c.kasAllowlist = allowlist
		return nil
	}
}

func withNanoKasAllowlist(allowlist AllowList) NanoTDFReaderOption {
	return func(c *NanoTDFReaderConfig) error {
		c.kasAllowlist = allowlist
		return nil
	}
}

func WithRewrapper(rewrapper nanobuilder.Rewrapper) NanoTDFReaderOption {
	return func(c *NanoTDFReaderConfig) error {
		c.rewrapper = rewrapper
		return nil
	}
}

func WithNanoIgnoreAllowlist(ignore bool) NanoTDFReaderOption {
	return func(c *NanoTDFReaderConfig) error {
		c.ignoreAllowList = ignore
		return nil
	}
}

func WithNanoTDFFulfillableObligationFQNs(fqns []string) NanoTDFReaderOption {
	return func(c *NanoTDFReaderConfig) error {
		c.fulfillableObligationFQNs = fqns
		return nil
	}
}
