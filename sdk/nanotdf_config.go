package sdk

import "github.com/opentdf/platform/lib/ocrypto"

type NanoTDFConfig struct {
	datasetMode        bool
	maxKeyIterations   uint64
	keyIterationCount  uint64
	eccMode            ocrypto.ECCMode
	keyPair            ocrypto.ECKeyPair
	mPrivateKey        string
	publicKey          string
	attributes         []string
	bufferSize         uint64
	signerPrivateKey   []byte
	cipher             cipherMode
	kasURL             resourceLocator
	mKasPublicKey      string
	mDefaultSalt       []byte
	EphemeralPublicKey eccKey
	sigCfg             signatureConfig
	policy             policyInfo

	binding bindingCfg
}
