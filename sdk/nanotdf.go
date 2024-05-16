//nolint:gomnd // nanotdf magics and lengths are inlined for clarity
package sdk

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	ErrNanoTdfRead = Error("nanotdf read error")
)

type NanoTdf struct {
	magicNumber        [3]byte
	kasURL             *resourceLocator
	binding            *bindingCfg
	sigCfg             *signatureConfig
	Policy             *policyInfo
	EphemeralPublicKey *eccKey
}

type resourceLocator struct {
	protocol   urlProtocol
	lengthBody uint8
	body       string
}

func (resourceLocator) isPolicyBody() {} //nolint:unused marker method to ensure interface implementation

type bindingCfg struct {
	useEcdsaBinding bool
	padding         uint8
	bindingBody     ocrypto.ECCMode
}

type signatureConfig struct {
	hasSignature  bool
	signatureMode ocrypto.ECCMode
	cipher        cipherMode
}

type PolicyBody interface {
	isPolicyBody() // marker method to ensure interface implementation
	GetPolicyBody() string
}

type policyInfo struct {
	mode    uint8
	Body    PolicyBody
	binding *eccSignature
}

type remotePolicy struct {
	url *resourceLocator
}

func (remotePolicy) isPolicyBody() {}
func (rp remotePolicy) GetPolicyBody() string {
	return rp.url.body
}

type embeddedPolicy struct {
	lengthBody uint16
	body       string
}

func (embeddedPolicy) isPolicyBody() {}
func (ep embeddedPolicy) GetPolicyBody() string {
	return ep.body
}

type eccSignature struct {
	value []byte
}

type eccKey struct {
	Key []byte
}

type urlProtocol uint8

const (
	urlProtocolHTTP   urlProtocol = 0
	urlProtocolHTTPS  urlProtocol = 1
	urlProtocolShared urlProtocol = 255
)

type cipherMode int

const (
	cipherModeAes256gcm64Bit  cipherMode = 0
	cipherModeAes256gcm96Bit  cipherMode = 1
	cipherModeAes256gcm104Bit cipherMode = 2
	cipherModeAes256gcm112Bit cipherMode = 3
	cipherModeAes256gcm120Bit cipherMode = 4
	cipherModeAes256gcm128Bit cipherMode = 5
)

type policyType uint8

const (
	policyTypeRemotePolicy                           policyType = 0
	policyTypEmbeddedPolicyPainText                  policyType = 1
	policyTypeEmbeddedPolicyEncrypted                policyType = 2
	policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess policyType = 3
)

func deserializeBindingCfg(b byte) *bindingCfg {
	cfg := bindingCfg{}
	cfg.useEcdsaBinding = (b >> 7 & 0x01) == 1
	cfg.padding = 0
	cfg.bindingBody = ocrypto.ECCMode((b >> 4) & 0x07)

	return &cfg
}

func deserializeSignatureCfg(b byte) *signatureConfig {
	cfg := signatureConfig{}
	cfg.hasSignature = (b >> 7 & 0x01) == 1
	cfg.signatureMode = ocrypto.ECCMode((b >> 4) & 0x07)
	cfg.cipher = cipherMode(b & 0x0F)

	return &cfg
}

func readPolicyBody(reader io.Reader, mode uint8) (PolicyBody, error) {
	switch mode {
	case 0:
		var resourceLoc resourceLocator
		if err := binary.Read(reader, binary.BigEndian, &resourceLoc.protocol); err != nil {
			return nil, errors.Join(ErrNanoTdfRead, err)
		}
		if err := binary.Read(reader, binary.BigEndian, &resourceLoc.lengthBody); err != nil {
			return nil, errors.Join(ErrNanoTdfRead, err)
		}
		body := make([]byte, resourceLoc.lengthBody)
		if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
			return nil, errors.Join(ErrNanoTdfRead, err)
		}
		resourceLoc.body = string(body)
		return remotePolicy{url: &resourceLoc}, nil
	default:
		var embedPolicy embeddedPolicy
		if err := binary.Read(reader, binary.BigEndian, &embedPolicy.lengthBody); err != nil {
			return nil, errors.Join(ErrNanoTdfRead, err)
		}
		body := make([]byte, embedPolicy.lengthBody)
		if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
			return nil, errors.Join(ErrNanoTdfRead, err)
		}
		embedPolicy.body = string(body)
		return embedPolicy, nil
	}
}

func readEphemeralPublicKey(reader io.Reader, curve ocrypto.ECCMode) (*eccKey, error) {
	var numberOfBytes uint8
	switch curve {
	case ocrypto.ECCModeSecp256r1:
		numberOfBytes = 33
	case ocrypto.ECCModeSecp256k1:
		numberOfBytes = 33
	case ocrypto.ECCModeSecp384r1:
		numberOfBytes = 49
	case ocrypto.ECCModeSecp521r1:
		numberOfBytes = 67
	}
	buffer := make([]byte, numberOfBytes)
	if err := binary.Read(reader, binary.BigEndian, &buffer); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	return &eccKey{Key: buffer}, nil
}

func ReadNanoTDFHeader(reader io.Reader) (*NanoTdf, error) {
	var nanoTDF NanoTdf

	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.magicNumber); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}

	nanoTDF.kasURL = &resourceLocator{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.kasURL.protocol); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.kasURL.lengthBody); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	body := make([]byte, nanoTDF.kasURL.lengthBody)
	if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	nanoTDF.kasURL.body = string(body)

	var bindingByte uint8
	if err := binary.Read(reader, binary.BigEndian, &bindingByte); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	nanoTDF.binding = deserializeBindingCfg(bindingByte)

	var signatureByte uint8
	if err := binary.Read(reader, binary.BigEndian, &signatureByte); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	nanoTDF.sigCfg = deserializeSignatureCfg(signatureByte)

	nanoTDF.Policy = &policyInfo{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.Policy.mode); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	policyBody, err := readPolicyBody(reader, nanoTDF.Policy.mode)
	if err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}

	nanoTDF.Policy.Body = policyBody

	nanoTDF.Policy.binding = &eccSignature{}
	nanoTDF.Policy.binding.value = make([]byte, 8)
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.Policy.binding.value); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}

	nanoTDF.EphemeralPublicKey = &eccKey{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.EphemeralPublicKey.Key); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	nanoTDF.EphemeralPublicKey, err = readEphemeralPublicKey(reader, nanoTDF.binding.bindingBody)

	return &nanoTDF, err
}
