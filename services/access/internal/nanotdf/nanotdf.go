package nanotdf

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	ErrNanoTdfRead = Error("nanotdf read error")
)

type nanoTdf struct {
	magicNumber        [3]byte
	kasUrl             *resourceLocator
	binding            *bindingCfg
	sigCfg             *signatureConfig
	policy             *policyInfo
	EphemeralPublicKey *eccKey
}

type resourceLocator struct {
	protocol   urlProtocol
	lengthBody uint8
	body       string
}

func (resourceLocator) isPolicyBody() {}

type bindingCfg struct {
	useEcdsaBinding bool
	padding         uint8
	bindingBody     eccMode
}

type signatureConfig struct {
	hasSignature  bool
	signatureMode eccMode
	cipher        cipherMode
}

type PolicyBody interface {
	isPolicyBody() // marker method to ensure interface implementation
}

type policyInfo struct {
	mode    uint8
	body    PolicyBody
	binding *eccSignature
}

type remotePolicy struct {
	url *resourceLocator
}

func (remotePolicy) isPolicyBody() {}

type embeddedPolicy struct {
	lengthBody uint16
	body       string
}

func (embeddedPolicy) isPolicyBody() {}

type eccSignature struct {
	value []byte
}

type eccKey struct {
	Key []byte
}

type urlProtocol uint8

const (
	urlProtocolHttp   urlProtocol = 0
	urlProtocolHttps  urlProtocol = 1
	urlProtocolShared urlProtocol = 255
)

type eccMode uint8

const (
	eccModeSecp256r1 eccMode = 0
	eccModeSecp384r1 eccMode = 1
	eccModeSecp521r1 eccMode = 2
	eccModeSecp256k1 eccMode = 3
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
	cfg.bindingBody = eccMode((b >> 4) & 0x07)

	return &cfg
}

func deserializeSignatureCfg(b byte) *signatureConfig {
	cfg := signatureConfig{}
	cfg.hasSignature = (b >> 7 & 0x01) == 1
	cfg.signatureMode = eccMode((b >> 4) & 0x07)
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
		return embeddedPolicy(embedPolicy), nil
	}
}

func readEphemeralPublicKey(reader io.Reader, curve eccMode) (*eccKey, error) {
	var numberOfBytes uint8
	switch curve {
	case eccModeSecp256r1:
		numberOfBytes = 33
	case eccModeSecp384r1:
		numberOfBytes = 49
	case eccModeSecp521r1:
		numberOfBytes = 67
	}
	buffer := make([]byte, numberOfBytes)
	if err := binary.Read(reader, binary.BigEndian, &buffer); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	return &eccKey{Key: buffer}, nil
}

func ReadNanoTDFHeader(reader io.Reader) (*nanoTdf, error) {

	var nanoTDF nanoTdf

	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.magicNumber); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}

	nanoTDF.kasUrl = &resourceLocator{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.kasUrl.protocol); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.kasUrl.lengthBody); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	body := make([]byte, nanoTDF.kasUrl.lengthBody)
	if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	nanoTDF.kasUrl.body = string(body)

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

	nanoTDF.policy = &policyInfo{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.policy.mode); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	policyBody, err := readPolicyBody(reader, nanoTDF.policy.mode)
	if err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}

	nanoTDF.policy.body = policyBody

	nanoTDF.policy.binding = &eccSignature{}
	nanoTDF.policy.binding.value = make([]byte, 8)
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.policy.binding.value); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}

	nanoTDF.EphemeralPublicKey = &eccKey{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.EphemeralPublicKey.Key); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	nanoTDF.EphemeralPublicKey, err = readEphemeralPublicKey(reader, nanoTDF.binding.bindingBody)

	return &nanoTDF, nil
}

type Error string

func (e Error) Error() string {
	return string(e)
}
