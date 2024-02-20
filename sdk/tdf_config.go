package sdk

import (
	"fmt"

	"github.com/opentdf/platform/sdk/internal/crypto"
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

type TDFConfig struct {
	defaultSegmentSize        int64
	enableEncryption          bool
	tdfFormat                 TDFFormat
	tdfPublicKey              string // TODO: Remove it
	tdfPrivateKey             string
	metaData                  string
	integrityAlgorithm        IntegrityAlgorithm
	segmentIntegrityAlgorithm IntegrityAlgorithm
	assertions                []Assertion
	attributes                []string
	kasInfoList               []KASInfo
}

const (
	tdf3KeySize        = 2048
	defaultSegmentSize = 2 * 1024 * 1024 // 2mb
	kasPublicKeyPath   = "/kas_public_key"
)

// NewTDFConfig CreateTDF a new instance of tdf config.
func NewTDFConfig() (*TDFConfig, error) {
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

	return &TDFConfig{
		tdfPrivateKey:             privateKey,
		tdfPublicKey:              publicKey,
		defaultSegmentSize:        defaultSegmentSize,
		enableEncryption:          true,
		tdfFormat:                 JSONFormat,
		integrityAlgorithm:        HS256,
		segmentIntegrityAlgorithm: GMAC,
	}, nil
}

func NewKasInfo(url string) KASInfo {
	return KASInfo{url: url}
}

// AddKasInformation Add all the kas urls and their corresponding public keys
// that is required to create and read the tdf.
func (tdfConfig *TDFConfig) AddKasInformation(unwrapper Unwrapper, kasInfoList []KASInfo) error {
	for _, kasInfo := range kasInfoList {
		newEntry := KASInfo{}
		newEntry.url = kasInfo.url
		if kasInfo.publicKey == "" {
			pk, err := unwrapper.GetKASPublicKey(kasInfo)
			if err != nil {
				return err
			}
			newEntry.publicKey = pk
		} else {
			newEntry.publicKey = kasInfo.publicKey
		}

		tdfConfig.kasInfoList = append(tdfConfig.kasInfoList, newEntry)
	}

	return nil
}

// AddAttributes Add all the attributes used to create and read the tdf.
func (tdfConfig *TDFConfig) AddAttributes(attributes []string) {
	tdfConfig.attributes = append(tdfConfig.attributes, attributes...)
}

// SetMetaData Set the meta data.
func (tdfConfig *TDFConfig) SetMetaData(metaData string) {
	tdfConfig.metaData = metaData
}

// SetDefaultSegmentSize Set the default segment size.
func (tdfConfig *TDFConfig) SetDefaultSegmentSize(size int64) {
	tdfConfig.defaultSegmentSize = size
}

// SetXMLFormat TDFs created with this config will be in XML format.
func (tdfConfig *TDFConfig) SetXMLFormat() {
	tdfConfig.tdfFormat = XMLFormat
}

// DisableEncryption TDFs create with this config will not be encrypted.
func (tdfConfig *TDFConfig) DisableEncryption() {
	tdfConfig.enableEncryption = false
}
