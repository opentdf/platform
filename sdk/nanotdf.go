package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/opentdf/platform/lib/ocrypto"
)

/******************************** Header**************************
  | Section            | Minimum Length (B)  | Maximum Length (B)  |
  |--------------------|---------------------|---------------------|
  | Magic Number       | 2                   | 2                   |
  | Version            | 1                   | 1                   |
  | KAS                | 3                   | 257                 |
  | ECC Mode           | 1                   | 1                   |
  | Payload + Sig Mode | 1                   | 1                   |
  | Policy             | 3                   | 257                 |
  | Ephemeral Key      | 33                  | 67                  |
  ********************************* Header*************************/

type NanoTDFHeader struct {
	magicNumber        [3]byte
	kasURL             *resourceLocator
	binding            *bindingCfg
	sigCfg             *signatureConfig
	policy             *policyInfo
	EphemeralPublicKey *eccKey
}

type NanoTDFConfig struct {
	m_datasetMode      bool
	m_maxKeyIterations int
	m_eccMode          ocrypto.ECCMode
	m_keyPair          ocrypto.ECKeyPair
	m_privateKey       string
	m_publicKey        string
	attributes         []string
	m_bufferSize       uint64
	m_hasSignature     bool
	m_signerPrivateKey []byte
}

type NanoTDF struct {
	header                NanoTDFHeader
	config                NanoTDFConfig
	m_initialized         bool
	m_keyIterationCount   int
	policyObj             PolicyObject
	m_compressedPubKey    []byte
	m_iv                  int
	m_authTag             []byte
	m_workingBuffer       []byte
	m_encryptSymmetricKey []byte
	m_signature           []byte
	policyObjectAsStr     string
}

// / Constants
const (
	kMaxTDFSize        = ((16 * 1024 * 1024) - 3 - 32) // 16 mb - 3(iv) - 32(max auth tag)
	kDatasetMaxMBBytes = 2097152                       // 2mb

	// Max size of the encrypted tdfs
	//  16mb payload
	// ~67kb of policy
	// 133 of signature
	kMaxEncryptedNTDFSize = (16 * 1024 * 1024) + (68 * 1024) + 133

	kIvPadding         = 9
	kNanoTDFIvSize     = 3
	kNanoTDFGMACLength = 8
	kNanoTDFHeader     = "header"
)

func (c NanoTDFConfig) SetECCMode(r1 ocrypto.ECCMode) {
	c.m_eccMode = r1
}

func (c NanoTDFConfig) SetDatasetMode(b bool) {
	c.m_datasetMode = b
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
	bindingBody     ocrypto.ECCMode
}

type signatureConfig struct {
	hasSignature  bool
	signatureMode ocrypto.ECCMode
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

const (
	ErrNanoTDFHeaderRead = Error("nanoTDF read error")
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
			return nil, errors.Join(ErrNanoTDFHeaderRead, err)
		}
		if err := binary.Read(reader, binary.BigEndian, &resourceLoc.lengthBody); err != nil {
			return nil, errors.Join(ErrNanoTDFHeaderRead, err)
		}
		body := make([]byte, resourceLoc.lengthBody)
		if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
			return nil, errors.Join(ErrNanoTDFHeaderRead, err)
		}
		resourceLoc.body = string(body)
		return remotePolicy{url: &resourceLoc}, nil
	default:
		var embedPolicy embeddedPolicy
		if err := binary.Read(reader, binary.BigEndian, &embedPolicy.lengthBody); err != nil {
			return nil, errors.Join(ErrNanoTDFHeaderRead, err)
		}
		body := make([]byte, embedPolicy.lengthBody)
		if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
			return nil, errors.Join(ErrNanoTDFHeaderRead, err)
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
	case ocrypto.ECCModeSecp384r1:
		numberOfBytes = 49
	case ocrypto.ECCModeSecp521r1:
		numberOfBytes = 67
	}
	buffer := make([]byte, numberOfBytes)
	if err := binary.Read(reader, binary.BigEndian, &buffer); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}
	return &eccKey{Key: buffer}, nil
}

func ReadNanoTDFHeader(reader io.Reader) (*NanoTDFHeader, error) {
	var nanoTDF NanoTDFHeader

	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.magicNumber); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}

	nanoTDF.kasURL = &resourceLocator{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.kasURL.protocol); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.kasURL.lengthBody); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}
	body := make([]byte, nanoTDF.kasURL.lengthBody)
	if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}
	nanoTDF.kasURL.body = string(body)

	var bindingByte uint8
	if err := binary.Read(reader, binary.BigEndian, &bindingByte); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}
	nanoTDF.binding = deserializeBindingCfg(bindingByte)

	var signatureByte uint8
	if err := binary.Read(reader, binary.BigEndian, &signatureByte); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}
	nanoTDF.sigCfg = deserializeSignatureCfg(signatureByte)

	nanoTDF.policy = &policyInfo{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.policy.mode); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}
	policyBody, err := readPolicyBody(reader, nanoTDF.policy.mode)
	if err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}

	nanoTDF.policy.body = policyBody

	nanoTDF.policy.binding = &eccSignature{}
	nanoTDF.policy.binding.value = make([]byte, 8)
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.policy.binding.value); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}

	nanoTDF.EphemeralPublicKey = &eccKey{}
	if err := binary.Read(reader, binary.BigEndian, &nanoTDF.EphemeralPublicKey.Key); err != nil {
		return nil, errors.Join(ErrNanoTDFHeaderRead, err)
	}
	nanoTDF.EphemeralPublicKey, err = readEphemeralPublicKey(reader, nanoTDF.binding.bindingBody)

	return &nanoTDF, err
}

func createHeader(nanoTDF *NanoTDF) error {
	var err error = nil

	if nanoTDF.config.m_datasetMode && // In data set mode
		nanoTDF.m_keyIterationCount > 0 && // Not the first iteration
		nanoTDF.m_keyIterationCount != nanoTDF.config.m_maxKeyIterations { // Didn't reach the max iteration

		//LogDebug("Reusing the header for dataset");

		// Use the old header.
		return err
	}

	if nanoTDF.config.m_datasetMode && (nanoTDF.config.m_maxKeyIterations == nanoTDF.m_keyIterationCount) {
		var sdkECKeyPair, err = ocrypto.NewECKeyPair(nanoTDF.config.m_eccMode)
		if err != nil {
			return err
		}
		nanoTDF.config.m_privateKey, err = sdkECKeyPair.PrivateKeyInPemFormat()
		if err != nil {
			return err
		}
		nanoTDF.config.m_publicKey, err = sdkECKeyPair.PublicKeyInPemFormat()
		if err != nil {
			return err
		}
		nanoTDF.config.m_keyPair = sdkECKeyPair

		nanoTDF.m_compressedPubKey, err = ocrypto.CompressedECPublicKey(nanoTDF.config.m_eccMode, nanoTDF.config.m_keyPair.PrivateKey.PublicKey)

		// Create a new policy.
		nanoTDF.policyObj, err = createPolicyObject(nanoTDF.config.attributes)
		if err != nil {
			return fmt.Errorf("fail to create policy object:%w", err)
		}

		nanoTDF.policyObjectAsStr, err = json.Marshal(nanoTDF.policyObj)
		if err != nil {
			return fmt.Errorf("json.Marshal failed:%w", err)
		}

		//LogDebug("Max iteration reached - create new header for dataset");
	}
	return err
}

func writeHeader(n *NanoTDFHeader, buffer *bytes.Buffer) {

}

// NanoTDFEncryptFile - read from supplied input file, write encrypted data to supplied output file
func NanoTDFEncryptFile(plaintextFile *os.File, encryptedFile *os.File, config NanoTDFConfig) error {

	var err error = nil

	plaintextSize, err := plaintextFile.Seek(0, 2)
	if err != nil {
		return err
	}

	plaintextBuffer := bytes.NewBuffer(make([]byte, 0, plaintextSize))

	_, err = plaintextFile.Read(plaintextBuffer.Bytes())
	if err != nil {
		return err
	}

	encryptedBuffer, err := NanoTDFEncrypt(config, *plaintextBuffer)
	if err != nil {
		return err
	}

	_, err = encryptedFile.Seek(0, 0)
	if err != nil {
		return err
	}

	_, err = encryptedFile.Write(encryptedBuffer)
	return err
}

func NanoTDFCreate(config NanoTDFConfig) (NanoTDF, error) {

	// config is fixed at this point, make a copy
	nanoTDF := NanoTDF{}
	nanoTDF.config = config

	err := createHeader(&nanoTDF)
	if err != nil {
		return nanoTDF, err
	}

	return nanoTDF, nil

}

func NanoTDFEncrypt(config NanoTDFConfig, plaintextBuffer bytes.Buffer) ([]byte, error) {
	var err error = nil
	var header NanoTDFHeader

	encryptBuffer := bytes.NewBuffer(make([]byte, 0, config.m_bufferSize))

	writeHeader(&header, encryptBuffer)

	///
	/// Add the length of cipher text to output - (IV + Cipher Text + Auth tag)
	///

	// TODO FIXME
	authTagSize := 1024
	// TODO FIXME
	bytesAdded := 0

	encryptedDataSize := kNanoTDFIvSize + plaintextBuffer.Len() + authTagSize

	// TODO FIXME
	cipherTextSize := encryptedDataSize + kNanoTDFIvSize + kIvPadding

	copy(encryptBuffer.Bytes(), ([]byte)(&cipherTextSize))

	// Encrypt the payload into the working buffer
	{
		ivSizeWithPadding := kIvPadding + kNanoTDFIvSize
		iv := bytes.NewBuffer(make([]byte, 0, ivSizeWithPadding))

		// Reset the IV after max iterations
		if header.m_maxKeyIterations == header.m_keyIterationCount {
			header.m_iv = 1
			if header.m_datasetMode {
				header.m_keyIterationCount = 0
			}
		}

		ivBufferSpan := iv.Bytes()
		ivAsNetworkOrder := header.m_iv
		copy(ivBufferSpan, ([]byte)(&ivAsNetworkOrder))
		header.m_iv += 1

		// Resize the auth tag.
		newAuthTag := make([]byte, authTagSize)
		copy(newAuthTag, header.m_authTag)
		header.m_authTag = newAuthTag

		// Adjust the span to add the IV vector at the start of the buffer after the encryption.
		payloadBufferSpan := &payloadBuffer[ivSizeWithPadding]

		GCMEncrypt(header.m_encryptSymmetricKey, iv, plaintextBuffer, payloadBufferSpan)

		authTag := ([]byte)(m_authTag)

		// Copy IV at start
		copy(iv, payloadBuffer)

		// Copy tag at end
		copy(header.m_authTag, payloadBuffer.bytes()+ivSizeWithPadding+plaintextBuffer.Len())
	}

	// Copy the payload buffer contents into encrypt buffer without the IV padding.
	copy(header.m_workingBuffer.Bytes()+kIvPadding, encryptBuffer.Bytes())

	// Adjust the buffer

	bytesAdded += encryptedDataSize
	encryptBuffer += encryptedDataSize

	// Digest(header + payload) for signature
	digest := sha256.Sum256(encryptBuffer.Bytes())

	/*
	   	#if DEBUG_LOG
	   		auto digestData = base64Encode(toBytes(digest));
	   std::cout << "Encrypt digest: " << digestData << std::endl;
	   	#endif
	*/

	if header.m_hasSignature {
		signerPrivateKey := header.m_signerPrivateKey
		signerPublicKey := ocrypto.GetPEMPublicKeyFromPrivateKey(signerPrivateKey, header.m_ellipticCurveType)
		compressedPubKey, err := ocrypto.CompressedECPublicKey(header.m_ellipticCurveType, signerPublicKey)
		if err != nil {
			return nil, err
		}

		// Add the signer public key
		copy(encryptBuffer.Bytes(), compressedPubKey)

		/*	#if DEBUG_LOG
					auto signerData = base64Encode(toBytes(compressedPubKey));
			std::cout << "Encrypt signer public key: " << signerData << std::endl;
				#endif

		*/
		// Adjust the buffer
		bytesAdded += len(compressedPubKey)
		encryptBuffer += len(compressedPubKey)

		// Calculate the signature.
		header.m_signature = ocrypto.ComputeECDSASig(digest, signerPrivateKey)
		/* #if DEBUG_LOG
				auto sigData = base64Encode(toBytes(m_signature));
		std::cout << "Encrypt signature: " << sigData << std::endl;
			#endif

		*/

		// Add the signature and update the count of bytes added.
		copy(encryptBuffer, header.m_signature)

		// Adjust the buffer
		bytesAdded += len(header.m_signature)
	}

	if header.m_datasetMode {
		header.m_keyIterationCount += 1
	}

	return encryptBuffer.Bytes(), err
}
