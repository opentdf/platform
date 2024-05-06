package sdk

import (
	"bufio"
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
	m_cipher           cipherMode
	m_kasURL           resourceLocator
}

type NanoTDF struct {
	header                NanoTDFHeader
	config                NanoTDFConfig
	m_initialized         bool
	m_keyIterationCount   int
	policyObj             PolicyObject
	m_compressedPubKey    []byte
	m_iv                  uint64
	m_authTag             []byte
	m_workingBuffer       []byte
	m_encryptSymmetricKey []byte
	m_signature           []byte
	policyObjectAsStr     []byte
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

func (resourceLocator) isPolicyBody()      {}
func (rl resourceLocator) getBody() string { return rl.body }

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
	getBody() string
}

type policyInfo struct {
	mode    uint8
	body    PolicyBody
	binding *eccSignature
}

type remotePolicy struct {
	url *resourceLocator
}

func (remotePolicy) isPolicyBody()      {}
func (rp remotePolicy) getBody() string { return rp.url.body }

type embeddedPolicy struct {
	lengthBody uint16
	body       string
}

func (embeddedPolicy) isPolicyBody()      {}
func (ep embeddedPolicy) getBody() string { return ep.body }

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

// Binding config byte format
// ---------------------------------
// | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
// ---------------------------------
// | E | M | M | M | x | x | x | x |
// ---------------------------------
// bit 8 - use ECDSA
// bit 5-7 - eccMode
// bit 1-4 - padding

// deserializeBindingCfg - read byte of binding config into bindingCfg struct
func deserializeBindingCfg(b byte) *bindingCfg {
	cfg := bindingCfg{}
	cfg.useEcdsaBinding = (b >> 7 & 0x01) == 1
	cfg.padding = 0
	cfg.bindingBody = ocrypto.ECCMode((b >> 4) & 0x07)

	return &cfg
}

// serializeBindingCfg - take info from bindingConfig struct and encode as single byte
func serializeBindingCfg(bindCfg *bindingCfg) byte {
	var bindSerial byte = 0x00

	if bindCfg.useEcdsaBinding {
		bindSerial |= 0x80
	}
	bindSerial |= byte((bindCfg.bindingBody)&0x07) << 4

	return bindSerial
}

// Signature config byte format
// ---------------------------------
// | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
// ---------------------------------
// | S | M | M | M | C | C | C | C |
// ---------------------------------
// bit 8 - has signature
// bit 5-7 - eccMode
// bit 1-4 - cipher

// deserializeSignatureCfg - read byte of signature config into signatureCfg struct
func deserializeSignatureCfg(b byte) *signatureConfig {
	cfg := signatureConfig{}
	cfg.hasSignature = (b >> 7 & 0x01) == 1
	cfg.signatureMode = ocrypto.ECCMode((b >> 4) & 0x07)
	cfg.cipher = cipherMode(b & 0x0F)

	return &cfg
}

// serializeSignatureCfg - take info from signatureConfig struct and encode as single byte
func serializeSignatureCfg(sigCfg signatureConfig) byte {
	var sigSerial byte = 0x00

	if sigCfg.hasSignature {
		sigSerial |= 0x80
	}
	sigSerial |= byte((sigCfg.signatureMode)&0x07) << 4
	sigSerial |= byte((sigCfg.cipher) & 0x0F)

	return sigSerial
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

func writePolicyBody(writer io.Writer, h *NanoTDFHeader) error {
	var err error = nil

	switch h.policy.mode {
	case 0: // remote policy - resource locator
		// TODO FIXME - get real value from resourceLocator
		if err = binary.Write(writer, binary.BigEndian, uint8(urlProtocolHTTPS)); err != nil {
			return err
		}
		var reBody = h.policy.body.getBody()
		if err = binary.Write(writer, binary.BigEndian, uint8(len(reBody))); err != nil {
			return err
		}
		if err = binary.Write(writer, binary.BigEndian, []byte(reBody)); err != nil {
			return err
		}
		return nil
	default: // embedded policy - inline
		var emBody = h.policy.body.getBody()
		if err := binary.Write(writer, binary.BigEndian, uint8(len(emBody))); err != nil {
			return err
		}
		if err := binary.Write(writer, binary.BigEndian, []byte(emBody)); err != nil {
			return err
		}
	}
	return err
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

	// TODO FIXME - should be constants
	nanoTDF.header.magicNumber[0] = 'L'
	nanoTDF.header.magicNumber[1] = '1'
	nanoTDF.header.magicNumber[2] = 'L'

	// TODO FIXME - gotta be a better way to do this copy
	nanoTDF.header.kasURL = &resourceLocator{nanoTDF.config.m_kasURL.protocol, nanoTDF.config.m_kasURL.lengthBody, nanoTDF.config.m_kasURL.body}

	// TODO FIXME - put real values in here
	nanoTDF.header.binding = new(bindingCfg)
	nanoTDF.header.binding.useEcdsaBinding = true
	nanoTDF.header.binding.bindingBody = nanoTDF.config.m_eccMode

	// TODO FIXME - put real values here
	nanoTDF.header.sigCfg = new(signatureConfig)
	nanoTDF.header.sigCfg.hasSignature = true
	nanoTDF.header.sigCfg.signatureMode = nanoTDF.config.m_eccMode
	nanoTDF.header.sigCfg.cipher = nanoTDF.config.m_cipher

	// TODO FIXME - put real values here
	var rlBody resourceLocator
	rlBody.protocol = urlProtocolHTTPS
	rlBody.body = "https://resource.virtru.com"

	rlBody.lengthBody = uint8(len(rlBody.body))
	nanoTDF.header.policy = new(policyInfo)
	nanoTDF.header.policy.mode = uint8(0)
	nanoTDF.header.policy.body = rlBody

	// TODO FIXME - put real values here
	nanoTDF.header.EphemeralPublicKey = new(eccKey)

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

func writeHeader(n *NanoTDFHeader, writer io.Writer) error {

	var err error = nil

	if err = binary.Write(writer, binary.BigEndian, n.magicNumber); err != nil {
		return err
	}
	if err = binary.Write(writer, binary.BigEndian, n.kasURL.protocol); err != nil {
		return err
	}
	// Note that written length is based on actual string, not the bodylength element in kasURL
	if err = binary.Write(writer, binary.BigEndian, uint8(len(n.kasURL.body))); err != nil {
		return err
	}

	if err = binary.Write(writer, binary.BigEndian, []byte(n.kasURL.body)); err != nil {
		return err
	}
	if err = binary.Write(writer, binary.BigEndian, serializeBindingCfg(n.binding)); err != nil {
		return err
	}

	signatureByte := serializeSignatureCfg(*n.sigCfg)
	if err := binary.Write(writer, binary.BigEndian, signatureByte); err != nil {
		return err
	}

	if err = writePolicyBody(writer, n); err != nil {
		return err
	}
	if err = binary.Write(writer, binary.BigEndian, n.EphemeralPublicKey.Key); err != nil {
		return err
	}

	return err
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

	nanoBuffer, err := NanoTDFEncrypt(config, *plaintextBuffer)
	if err != nil {
		return err
	}

	_, err = encryptedFile.Seek(0, 0)
	if err != nil {
		return err
	}

	_, err = encryptedFile.Write(nanoBuffer)
	return err
}

func NanoTDFToBuffer(nanoTDF NanoTDF) ([]byte, error) {
	return nanoTDF.m_workingBuffer, nil
}

func NanoTDFEncrypt(config NanoTDFConfig, plaintextBuffer bytes.Buffer) ([]byte, error) {
	var err error = nil

	// config is fixed at this point, make a copy
	nanoTDF := NanoTDF{}
	nanoTDF.config = config

	err = createHeader(&nanoTDF)
	if err != nil {
		return nil, err
	}

	encryptBuffer := bytes.NewBuffer(make([]byte, 0, config.m_bufferSize))
	ebWriter := bufio.NewWriter(encryptBuffer)
	err = writeHeader(&nanoTDF.header, ebWriter)
	if err != nil {
		return nil, err
	}

	///
	/// Add the length of cipher text to output - (IV + Cipher Text + Auth tag)
	///

	// TODO FIXME
	authTagSize := 1024
	// TODO FIXME
	bytesAdded := 0

	encryptedDataSize := kNanoTDFIvSize + plaintextBuffer.Len() + authTagSize

	// TODO FIXME
	cipherTextSize := uint64(encryptedDataSize + kNanoTDFIvSize + kIvPadding)

	if err := binary.Write(ebWriter, binary.BigEndian, &cipherTextSize); err != nil {
		return nil, err
	}

	// Encrypt the payload into the working buffer
	{
		ivSizeWithPadding := kIvPadding + kNanoTDFIvSize
		iv := bytes.NewBuffer(make([]byte, 0, ivSizeWithPadding))

		// Reset the IV after max iterations
		if nanoTDF.config.m_maxKeyIterations == nanoTDF.m_keyIterationCount {
			nanoTDF.m_iv = 1
			if nanoTDF.config.m_datasetMode {
				nanoTDF.m_keyIterationCount = 0
			}
		}

		if err := binary.Write(ebWriter, binary.BigEndian, &nanoTDF.m_iv); err != nil {
			return nil, err
		}
		nanoTDF.m_iv += 1

		// Resize the auth tag.
		newAuthTag := make([]byte, authTagSize)
		copy(newAuthTag, nanoTDF.m_authTag)

		aesGcm, err := ocrypto.NewAESGcm(nanoTDF.m_encryptSymmetricKey)
		if err != nil {
			return nil, err
		}

		// Convert the uint64 IV value to bytes
		byteIv := make([]byte, 8)
		binary.BigEndian.PutUint64(byteIv, nanoTDF.m_iv)

		// Encrypt the plaintext
		encryptedText, err := aesGcm.EncryptWithIV(byteIv, plaintextBuffer.Bytes())
		if err != nil {
			return nil, err
		}

		// TODO FIXME - need real length here
		payloadBuffer := bytes.NewBuffer(make([]byte, 0, len(encryptedText)))
		pbWriter := bufio.NewWriter(payloadBuffer)

		// Copy IV at start
		err = binary.Write(pbWriter, binary.BigEndian, iv)
		if err != nil {
			return nil, err
		}

		// Copy tag at end
		err = binary.Write(pbWriter, binary.BigEndian, nanoTDF.m_authTag)
		if err != nil {
			return nil, err
		}
	}

	// Copy the payload buffer contents into encrypt buffer without the IV padding.
	pbContentsWithoutIv := &nanoTDF.m_workingBuffer[kIvPadding]

	binary.Write(ebWriter, binary.BigEndian, pbContentsWithoutIv)

	// Adjust the buffer

	bytesAdded += encryptedDataSize

	// Digest(header + payload) for signature
	digest := sha256.Sum256(encryptBuffer.Bytes())

	/*
	   	#if DEBUG_LOG
	   		auto digestData = base64Encode(toBytes(digest));
	   std::cout << "Encrypt digest: " << digestData << std::endl;
	   	#endif
	*/

	if nanoTDF.config.m_hasSignature {
		signerPrivateKey := nanoTDF.config.m_signerPrivateKey
		signerPublicKey := ocrypto.GetPEMPublicKeyFromPrivateKey(signerPrivateKey, nanoTDF.config.m_eccMode)
		compressedPubKey, err := ocrypto.CompressedECPublicKey(nanoTDF.config.m_eccMode, signerPublicKey)
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

		// Calculate the signature.
		signature := ocrypto.ComputeECDSASig(digest, signerPrivateKey)
		/* #if DEBUG_LOG
				auto sigData = base64Encode(toBytes(m_signature));
		std::cout << "Encrypt signature: " << sigData << std::endl;
			#endif

		*/

		// Add the signature and update the count of bytes added.
		binary.Write(ebWriter, binary.BigEndian, &signature)

		// Adjust the buffer
		bytesAdded += len(signature)
	}

	if nanoTDF.config.m_datasetMode {
		nanoTDF.m_keyIterationCount += 1
	}

	return encryptBuffer.Bytes(), err
}
