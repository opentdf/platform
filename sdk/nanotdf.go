//nolint:gomnd // nanotdf magics and lengths are inlined for clarity
package sdk

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

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

const (
	ErrNanoTdfRead = Error("nanotdf read error")
)

type NanoTDFHeader struct {
	magicNumber        [3]byte
	kasUrl             *resourceLocator
	binding            *bindingCfg
	sigCfg             *signatureConfig
	policy             *policyInfo
	EphemeralPublicKey *eccKey

	m_keyIterationCount int
	m_datasetMode       bool
	m_eccMode           ocrypto.ECCMode
	policyObj           PolicyObject
	m_initialized       bool
	m_compressedPubKey  []byte
}

func (h NanoTDFHeader) SetDatasetMode(mode bool) {
	 h.m_datasetMode = mode
}

func (h NanoTDFHeader) SetECCMode(curveType ocrypto.ECCMode) {
	h.m_eccMode = curveType
}

type NanoTDFConfig struct {
	m_datasetMode bool

	m_maxKeyIterations  int
	m_ellipticCurveType ocrypto.ECCMode
	m_keyPair           ocrypto.ECKeyPair
	m_privateKey        string
	m_publicKey         string
	attributes          []string
	m_bufferSize        uint64
}



func (h NanoTDFConfig) SetECCMode(r1 ocrypto.ECCMode) {
	h.m_ellipticCurveType = r1
}

func (h NanoTDFConfig) SetDatasetMode(b bool) {
	h.m_datasetMode = b;
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
	urlProtocolHttp   urlProtocol = 0
	urlProtocolHttps  urlProtocol = 1
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
		return embeddedPolicy(embedPolicy), nil
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
	default:
		return nil, Error("invalid curve value")
	}
	buffer := make([]byte, numberOfBytes)
	if err := binary.Read(reader, binary.BigEndian, &buffer); err != nil {
		return nil, errors.Join(ErrNanoTdfRead, err)
	}
	return &eccKey{Key: buffer}, nil
}

func ReadNanoTDFHeader(reader io.Reader) (*NanoTDFHeader, error) {
	var nanoTDF NanoTDFHeader

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

	return &nanoTDF, err
}

func createHeader(header *NanoTDFHeader, config NanoTDFConfig) (error) {
	var err error = nil

	// First time initialization
	if (header.m_initialized == false) {
		header.SetECCMode(config.m_ellipticCurveType)
		header.SetDatasetMode(config.m_datasetMode)
		header.m_initialized = true
	}

	if (config.m_datasetMode && // In data set mode
		header.m_keyIterationCount > 0 && // Not the first iteration
		header.m_keyIterationCount != config.m_maxKeyIterations) { // Didn't reach the max iteration

		//LogDebug("Reusing the header for dataset");

		// Use the old header.
		return err
	}

	if (config.m_datasetMode && (config.m_maxKeyIterations == header.m_keyIterationCount)) {
		var sdkECKeyPair, err = ocrypto.NewECKeyPair(config.m_ellipticCurveType);
		if err != nil {return err}
		config.m_privateKey, err = sdkECKeyPair.PrivateKeyInPemFormat()
		if err != nil {return err}
		config.m_publicKey, err = sdkECKeyPair.PublicKeyInPemFormat()
		if err != nil {return err}
		config.m_keyPair = sdkECKeyPair

		header.m_compressedPubKey, err = ocrypto.CompressedECPublicKey(config.m_ellipticCurveType, config.m_keyPair.PrivateKey.PublicKey);

		// Create a new policy.
		header.policyObj, err := createPolicyObject(config.attributes)
		if err != nil {
			return fmt.Errorf("fail to create policy object:%w", err)
		}

		policyObjectAsStr, err := json.Marshal(header.policyObj)
		if err != nil {
			return fmt.Errorf("json.Marshal failed:%w", err)
		}

		//LogDebug("Max iteration reached - create new header for dataset");
	}
	return err
}

func writeHeader(n *NanoTDFHeader, buffer *bytes.Buffer) {

}

func NanoTDFEncrypt(config NanoTDFConfig, plaintextBuffer bytes.Buffer, writer io.Writer) (error) {
	var err error = nil
	var header NanoTDFHeader

	encryptBuffer := bytes.NewBuffer(make([]byte, 0, config.m_bufferSize))

	err = createHeader(&header, config)
	if err != nil {return err}

	writeHeader(&header, encryptBuffer)

	///
	/// Add the length of cipher text to output - (IV + Cipher Text + Auth tag)
	///

	// TODO FIXME
	kNanoTDFIvSize := 2048
	kIvPadding := 128
	// TODO FIXME
	authTagSize := 1024

	encryptedDataSize := kNanoTDFIvSize + plaintextBuffer.Len() + authTagSize
/*
	copy(encryptBuffer.data(), &cipherTextSize, sizeof(cipherTextSize))

	// Encrypt the payload into the working buffer
	{
	ivSizeWithPadding := kIvPadding + kNanoTDFIvSize;
	std::array<gsl::byte, ivSizeWithPadding> iv{};

	// Reset the IV after max iterations
	if (m_maxKeyIterations == m_keyIterationCount) {
	m_iv = 1;
	if (m_datasetMode) {
	m_keyIterationCount = 0;
	}
	}

	auto ivBufferSpan = toWriteableBytes(iv).last(kNanoTDFIvSize);
	boost::endian::big_uint24_t ivAsNetworkOrder = m_iv;
	std::memcpy(ivBufferSpan.data(), &ivAsNetworkOrder, kNanoTDFIvSize);
	m_iv += 1;

	// Resize the auth tag.
	m_authTag.resize(authTagSize);

	// Adjust the span to add the IV vector at the start of the buffer after the encryption.
	auto payloadBufferSpan = payloadBuffer.subspan(ivSizeWithPadding);

	auto encoder = GCMEncryption::create(toBytes(m_encryptSymmetricKey), iv);
	encoder->encrypt(toBytes(plainData), payloadBufferSpan);

	auto authTag = WriteableBytes{m_authTag};
	encoder->finish(authTag);

	// Copy IV at start
	copy(iv.begin(), iv.end(), payloadBuffer.begin());

	// Copy tag at end
	copy(m_authTag.begin(), m_authTag.end(), payloadBuffer.begin() + ivSizeWithPadding + plainData.size());
	}

	// Copy the payload buffer contents into encrypt buffer without the IV padding.
std::copy(m_workingBuffer.begin() + kIvPadding, m_workingBuffer.end(),
		encryptBuffer.begin());

	// Adjust the buffer
	bytesAdded += encryptedDataSize;
	encryptBuffer = encryptBuffer.subspan(encryptedDataSize);

	// Digest(header + payload) for signature
	digest = calculateSHA256({m_encryptBuffer.data(), static_cast<gsl::span<const std::byte,-1>::index_type>(bytesAdded)});

	#if DEBUG_LOG
		auto digestData = base64Encode(toBytes(digest));
std::cout << "Encrypt digest: " << digestData << std::endl;
	#endif

	if (m_tdfBuilder.m_impl->m_hasSignature) {
		const auto& signerPrivateKey = m_tdfBuilder.m_impl->m_signerPrivateKey;
		auto curveName = ECCMode::GetEllipticCurveName(m_tdfBuilder.m_impl->m_signatureECCMode);
		auto signerPublicKey = ECKeyPair::GetPEMPublicKeyFromPrivateKey(signerPrivateKey, curveName);
		auto compressedPubKey = ECKeyPair::CompressedECPublicKey(signerPublicKey);

		// Add the signer public key
	std::memcpy(encryptBuffer.data(), compressedPubKey.data(), compressedPubKey.size());

		#if DEBUG_LOG
			auto signerData = base64Encode(toBytes(compressedPubKey));
	std::cout << "Encrypt signer public key: " << signerData << std::endl;
		#endif
		// Adjust the buffer
		bytesAdded += compressedPubKey.size();
		encryptBuffer = encryptBuffer.subspan(compressedPubKey.size());

		// Calculate the signature.
		m_signature = ECKeyPair::ComputeECDSASig(toBytes(digest), signerPrivateKey);
		#if DEBUG_LOG
			auto sigData = base64Encode(toBytes(m_signature));
	std::cout << "Encrypt signature: " << sigData << std::endl;
		#endif

		// Add the signature and update the count of bytes added.
	std::memcpy(encryptBuffer.data(), m_signature.data(), m_signature.size());

		// Adjust the buffer
		bytesAdded += m_signature.size();
	}

	if (m_datasetMode) {
		m_keyIterationCount += 1;
	}

	return { reinterpret_cast<const char*>(m_encryptBuffer.data()), bytesAdded};
*/
return err
}


