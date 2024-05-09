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

// / Constants
const (
	kMaxTDFSize        = ((16 * 1024 * 1024) - 3 - 32) //nolint:gomnd // 16 mb - 3(iv) - 32(max auth tag)
	kDatasetMaxMBBytes = 2097152                       // 2mb

	// Max size of the encrypted tdfs
	//  16mb payload
	// ~67kb of policy
	// 133 of signature
	kMaxEncryptedNTDFSize = (16 * 1024 * 1024) + (68 * 1024) + 133 //nolint:gomnd // See comment block above

	kIvPadding                    = 9
	kNanoTDFIvSize                = 3
	kNanoTDFGMACLength            = 8
	kNanoTDFHeader                = "header"
	kNanoTDFMagicStringAndVersion = "L1L"
	kUint64Size                   = 8 // 64 bits = 8 bytes
	kEccSignatureLength           = 8
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
	magicNumber        [len(kNanoTDFMagicStringAndVersion)]byte
	kasURL             *resourceLocator
	binding            *bindingCfg
	sigCfg             *signatureConfig
	policy             *policyInfo
	EphemeralPublicKey *eccKey
}

type NanoTDFConfig struct {
	mDatasetMode      bool
	mMaxKeyIterations int
	mEccMode          ocrypto.ECCMode
	mKeyPair          ocrypto.ECKeyPair
	mPrivateKey       string
	mPublicKey        string
	attributes        []string
	mBufferSize       uint64
	mHasSignature     bool
	mSignerPrivateKey []byte
	mCipher           cipherMode
	mKasURL           resourceLocator
	mKasPublicKey     string
	mDefaultSalt      []byte
}

type NanoTDF struct {
	header               NanoTDFHeader
	config               NanoTDFConfig
	mInitialized         bool
	mKeyIterationCount   int
	policyObj            PolicyObject
	mCompressedPubKey    []byte
	mIv                  uint64
	mAuthTag             []byte
	mWorkingBuffer       []byte
	mEncryptSymmetricKey []byte
	// mSignature           []byte
	policyObjectAsStr []byte
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
	// Shift to low nybble test low bit
	cfg.useEcdsaBinding = (b >> 7 & 0b00000001) == 1 //nolint:gomnd // better readability as literal
	// ignore padding
	cfg.padding = 0
	// shift to low nybble and use low 3 bits
	cfg.bindingBody = ocrypto.ECCMode((b >> 4) & 0b00000111) //nolint:gomnd // better readability as literal

	return &cfg
}

// serializeBindingCfg - take info from bindingConfig struct and encode as single byte
func serializeBindingCfg(bindCfg *bindingCfg) byte {
	var bindSerial byte = 0x00

	// Set high bit if ecdsa binding is enabled
	if bindCfg.useEcdsaBinding {
		bindSerial |= 0b10000000
	}
	// Mask value to low 3 bytes and shift to high nybble
	bindSerial |= (byte(bindCfg.bindingBody) & 0b00000111) << 4 //nolint:gomnd // better readability as literal

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

// deserializeSignatureCfg - decode byte of signature config into signatureCfg struct
func deserializeSignatureCfg(b byte) *signatureConfig {
	cfg := signatureConfig{}
	// Shift high bit down and mask to test for value
	cfg.hasSignature = (b >> 7 & 0b000000001) == 1 //nolint:gomnd // better readability as literal
	// Shift high nybble down and mask for eccmode value
	cfg.signatureMode = ocrypto.ECCMode((b >> 4) & 0b00000111) //nolint:gomnd // better readability as literal
	// Mask low nybble for cipher value
	cfg.cipher = cipherMode(b & 0b00001111) //nolint:gomnd // better readability as literal

	return &cfg
}

// serializeSignatureCfg - take info from signatureConfig struct and encode as single byte
func serializeSignatureCfg(sigCfg signatureConfig) byte {
	var sigSerial byte = 0x00

	// Set high bit if signature is enabled
	if sigCfg.hasSignature {
		sigSerial |= 0b10000000
	}
	// Mask low 3 bits of mode and shift to high nybble
	sigSerial |= byte((sigCfg.signatureMode)&0b00000111) << 4 //nolint:gomnd // better readability as literal
	// Mask low nybble of cipher
	sigSerial |= byte((sigCfg.cipher) & 0b00001111) //nolint:gomnd // better readability as literal

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
	var err error

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
	case ocrypto.ECCModeSecp256k1:
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
	nanoTDF.policy.binding.value = make([]byte, kEccSignatureLength)
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
	var err error

	if nanoTDF.config.mDatasetMode && // In data set mode
		nanoTDF.mKeyIterationCount > 0 && // Not the first iteration
		nanoTDF.mKeyIterationCount != nanoTDF.config.mMaxKeyIterations { // Didn't reach the max iteration
		// LogDebug("Reusing the header for dataset");
		// Use the old header.
		return err
	}

	// Set magic number in header, and generate default salt
	var i int
	for _, magicByte := range []byte(kNanoTDFMagicStringAndVersion) {
		nanoTDF.header.magicNumber[i] = magicByte
		i++
	}
	nanoTDF.config.mDefaultSalt = ocrypto.CalculateSHA256([]byte(kNanoTDFMagicStringAndVersion))

	// TODO FIXME - gotta be a better way to do this copy
	nanoTDF.header.kasURL = &resourceLocator{nanoTDF.config.mKasURL.protocol, nanoTDF.config.mKasURL.lengthBody, nanoTDF.config.mKasURL.body}

	// TODO FIXME - put real values in here
	nanoTDF.header.binding = new(bindingCfg)
	nanoTDF.header.binding.useEcdsaBinding = true
	nanoTDF.header.binding.bindingBody = nanoTDF.config.mEccMode

	// TODO FIXME - put real values here
	nanoTDF.header.sigCfg = new(signatureConfig)
	nanoTDF.header.sigCfg.hasSignature = true
	nanoTDF.header.sigCfg.signatureMode = nanoTDF.config.mEccMode
	nanoTDF.header.sigCfg.cipher = nanoTDF.config.mCipher

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

	if nanoTDF.config.mDatasetMode && (nanoTDF.config.mMaxKeyIterations == nanoTDF.mKeyIterationCount) { //nolint:nestif // error checking each operation
		var sdkECKeyPair, err = ocrypto.NewECKeyPair(nanoTDF.config.mEccMode)
		if err != nil {
			return err
		}
		nanoTDF.config.mPrivateKey, err = sdkECKeyPair.PrivateKeyInPemFormat()
		if err != nil {
			return err
		}
		nanoTDF.config.mPublicKey, err = sdkECKeyPair.PublicKeyInPemFormat()
		if err != nil {
			return err
		}
		nanoTDF.config.mKeyPair = sdkECKeyPair

		nanoTDF.mCompressedPubKey, err = ocrypto.CompressedECPublicKey(nanoTDF.config.mEccMode, nanoTDF.config.mKeyPair.PrivateKey.PublicKey)
		if err != nil {
			return err
		}

		// Create a new policy.
		nanoTDF.policyObj, err = createPolicyObject(nanoTDF.config.attributes)
		if err != nil {
			return fmt.Errorf("fail to create policy object:%w", err)
		}

		nanoTDF.policyObjectAsStr, err = json.Marshal(nanoTDF.policyObj)
		if err != nil {
			return fmt.Errorf("json.Marshal failed:%w", err)
		}

		// LogDebug("Max iteration reached - create new header for dataset");
	}

	// Generate symmetric key.
	secret, err := ocrypto.ComputeECDHKey([]byte(nanoTDF.config.mPrivateKey), []byte(nanoTDF.config.mKasPublicKey))
	if err != nil {
		return err
	}
	nanoTDF.mEncryptSymmetricKey, err = ocrypto.CalculateHKDF(nanoTDF.config.mDefaultSalt, secret)
	if err != nil {
		return err
	}

	// TODO FIXME - more to do here

	return err
}

func writeHeader(n *NanoTDFHeader, writer io.Writer) error {
	var err error

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

// auth tag sizes for different key lengths
const (
	kCipher64AuthTagSize  = 8
	kCipher96AuthTagSize  = 12
	kCipher104AuthTagSize = 13
	kCipher112AuthTagSize = 14
	kCipher120AuthTagSize = 15
	kCipher128AuthTagSize = 16
)

// / SizeOfAuthTagForCipher - Return the size of auth tag to be used for aes gcm encryption.
func SizeOfAuthTagForCipher(cipherType cipherMode) (int, error) {
	switch cipherType {
	case cipherModeAes256gcm64Bit:
		return kCipher64AuthTagSize, nil
	case cipherModeAes256gcm96Bit:
		return kCipher96AuthTagSize, nil
	case cipherModeAes256gcm104Bit:
		return kCipher104AuthTagSize, nil
	case cipherModeAes256gcm112Bit:
		return kCipher112AuthTagSize, nil
	case cipherModeAes256gcm120Bit:
		return kCipher120AuthTagSize, nil
	case cipherModeAes256gcm128Bit:
		return kCipher128AuthTagSize, nil
	default:
		return 0, fmt.Errorf("unknown cipher mode:%d", cipherType)
	}
}

const (
	kSeekBeginning = 0
	kSeekEnd       = 2
)

// NanoTDFEncryptFile - read from supplied input file, write encrypted data to supplied output file
func NanoTDFEncryptFile(plaintextFile *os.File, encryptedFile *os.File, config NanoTDFConfig) error {
	var err error

	// Seek to end to get size of file
	plaintextSize, err := plaintextFile.Seek(0, kSeekEnd)
	if err != nil {
		return err
	}

	// TODO FIXME - pick one.  Also check in the underlying encrypt buffer call but this avoids an alloc and read
	if plaintextSize > kMaxTDFSize {
		return fmt.Errorf("too big plaintextSize:%d", plaintextSize)
	}

	if plaintextSize > kDatasetMaxMBBytes {
		return fmt.Errorf("too big plaintextSize:%d", plaintextSize)
	}

	if plaintextSize > kMaxEncryptedNTDFSize {
		return fmt.Errorf("too big plaintextSize:%d", plaintextSize)
	}

	// Allocate buffer of the file size
	plaintextBuffer := make([]byte, plaintextSize)

	// Seek back to beginning to prepare for reading content
	_, err = plaintextFile.Seek(0, kSeekBeginning)
	if err != nil {
		return err
	}

	// Read the file into the buffer
	_, err = plaintextFile.Read(plaintextBuffer)
	if err != nil {
		return err
	}

	nanoBuffer, err := NanoTDFEncrypt(config, plaintextBuffer)
	if err != nil {
		return err
	}

	_, err = encryptedFile.Seek(0, kSeekBeginning)
	if err != nil {
		return err
	}

	_, err = encryptedFile.Write(nanoBuffer)
	return err
}

func NanoTDFToBuffer(nanoTDF NanoTDF) ([]byte, error) {
	return nanoTDF.mWorkingBuffer, nil
}

func NanoTDFEncrypt(config NanoTDFConfig, plaintextBuffer []byte) ([]byte, error) {
	var err error

	// config is fixed at this point, make a copy
	nanoTDF := NanoTDF{}
	nanoTDF.config = config

	err = createHeader(&nanoTDF)
	if err != nil {
		return nil, err
	}

	nanoTDF.mInitialized = true

	encryptBuffer := bytes.NewBuffer(make([]byte, 0, config.mBufferSize))
	ebWriter := bufio.NewWriter(encryptBuffer)
	err = writeHeader(&nanoTDF.header, ebWriter)
	if err != nil {
		return nil, err
	}

	/// Resize the working buffer only if needed.
	authTagSize, err := SizeOfAuthTagForCipher(nanoTDF.config.mCipher)
	if err != nil {
		return nil, err
	}
	sizeOfWorkingBuffer := kIvPadding + kNanoTDFIvSize + len(plaintextBuffer) + authTagSize
	if nanoTDF.mWorkingBuffer == nil || len(nanoTDF.mWorkingBuffer) < sizeOfWorkingBuffer {
		nanoTDF.mWorkingBuffer = make([]byte, sizeOfWorkingBuffer)
	}

	///
	/// Add the length of cipher text to output - (IV + Cipher Text + Auth tag)
	///

	// TODO FIXME
	// bytesAdded := 0

	encryptedDataSize := kNanoTDFIvSize + len(plaintextBuffer) + authTagSize

	// TODO FIXME
	cipherTextSize := uint64(encryptedDataSize + kNanoTDFIvSize + kIvPadding)

	if err := binary.Write(ebWriter, binary.BigEndian, &cipherTextSize); err != nil {
		return nil, err
	}

	// Encrypt the payload into the working buffer
	{
		ivSizeWithPadding := kIvPadding + kNanoTDFIvSize
		ivWithPadding := bytes.NewBuffer(make([]byte, 0, ivSizeWithPadding))

		// Reset the IV after max iterations
		if nanoTDF.config.mMaxKeyIterations == nanoTDF.mKeyIterationCount {
			nanoTDF.mIv = 1
			if nanoTDF.config.mDatasetMode {
				nanoTDF.mKeyIterationCount = 0
			}
		}

		if err := binary.Write(ebWriter, binary.BigEndian, &nanoTDF.mIv); err != nil {
			return nil, err
		}
		nanoTDF.mIv++

		// Resize the auth tag.
		newAuthTag := make([]byte, authTagSize)
		copy(newAuthTag, nanoTDF.mAuthTag)

		aesGcm, err := ocrypto.NewAESGcm(nanoTDF.mEncryptSymmetricKey)
		if err != nil {
			return nil, err
		}

		// Convert the uint64 IV value to byte array
		byteIv := make([]byte, kUint64Size)
		binary.BigEndian.PutUint64(byteIv, nanoTDF.mIv)

		// Encrypt the plaintext
		encryptedText, err := aesGcm.EncryptWithIV(byteIv, plaintextBuffer)
		if err != nil {
			return nil, err
		}

		// TODO FIXME - need real length here
		payloadBuffer := bytes.NewBuffer(make([]byte, 0, len(encryptedText)))
		pbWriter := bufio.NewWriter(payloadBuffer)

		// Copy IV at start
		err = binary.Write(pbWriter, binary.BigEndian, ivWithPadding.Bytes())
		if err != nil {
			return nil, err
		}

		// Copy tag at end
		err = binary.Write(pbWriter, binary.BigEndian, nanoTDF.mAuthTag)
		if err != nil {
			return nil, err
		}
	}

	// Copy the payload buffer contents into encrypt buffer without the IV padding.
	pbContentsWithoutIv := bytes.NewBuffer(make([]byte, 0, len(nanoTDF.mWorkingBuffer)-kIvPadding))
	pbwiWriter := bufio.NewWriter(pbContentsWithoutIv)
	err = binary.Write(pbwiWriter, binary.BigEndian, nanoTDF.mWorkingBuffer)
	if err != nil {
		return nil, err
	}
	err = binary.Write(ebWriter, binary.BigEndian, pbContentsWithoutIv.Bytes())
	if err != nil {
		return nil, err
	}

	// Adjust the buffer

	// bytesAdded += encryptedDataSize

	// Digest(header + payload) for signature
	digest := sha256.Sum256(encryptBuffer.Bytes())

	/*
	   	#if DEBUG_LOG
	   		auto digestData = base64Encode(toBytes(digest));
	   std::cout << "Encrypt digest: " << digestData << std::endl;
	   	#endif
	*/

	if nanoTDF.config.mHasSignature {
		signerPrivateKey := nanoTDF.config.mSignerPrivateKey
		signerPublicKey := ocrypto.GetPEMPublicKeyFromPrivateKey(signerPrivateKey, nanoTDF.config.mEccMode)
		compressedPubKey, err := ocrypto.CompressedECPublicKey(nanoTDF.config.mEccMode, signerPublicKey)
		if err != nil {
			return nil, err
		}

		// Add the signer public key
		err = binary.Write(ebWriter, binary.BigEndian, compressedPubKey)
		if err != nil {
			return nil, err
		}
		/*	#if DEBUG_LOG
					auto signerData = base64Encode(toBytes(compressedPubKey));
			std::cout << "Encrypt signer public key: " << signerData << std::endl;
				#endif

		*/
		// Adjust the buffer
		// bytesAdded += len(compressedPubKey)

		// Calculate the signature.
		signature := ocrypto.ComputeECDSASig(digest, signerPrivateKey)
		/* #if DEBUG_LOG
				auto sigData = base64Encode(toBytes(mSignature));
		std::cout << "Encrypt signature: " << sigData << std::endl;
			#endif

		*/

		// Add the signature and update the count of bytes added.
		err = binary.Write(ebWriter, binary.BigEndian, &signature)
		if err != nil {
			return nil, err
		}

		// Adjust the buffer
		// bytesAdded += len(signature)
	}

	if nanoTDF.config.mDatasetMode {
		nanoTDF.mKeyIterationCount++
	}

	return encryptBuffer.Bytes(), err
}
