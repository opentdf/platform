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
	"strconv"
	"strings"

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
	magicNumber          [len(kNanoTDFMagicStringAndVersion)]byte
	kasURL               resourceLocator
	binding              bindingCfg
	sigCfg               signatureConfig
	policy               policyInfo
	EphemeralPublicKey   eccKey
	policyObjectAsStr    []byte
	isInitialized        bool
	mEncryptSymmetricKey []byte
	policyBinding        []byte
	compressedPubKey     []byte
	keyPair              ocrypto.ECKeyPair
	mPrivateKey          string
	publicKey            string
}

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

type NanoTDF struct {
	header               NanoTDFHeader
	config               NanoTDFConfig
	policyObj            PolicyObject
	compressedPubKey     []byte
	iv                   uint64
	authTag              []byte
	workingBuffer        []byte
	mEncryptSymmetricKey []byte
	// mSignature           []byte
	policyObjectAsStr []byte
}

// ============================================================================================================

// resourceLocator - structure to contain a protocol + body comprising an URL
type resourceLocator struct {
	protocol   urlProtocol
	lengthBody uint8 // TODO FIXME - redundant?
	body       string
}

// urlProtocol - shorthand for protocol prefix on fully qualified url
type urlProtocol uint8

const (
	kPrefixHTTPS      string      = "https://"
	kPrefixHTTP       string      = "http://"
	urlProtocolHTTP   urlProtocol = 0
	urlProtocolHTTPS  urlProtocol = 1
	urlProtocolShared urlProtocol = 255 // TODO - how is this handled/parsed/rendered?
)

func (rl *resourceLocator) getLength() uint64 {
	return uint64(1 /* protocol byte */ + 1 /* length byte */ + len(rl.body) /* length of string */)
}

// setUrl - Store a fully qualified protocol+body string into a resourceLocator as a protocol value and a body string
func (rl *resourceLocator) setUrl(url string) error {
	lowerUrl := strings.ToLower(url)
	if strings.HasPrefix(lowerUrl, kPrefixHTTPS) {
		urlBody := url[len(kPrefixHTTPS):]
		if len(urlBody) > 255 {
			return errors.New("URL too long")
		}
		rl.protocol = urlProtocolHTTPS
		rl.lengthBody = uint8(len(urlBody))
		rl.body = urlBody
		return nil
	}
	if strings.HasPrefix(lowerUrl, kPrefixHTTP) {
		urlBody := url[len(kPrefixHTTP):]
		if len(urlBody) > 255 {
			return errors.New("URL too long")
		}
		rl.protocol = urlProtocolHTTP
		rl.lengthBody = uint8(len(urlBody))
		rl.body = urlBody
		return nil
	}
	return errors.New("Unsupported protocol: " + url)
}

// getUrl - Retrieve a fully qualified protocol+body URL string from a resourceLocator struct
func (rl *resourceLocator) getUrl() (string, error) {
	if rl.protocol == urlProtocolHTTPS {
		return kPrefixHTTPS + rl.body, nil
	}
	if rl.protocol == urlProtocolHTTP {
		return kPrefixHTTP + rl.body, nil
	}
	return "", fmt.Errorf("Unsupported protocol: %d", rl.protocol)
}

// writeResourceLocator - writes the content of the resource locator to the supplied writer
func (rl *resourceLocator) writeResourceLocator(writer io.Writer) error {
	if err := binary.Write(writer, binary.BigEndian, byte(rl.protocol)); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, uint8(len(rl.body))); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, []byte(rl.body)); err != nil { // TODO - normalize to lowercase?
		return err
	}
	return nil
}

// readResourceLocator - read the encoded protocol and body string into a resourceLocator
func (rl *resourceLocator) readResourceLocator(reader io.Reader) error {
	if err := binary.Read(reader, binary.BigEndian, &rl.protocol); err != nil {
		return errors.Join(Error("Error reading resourceLocator protocol value"), err)
	}
	if (rl.protocol != urlProtocolHTTP) && (rl.protocol != urlProtocolHTTPS) { // TODO - support 'shared' protocol?
		return errors.New("Unsupported protocol: " + strconv.Itoa(int(rl.protocol)))
	}
	if err := binary.Read(reader, binary.BigEndian, &rl.lengthBody); err != nil {
		return errors.Join(Error("Error reading resourceLocator body length value"), err)
	}
	body := make([]byte, rl.lengthBody)
	if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
		return errors.Join(Error("Error reading resourceLocator body value"), err)
	}
	rl.body = string(body) // TODO - normalize to lowercase?
	return nil
}

// ============================================================================================================

// embeddedPolicy - policy for data that is stored locally within the nanoTDF
type embeddedPolicy struct {
	lengthBody uint16
	body       string
}

// getLength - size in bytes of the serialized content of this object
func (ep *embeddedPolicy) getLength() uint64 {
	return uint64(2 /* length word length */ + len(ep.body) /* body data length */)
}

// writeEmbeddedPolicy - writes the content of the  to the supplied writer
func (ep embeddedPolicy) writeEmbeddedPolicy(writer io.Writer) error {
	if err := binary.Write(writer, binary.BigEndian, uint8(len(ep.body))); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, []byte(ep.body)); err != nil {
		return err
	}
	return nil
}

// readEmbeddedPolicy - reads an embeddedPolicy from the supplied reader
func (ep *embeddedPolicy) readEmbeddedPolicy(reader io.Reader) error {
	if err := binary.Read(reader, binary.BigEndian, &ep.lengthBody); err != nil {
		return errors.Join(ErrNanoTDFHeaderRead, err)
	}
	body := make([]byte, ep.lengthBody)
	if err := binary.Read(reader, binary.BigEndian, &body); err != nil {
		return errors.Join(ErrNanoTDFHeaderRead, err)
	}
	ep.body = string(body)
	return nil
}

// ============================================================================================================

// remotePolicy - locator value for policy content that is stored externally to the nanoTDF
type remotePolicy struct {
	url resourceLocator
}

// getLength - size in bytes of the serialized content of this object
func (rp *remotePolicy) getLength() uint64 {
	return rp.url.getLength()
}

// ============================================================================================================

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

type policyInfo struct {
	body    PolicyBody
	binding *eccSignature
}

type eccSignature struct {
	value []byte
}

type eccKey struct {
	Key []byte
}

type cipherMode int

const (
	cipherModeAes256gcm64Bit  cipherMode = 0
	cipherModeAes256gcm96Bit  cipherMode = 1
	cipherModeAes256gcm104Bit cipherMode = 2
	cipherModeAes256gcm112Bit cipherMode = 3
	cipherModeAes256gcm120Bit cipherMode = 4
	cipherModeAes256gcm128Bit cipherMode = 5
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
func deserializeBindingCfg(b byte) bindingCfg {
	cfg := bindingCfg{}
	// Shift to low nybble test low bit
	cfg.useEcdsaBinding = (b >> 7 & 0b00000001) == 1 //nolint:gomnd // better readability as literal
	// ignore padding
	cfg.padding = 0
	// shift to low nybble and use low 3 bits
	cfg.bindingBody = ocrypto.ECCMode((b >> 4) & 0b00000111) //nolint:gomnd // better readability as literal

	return cfg
}

// serializeBindingCfg - take info from bindingConfig struct and encode as single byte
func serializeBindingCfg(bindCfg bindingCfg) byte {
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
func deserializeSignatureCfg(b byte) signatureConfig {
	cfg := signatureConfig{}
	// Shift high bit down and mask to test for value
	cfg.hasSignature = (b >> 7 & 0b000000001) == 1 //nolint:gomnd // better readability as literal
	// Shift high nybble down and mask for eccmode value
	cfg.signatureMode = ocrypto.ECCMode((b >> 4) & 0b00000111) //nolint:gomnd // better readability as literal
	// Mask low nybble for cipher value
	cfg.cipher = cipherMode(b & 0b00001111) //nolint:gomnd // better readability as literal

	return cfg
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

// ============================================================================================================

type policyType uint8

const (
	policyTypeRemotePolicy                           policyType = 0
	policyTypeEmbeddedPolicyPlainText                policyType = 1
	policyTypeEmbeddedPolicyEncrypted                policyType = 2
	policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess policyType = 3
)

type PolicyBody struct {
	mode policyType
	rp   remotePolicy
	ep   embeddedPolicy
}

// getLength - size in bytes of the serialized content of this object
func (pb *PolicyBody) getLength() uint64 {
	var result uint64

	result = 1 /* policy mode byte */

	if pb.mode == policyTypeRemotePolicy {
		result += pb.rp.getLength()
	} else {
		// If it's not remote, assume embedded policy
		result += pb.ep.getLength()
	}

	return result
}

// readPolicyBody - helper function to decode input data into a PolicyBody object
func (pb *PolicyBody) readPolicyBody(reader io.Reader) error {

	var mode policyType
	if err := binary.Read(reader, binary.BigEndian, &mode); err != nil {
		return err
	}
	switch mode {
	case policyTypeRemotePolicy:
		var rl resourceLocator
		if err := rl.readResourceLocator(reader); err != nil {
			return errors.Join(ErrNanoTDFHeaderRead, err)
		}
		pb.rp = remotePolicy{url: rl}
	case policyTypeEmbeddedPolicyPlainText:
	case policyTypeEmbeddedPolicyEncrypted:
	case policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess:
		var ep embeddedPolicy
		if err := ep.readEmbeddedPolicy(reader); err != nil {
			return errors.Join(ErrNanoTDFHeaderRead, err)
		}
		pb.ep = ep
	default:
		return errors.New("unknown policy type")
	}
	return nil
}

// writePolicyBody - helper function to encode and write a PolicyBody object
func (pb *PolicyBody) writePolicyBody(writer io.Writer) error {
	var err error

	switch pb.mode {
	case policyTypeRemotePolicy: // remote policy - resource locator
		if err = binary.Write(writer, binary.BigEndian, pb.mode); err != nil {
			return err
		}
		if err = pb.rp.url.writeResourceLocator(writer); err != nil {
			return err
		}
		return nil
	case policyTypeEmbeddedPolicyPlainText:
	case policyTypeEmbeddedPolicyEncrypted:
	case policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess:
		// embedded policy - inline
		if err = binary.Write(writer, binary.BigEndian, pb.mode); err != nil {
			return err
		}
		if err = pb.ep.writeEmbeddedPolicy(writer); err != nil {
			return err
		}
	default:
		return errors.New("unsupported policy mode")
	}
	return nil
}

// ============================================================================================================

// Key length sizes for different curves
const (
	kCurveSecp256r1KeySize = 33
	kCurveSecp256k1KeySize = 33
	kCurveSecp384r1KeySize = 49
	kCurveSecp521r1KeySize = 67
)

// getECCKeyLength - return the length in bytes of a key related to the specified curve
func getECCKeyLength(curve ocrypto.ECCMode) (uint8, error) {
	var numberOfBytes uint8
	switch curve {
	case ocrypto.ECCModeSecp256r1:
		numberOfBytes = kCurveSecp256r1KeySize
	case ocrypto.ECCModeSecp256k1:
		numberOfBytes = kCurveSecp256k1KeySize
	case ocrypto.ECCModeSecp384r1:
		numberOfBytes = kCurveSecp384r1KeySize
	case ocrypto.ECCModeSecp521r1:
		numberOfBytes = kCurveSecp521r1KeySize
	default:
		return 0, fmt.Errorf("unknown cipher mode:%d", curve)
	}
	return numberOfBytes, nil
}

// readEphemeralPublicKey - helper function to decode input into an eccKey object
func readEphemeralPublicKey(reader io.Reader, curve ocrypto.ECCMode) (eccKey, error) {
	var key eccKey
	// get length of key for this curve
	numberOfBytes, err := getECCKeyLength(curve)
	if err != nil {
		return key, err
	}
	buffer := make([]byte, numberOfBytes)
	if err := binary.Read(reader, binary.BigEndian, &buffer); err != nil {
		return key, errors.Join(ErrNanoTDFHeaderRead, err)
	}
	key.Key = buffer
	return key, nil
}

// ============================================================================================================

// ReadNanoTDFHeader - decode input into a NanoTDFHeader object
func (header *NanoTDFHeader) ReadNanoTDFHeader(reader io.Reader) error {

	if err := binary.Read(reader, binary.BigEndian, &header.magicNumber); err != nil {
		return errors.Join(ErrNanoTDFHeaderRead, err)
	}

	if err := header.kasURL.readResourceLocator(reader); err != nil {
		return errors.Join(ErrNanoTDFHeaderRead, err)
	}

	var bindingByte uint8
	if err := binary.Read(reader, binary.BigEndian, &bindingByte); err != nil {
		return errors.Join(ErrNanoTDFHeaderRead, err)
	}
	header.binding = deserializeBindingCfg(bindingByte)

	var signatureByte uint8
	if err := binary.Read(reader, binary.BigEndian, &signatureByte); err != nil {
		return errors.Join(ErrNanoTDFHeaderRead, err)
	}
	header.sigCfg = deserializeSignatureCfg(signatureByte)

	if err := header.policy.body.readPolicyBody(reader); err != nil {
		return errors.Join(ErrNanoTDFHeaderRead, err)
	}

	header.policy.binding = &eccSignature{}
	header.policy.binding.value = make([]byte, kEccSignatureLength)
	if err := binary.Read(reader, binary.BigEndian, &header.policy.binding.value); err != nil {
		return errors.Join(ErrNanoTDFHeaderRead, err)
	}

	var err error
	header.EphemeralPublicKey, err = readEphemeralPublicKey(reader, header.binding.bindingBody)

	return err
}

func createHeader(header *NanoTDFHeader, config *NanoTDFConfig) error {
	var err error

	if header.isInitialized == false {
		// Set magic number in header, and generate default salt
		var i int
		for _, magicByte := range []byte(kNanoTDFMagicStringAndVersion) {
			header.magicNumber[i] = magicByte
			i++
		}
		config.mDefaultSalt = ocrypto.CalculateSHA256([]byte(kNanoTDFMagicStringAndVersion))

		header.mPrivateKey = config.mPrivateKey
		header.publicKey = config.publicKey
		header.keyPair = config.keyPair

		header.kasURL = config.kasURL

		header.binding = config.binding

		header.sigCfg = config.sigCfg

		header.policy = config.policy

		// TODO - FIXME - calculate a real policy binding value
		header.policyBinding = make([]byte, kEccSignatureLength)

		// copy key from config
		header.EphemeralPublicKey = config.EphemeralPublicKey

		header.isInitialized = true
	}

	if config.datasetMode && // In data set mode
		config.keyIterationCount > 0 && // Not the first iteration
		config.keyIterationCount != config.maxKeyIterations { // Didn't reach the max iteration
		// LogDebug("Reusing the header for dataset");
		// Use the old header.
		return err
	}

	if config.datasetMode && (config.maxKeyIterations == config.keyIterationCount) { //nolint:nestif // error checking each operation
		var sdkECKeyPair, err = ocrypto.NewECKeyPair(config.eccMode)
		if err != nil {
			return err
		}
		header.mPrivateKey, err = sdkECKeyPair.PrivateKeyInPemFormat()
		if err != nil {
			return err
		}
		header.publicKey, err = sdkECKeyPair.PublicKeyInPemFormat()
		if err != nil {
			return err
		}
		header.keyPair = sdkECKeyPair

		header.compressedPubKey, err = ocrypto.CompressedECPublicKey(config.eccMode, header.keyPair.PrivateKey.PublicKey)
		if err != nil {
			return err
		}

		// Create a new policy.
		policyObj, err := createPolicyObject(config.attributes)
		header.policy = config.policy
		if err != nil {
			return fmt.Errorf("fail to create policy object:%w", err)
		}

		header.policyObjectAsStr, err = json.Marshal(policyObj)
		if err != nil {
			return fmt.Errorf("json.Marshal failed:%w", err)
		}

		// LogDebug("Max iteration reached - create new header for dataset");
	}

	header.EphemeralPublicKey = config.EphemeralPublicKey

	// Generate symmetric key.
	// secret, err := ocrypto.ComputeECDHKey([]byte(config.mPrivateKey), []byte(config.mKasPublicKey))
	//  if err != nil {
	//	return err
	// }
	// header.mEncryptSymmetricKey, err = ocrypto.CalculateHKDF(config.mDefaultSalt, secret)
	// if err != nil {
	//	return err
	// }

	// TODO FIXME - more to do here

	return err
}

func (header *NanoTDFHeader) getLength() uint64 {
	var totalBytes uint64

	totalBytes += uint64(len(header.magicNumber))

	totalBytes += header.kasURL.getLength()

	totalBytes += 1 /* binding byte */

	totalBytes += 1 /* signature byte */

	totalBytes += header.policy.body.getLength()

	totalBytes += uint64(len(header.policyBinding))

	totalBytes += uint64(len(header.EphemeralPublicKey.Key))

	return totalBytes
}

func writeHeader(header *NanoTDFHeader, writer io.Writer) error {
	var err error

	if err = binary.Write(writer, binary.BigEndian, header.magicNumber); err != nil {
		return err
	}

	if err = header.kasURL.writeResourceLocator(writer); err != nil {
		return err
	}

	bindingByte := serializeBindingCfg(header.binding)
	if err = binary.Write(writer, binary.BigEndian, bindingByte); err != nil {
		return err
	}

	// Policy
	signatureByte := serializeSignatureCfg(header.sigCfg)
	if err := binary.Write(writer, binary.BigEndian, signatureByte); err != nil {
		return err
	}

	if err = header.policy.body.writePolicyBody(writer); err != nil {
		return err
	}

	if err = binary.Write(writer, binary.BigEndian, header.policyBinding); err != nil {
		return err
	}

	if err = binary.Write(writer, binary.BigEndian, header.EphemeralPublicKey.Key); err != nil {
		return err
	}

	return err
}

// ============================================================================================================

// auth tag size in bytes for different ciphers
const (
	kCipher64AuthTagSize  = 8
	kCipher96AuthTagSize  = 12
	kCipher104AuthTagSize = 13
	kCipher112AuthTagSize = 14
	kCipher120AuthTagSize = 15
	kCipher128AuthTagSize = 16
)

// SizeOfAuthTagForCipher - Return the size in bytes of auth tag to be used for aes gcm encryption
func SizeOfAuthTagForCipher(cipherType cipherMode) (int, error) {
	var numberOfBytes int
	switch cipherType {
	case cipherModeAes256gcm64Bit:

		numberOfBytes = kCipher64AuthTagSize
	case cipherModeAes256gcm96Bit:

		numberOfBytes = kCipher96AuthTagSize
	case cipherModeAes256gcm104Bit:
		numberOfBytes = kCipher104AuthTagSize
	case cipherModeAes256gcm112Bit:

		numberOfBytes = kCipher112AuthTagSize
	case cipherModeAes256gcm120Bit:

		numberOfBytes = kCipher120AuthTagSize
	case cipherModeAes256gcm128Bit:

		numberOfBytes = kCipher128AuthTagSize
	default:

		return 0, fmt.Errorf("unknown cipher mode:%d", cipherType)
	}
	return numberOfBytes, nil
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

	nanoTDF := NanoTDF{config: config}
	nanoBuffer, err := NanoTDFEncrypt(&nanoTDF, plaintextBuffer)
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
	return nanoTDF.workingBuffer, nil
}

func NanoTDFEncrypt(nanoTDF *NanoTDF, plaintextBuffer []byte) ([]byte, error) {
	var err error

	// config is fixed at this point, make a copy
	nanoTDFHeader := new(NanoTDFHeader)

	err = createHeader(nanoTDFHeader, &nanoTDF.config)
	if err != nil {
		return nil, err
	}

	encryptBuffer := bytes.NewBuffer(make([]byte, 0, nanoTDF.config.bufferSize))
	ebWriter := bufio.NewWriter(encryptBuffer)
	err = writeHeader(&nanoTDF.header, ebWriter)
	if err != nil {
		return nil, err
	}

	/// Resize the working buffer only if needed.
	authTagSize, err := SizeOfAuthTagForCipher(nanoTDF.config.cipher)
	if err != nil {
		return nil, err
	}
	sizeOfWorkingBuffer := kIvPadding + kNanoTDFIvSize + len(plaintextBuffer) + authTagSize
	if nanoTDF.workingBuffer == nil || len(nanoTDF.workingBuffer) < sizeOfWorkingBuffer {
		nanoTDF.workingBuffer = make([]byte, sizeOfWorkingBuffer)
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
		if nanoTDF.config.maxKeyIterations == nanoTDF.config.keyIterationCount {
			nanoTDF.iv = 1
			if nanoTDF.config.datasetMode {
				nanoTDF.config.keyIterationCount = 0
			}
		}

		if err := binary.Write(ebWriter, binary.BigEndian, &nanoTDF.iv); err != nil {
			return nil, err
		}
		nanoTDF.iv++

		// Resize the auth tag.
		newAuthTag := make([]byte, authTagSize)
		copy(newAuthTag, nanoTDF.authTag)

		aesGcm, err := ocrypto.NewAESGcm(nanoTDF.mEncryptSymmetricKey)
		if err != nil {
			return nil, err
		}

		// Convert the uint64 IV value to byte array
		byteIv := make([]byte, kUint64Size)
		binary.BigEndian.PutUint64(byteIv, nanoTDF.iv)

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
		err = binary.Write(pbWriter, binary.BigEndian, nanoTDF.authTag)
		if err != nil {
			return nil, err
		}
	}

	// Copy the payload buffer contents into encrypt buffer without the IV padding.
	pbContentsWithoutIv := bytes.NewBuffer(make([]byte, 0, len(nanoTDF.workingBuffer)-kIvPadding))
	pbwiWriter := bufio.NewWriter(pbContentsWithoutIv)
	err = binary.Write(pbwiWriter, binary.BigEndian, nanoTDF.workingBuffer)
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

	if nanoTDF.config.sigCfg.hasSignature {
		signerPrivateKey := nanoTDF.config.signerPrivateKey
		signerPublicKey := ocrypto.GetPEMPublicKeyFromPrivateKey(signerPrivateKey, nanoTDF.config.eccMode)
		compressedPubKey, err := ocrypto.CompressedECPublicKey(nanoTDF.config.eccMode, signerPublicKey)
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

		// slog.Debug("Encrypt signature:", sigData)
		*/

		// Add the signature and update the count of bytes added.
		err = binary.Write(ebWriter, binary.BigEndian, &signature)
		if err != nil {
			return nil, err
		}

		// Adjust the buffer
		// bytesAdded += len(signature)
	}

	if nanoTDF.config.datasetMode {
		nanoTDF.config.keyIterationCount++
	}

	return encryptBuffer.Bytes(), err
}
