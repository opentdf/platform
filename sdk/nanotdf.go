package sdk

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/kas"
	"google.golang.org/grpc"
)

// ============================================================================================================
// Pat Mancuso May 2024
// Support for nanoTDF operations
//
// See also the nanotdf_config.go interface
//
// ============================================================================================================

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

type NTDFHeader struct {
	kasURL       ResourceLocator
	bindCfg      bindingConfig
	sigCfg       signatureConfig
	EphemeralKey []byte
}

type NanoTDFHeader struct {
	magicNumber          [len(kNanoTDFMagicStringAndVersion)]byte
	kasURL               ResourceLocator
	bindCfg              bindingConfig
	sigCfg               signatureConfig
	policy               policyInfo
	policyObjectAsStr    []byte
	mEncryptSymmetricKey []byte
	policyBinding        []byte
	compressedPubKey     []byte
	keyPair              ocrypto.ECKeyPair
	privateKey           string
	publicKey            string
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

// embeddedPolicy - policy for data that is stored locally within the nanoTDF
type embeddedPolicy struct {
	lengthBody uint16
	body       []byte
}

// getLength - size in bytes of the serialized content of this object
func (ep *embeddedPolicy) getLength() uint16 {
	return uint16(2 /* length word length */ + len(ep.body) /* body data length */)
}

// writeEmbeddedPolicy - writes the content of the  to the supplied writer
func (ep embeddedPolicy) writeEmbeddedPolicy(writer io.Writer) error {

	// store uint16 in big endian format
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, ep.lengthBody)
	if _, err := writer.Write(buf); err != nil {
		return err
	}
	slog.Debug("writeEmbeddedPolicy", slog.Uint64("policy length", uint64(ep.lengthBody)))

	if _, err := writer.Write(ep.body); err != nil {
		return err
	}
	slog.Debug("writeEmbeddedPolicy", slog.Uint64("policy body", uint64(len(ep.body))))

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
	ep.body = body
	return nil
}

// ============================================================================================================

// remotePolicy - locator value for policy content that is stored externally to the nanoTDF
type remotePolicy struct {
	url ResourceLocator
}

// getLength - size in bytes of the serialized content of this object
func (rp *remotePolicy) getLength() uint16 {
	return rp.url.getLength()
}

// ============================================================================================================

type bindingConfig struct {
	useEcdsaBinding bool
	padding         uint8
	eccMode         ocrypto.ECCMode
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

// deserializeBindingCfg - read byte of binding config into bindingConfig struct
func deserializeBindingCfg(b byte) bindingConfig {
	cfg := bindingConfig{}
	// Shift to low nybble test low bit
	cfg.useEcdsaBinding = (b >> 7 & 0b00000001) == 1 //nolint:gomnd // better readability as literal
	// ignore padding
	cfg.padding = 0
	// shift to low nybble and use low 3 bits
	cfg.eccMode = ocrypto.ECCMode((b >> 4) & 0b00000111) //nolint:gomnd // better readability as literal

	return cfg
}

// serializeBindingCfg - take info from bindingConfig struct and encode as single byte
func serializeBindingCfg(bindCfg bindingConfig) byte {
	var bindSerial byte = 0x00

	// Set high bit if ecdsa binding is enabled
	if bindCfg.useEcdsaBinding {
		bindSerial |= 0b10000000
	}
	// Mask value to low 3 bytes and shift to high nybble
	bindSerial |= (byte(bindCfg.eccMode) & 0b00000111) << 4 //nolint:gomnd // better readability as literal

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
func (pb *PolicyBody) getLength() uint16 {
	var result uint16

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
		var rl ResourceLocator
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

func NewNanoTDFHeader(config NanoTDFConfig) (*NanoTDFHeader, error) {

	h := NanoTDFHeader{}

	h.magicNumber = [3]byte([]byte(kNanoTDFMagicStringAndVersion))
	h.keyPair = config.keyPair
	h.kasURL = config.kasURL
	h.bindCfg = config.bindCfg
	h.sigCfg = config.sigCfg
	h.policy = config.policy

	// TODO - FIXME - calculate a real policy binding value
	h.policyBinding = make([]byte, kEccSignatureLength)

	// copy key from config
	//var err error
	//h.EphemeralPublicKey.Key, err = ocrypto.CompressedECPublicKey(config.eccMode, config.keyPair.PrivateKey.PublicKey)
	//if err != nil {
	//	return nil, errors.New("URL too long")
	//}

	return &h, nil
}

func createHeader(header *NanoTDFHeader, config *NanoTDFConfig) error {
	var err error

	// TODO FIXME - more to do here

	return err
}

func (header *NanoTDFHeader) getLength() uint64 {
	var totalBytes uint64

	totalBytes += uint64(len(header.magicNumber))

	totalBytes += uint64(header.kasURL.getLength())

	totalBytes += 1 /* binding byte */

	totalBytes += 1 /* signature byte */

	totalBytes += uint64(header.policy.body.getLength())

	totalBytes += uint64(len(header.policyBinding))

	//totalBytes += uint64(len(header.EphemeralPublicKey.Key))

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

	bindingByte := serializeBindingCfg(header.bindCfg)
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

	//if err = binary.Write(writer, binary.BigEndian, header.EphemeralPublicKey.Key); err != nil {
	//	return err
	//}

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
//func NanoTDFEncryptFile(plaintextFile *os.File, encryptedFile *os.File, config NanoTDFConfig) error {
//	var err error
//
//	// Seek to end to get size of file
//	plaintextSize, err := plaintextFile.Seek(0, kSeekEnd)
//	if err != nil {
//		return err
//	}
//
//	// TODO FIXME - pick one.  Also check in the underlying encrypt buffer call but this avoids an alloc and read
//	if plaintextSize > kMaxTDFSize {
//		return fmt.Errorf("too big plaintextSize:%d", plaintextSize)
//	}
//
//	if plaintextSize > kDatasetMaxMBBytes {
//		return fmt.Errorf("too big plaintextSize:%d", plaintextSize)
//	}
//
//	if plaintextSize > kMaxEncryptedNTDFSize {
//		return fmt.Errorf("too big plaintextSize:%d", plaintextSize)
//	}
//
//	// Allocate buffer of the file size
//	plaintextBuffer := make([]byte, plaintextSize)
//
//	// Seek back to beginning to prepare for reading content
//	_, err = plaintextFile.Seek(0, kSeekBeginning)
//	if err != nil {
//		return err
//	}
//
//	// Read the file into the buffer
//	_, err = plaintextFile.Read(plaintextBuffer)
//	if err != nil {
//		return err
//	}
//
//	nanoTDF := NanoTDF{config: config}
//	nanoBuffer, err := NanoTDFEncrypt(&nanoTDF, plaintextBuffer)
//	if err != nil {
//		return err
//	}
//
//	_, err = encryptedFile.Seek(0, kSeekBeginning)
//	if err != nil {
//		return err
//	}
//
//	_, err = encryptedFile.Write(nanoBuffer)
//	return err
//}

//func NanoTDFToBuffer(nanoTDF NanoTDF) ([]byte, error) {
//	return nanoTDF.workingBuffer, nil
//}
//
//func NanoTDFEncrypt(nanoTDF *NanoTDF, plaintextBuffer []byte) ([]byte, error) {
//	var err error
//
//	// config is fixed at this point, make a copy
//	nanoTDFHeader := new(NanoTDFHeader)
//
//	err = createHeader(nanoTDFHeader, &nanoTDF.config)
//	if err != nil {
//		return nil, err
//	}
//
//	encryptBuffer := bytes.NewBuffer(make([]byte, 0, nanoTDF.config.bufferSize))
//	ebWriter := bufio.NewWriter(encryptBuffer)
//	err = writeHeader(&nanoTDF.header, ebWriter)
//	if err != nil {
//		return nil, err
//	}
//
//	/// Resize the working buffer only if needed.
//	authTagSize, err := SizeOfAuthTagForCipher(nanoTDF.config.cipher)
//	if err != nil {
//		return nil, err
//	}
//	sizeOfWorkingBuffer := kIvPadding + kNanoTDFIvSize + len(plaintextBuffer) + authTagSize
//	if nanoTDF.workingBuffer == nil || len(nanoTDF.workingBuffer) < sizeOfWorkingBuffer {
//		nanoTDF.workingBuffer = make([]byte, sizeOfWorkingBuffer)
//	}
//
//	///
//	/// Add the length of cipher text to output - (IV + Cipher Text + Auth tag)
//	///
//
//	// TODO FIXME
//	// bytesAdded := 0
//
//	encryptedDataSize := kNanoTDFIvSize + len(plaintextBuffer) + authTagSize
//
//	// TODO FIXME
//	cipherTextSize := uint64(encryptedDataSize + kNanoTDFIvSize + kIvPadding)
//
//	if err := binary.Write(ebWriter, binary.BigEndian, &cipherTextSize); err != nil {
//		return nil, err
//	}
//
//	// Encrypt the payload into the working buffer
//	{
//		ivSizeWithPadding := kIvPadding + kNanoTDFIvSize
//		ivWithPadding := bytes.NewBuffer(make([]byte, 0, ivSizeWithPadding))
//
//		// Reset the IV after max iterations
//		if nanoTDF.config.maxKeyIterations == nanoTDF.config.keyIterationCount {
//			nanoTDF.iv = 1
//			if nanoTDF.config.datasetMode {
//				nanoTDF.config.keyIterationCount = 0
//			}
//		}
//
//		if err := binary.Write(ebWriter, binary.BigEndian, &nanoTDF.iv); err != nil {
//			return nil, err
//		}
//		nanoTDF.iv++
//
//		// Resize the auth tag.
//		newAuthTag := make([]byte, authTagSize)
//		copy(newAuthTag, nanoTDF.authTag)
//
//		aesGcm, err := ocrypto.NewAESGcm(nanoTDF.mEncryptSymmetricKey)
//		if err != nil {
//			return nil, err
//		}
//
//		// Convert the uint64 IV value to byte array
//		byteIv := make([]byte, kUint64Size)
//		binary.BigEndian.PutUint64(byteIv, nanoTDF.iv)
//
//		// Encrypt the plaintext
//		encryptedText, err := aesGcm.EncryptWithIV(byteIv, plaintextBuffer)
//		if err != nil {
//			return nil, err
//		}
//
//		// TODO FIXME - need real length here
//		payloadBuffer := bytes.NewBuffer(make([]byte, 0, len(encryptedText)))
//		pbWriter := bufio.NewWriter(payloadBuffer)
//
//		// Copy IV at start
//		err = binary.Write(pbWriter, binary.BigEndian, ivWithPadding.Bytes())
//		if err != nil {
//			return nil, err
//		}
//
//		// Copy tag at end
//		err = binary.Write(pbWriter, binary.BigEndian, nanoTDF.authTag)
//		if err != nil {
//			return nil, err
//		}
//	}
//
//	// Copy the payload buffer contents into encrypt buffer without the IV padding.
//	pbContentsWithoutIv := bytes.NewBuffer(make([]byte, 0, len(nanoTDF.workingBuffer)-kIvPadding))
//	pbwiWriter := bufio.NewWriter(pbContentsWithoutIv)
//	err = binary.Write(pbwiWriter, binary.BigEndian, nanoTDF.workingBuffer)
//	if err != nil {
//		return nil, err
//	}
//	err = binary.Write(ebWriter, binary.BigEndian, pbContentsWithoutIv.Bytes())
//	if err != nil {
//		return nil, err
//	}
//
//	// Adjust the buffer
//
//	// bytesAdded += encryptedDataSize
//
//	// Digest(header + payload) for signature
//	digest := sha256.Sum256(encryptBuffer.Bytes())
//
//	/*
//	   	#if DEBUG_LOG
//	   		auto digestData = base64Encode(toBytes(digest));
//	   std::cout << "Encrypt digest: " << digestData << std::endl;
//	   	#endif
//	*/
//
//	if nanoTDF.config.sigCfg.hasSignature {
//		signerPrivateKey := nanoTDF.config.signerPrivateKey
//		signerPublicKey := ocrypto.GetPEMPublicKeyFromPrivateKey(signerPrivateKey, nanoTDF.config.eccMode)
//		compressedPubKey, err := ocrypto.CompressedECPublicKey(nanoTDF.config.eccMode, signerPublicKey)
//		if err != nil {
//			return nil, err
//		}
//
//		// Add the signer public key
//		err = binary.Write(ebWriter, binary.BigEndian, compressedPubKey)
//		if err != nil {
//			return nil, err
//		}
//		/*	#if DEBUG_LOG
//					auto signerData = base64Encode(toBytes(compressedPubKey));
//			std::cout << "Encrypt signer public key: " << signerData << std::endl;
//				#endif
//
//		*/
//		// Adjust the buffer
//		// bytesAdded += len(compressedPubKey)
//
//		// Calculate the signature.
//		signature := ocrypto.ComputeECDSASig(digest, signerPrivateKey)
//		/* #if DEBUG_LOG
//				auto sigData = base64Encode(toBytes(mSignature));
//		std::cout << "Encrypt signature: " << sigData << std::endl;
//			#endif
//
//		// slog.Debug("Encrypt signature:", sigData)
//		*/
//
//		// Add the signature and update the count of bytes added.
//		err = binary.Write(ebWriter, binary.BigEndian, &signature)
//		if err != nil {
//			return nil, err
//		}
//
//		// Adjust the buffer
//		// bytesAdded += len(signature)
//	}
//
//	if nanoTDF.config.datasetMode {
//		nanoTDF.config.keyIterationCount++
//	}
//
//	return encryptBuffer.Bytes(), err
//}

func writeNanoTDFHeader(writer io.Writer, config NanoTDFConfig) ([]byte, uint32, error) {

	var totalBytes uint32 = 0

	// Write the magic number
	l, err := writer.Write([]byte(kNanoTDFMagicStringAndVersion))
	if err != nil {
		return nil, 0, err
	}
	totalBytes += uint32(l)

	slog.Debug("writeNanoTDFHeader", slog.Uint64("magic number", uint64(len(kNanoTDFMagicStringAndVersion))))

	// Write the kas url
	err = config.kasURL.writeResourceLocator(writer)
	if err != nil {
		return nil, 0, err
	}
	totalBytes += uint32(config.kasURL.getLength())
	slog.Debug("writeNanoTDFHeader", slog.Uint64("resource locator number", uint64(config.kasURL.getLength())))

	// Write ECC And Binding Mode
	l, err = writer.Write([]byte{serializeBindingCfg(config.bindCfg)})
	if err != nil {
		return nil, 0, err
	}
	totalBytes += uint32(l)

	// Write Payload and Sig Mode
	l, err = writer.Write([]byte{serializeSignatureCfg(config.sigCfg)})
	if err != nil {
		return nil, 0, err
	}
	totalBytes += uint32(l)

	// Write policy - (Policy Mode, Policy length, Policy cipherText, Policy binding)
	config.policy.body.mode = policyTypeEmbeddedPolicyEncrypted
	l, err = writer.Write([]byte{byte(config.policy.body.mode)})
	if err != nil {
		return nil, 0, err
	}
	totalBytes += uint32(l)

	policyObj, err := createPolicyObject(config.attributes)
	if err != nil {
		return nil, 0, fmt.Errorf("fail to create policy object:%w", err)
	}

	policyObjectAsStr, err := json.Marshal(policyObj)
	if err != nil {
		return nil, 0, fmt.Errorf("json.Marshal failed:%w", err)
	}

	ecdhKey, err := ocrypto.ConvertToECDHPrivateKey(config.keyPair.PrivateKey)
	if err != nil {
		return nil, 0, fmt.Errorf("ocrypto.ConvertToECDHPrivateKey failed:%w", err)
	}

	symKey, err := ocrypto.ComputeECDHKeyFromECDHKeys(config.kasPublicKey, ecdhKey)
	if err != nil {
		return nil, 0, fmt.Errorf("ocrypto.ComputeECDHKeyFromEC failed:%w", err)
	}

	symmetricKey, err := ocrypto.CalculateHKDF([]byte(kNanoTDFMagicStringAndVersion), symKey)
	if err != nil {
		return nil, 0, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}

	encoded := ocrypto.Base64Encode(symmetricKey)
	slog.Debug("writeNanoTDFHeader", slog.String("symmetricKey", string(encoded)))

	aesGcm, err := ocrypto.NewAESGcm(symmetricKey)
	if err != nil {
		return nil, 0, fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	tagSize, err := SizeOfAuthTagForCipher(config.sigCfg.cipher)
	if err != nil {
		return nil, 0, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
	}

	iv := make([]byte, 12)
	cipherText, err := aesGcm.EncryptWithIVAndTagSize(iv, policyObjectAsStr, tagSize)
	if err != nil {
		return nil, 0, fmt.Errorf("AesGcm.EncryptWithIVAndTagSize failed:%w", err)
	}

	embeddedP := embeddedPolicy{
		lengthBody: uint16(len(cipherText) - len(iv)),
		body:       cipherText[len(iv):],
	}
	err = embeddedP.writeEmbeddedPolicy(writer)
	if err != nil {
		return nil, 0, fmt.Errorf("writeEmbeddedPolicy failed:%w", err)
	}

	// size of uint16
	totalBytes += 2 + uint32(len(embeddedP.body))

	digest := ocrypto.CalculateSHA256(cipherText)
	binding := digest[len(digest)-kNanoTDFGMACLength:]
	l, err = writer.Write(binding)
	if err != nil {
		return nil, 0, err
	}
	totalBytes += uint32(l)

	ephemeralPublicKeyKey, _ := ocrypto.CompressedECPublicKey(config.bindCfg.eccMode, config.keyPair.PrivateKey.PublicKey)
	if err != nil {
		return nil, 0, fmt.Errorf("ocrypto.CompressedECPublicKey failed:%w", err)
	}

	l, err = writer.Write(ephemeralPublicKeyKey)
	if err != nil {
		return nil, 0, err
	}
	totalBytes += uint32(l)

	return symmetricKey, totalBytes, nil
}

func NewNanoTDFHeaderFromReader(reader io.Reader) (NTDFHeader, uint32, error) {

	header := NTDFHeader{}
	var size uint32 = 0

	magicNumber := make([]byte, 3)
	l, err := reader.Read(magicNumber)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)

	if string(magicNumber) != kNanoTDFMagicStringAndVersion {
		return header, 0, fmt.Errorf("Not a valid nano tdf")
	}

	// read resource locator
	resource, err := NewResourceLocatorFromReader(reader)
	if err != nil {
		return header, 0, fmt.Errorf("NewResourceLocatorFromReader failed :%w", err)
	}
	size += uint32(resource.getLength())
	header.kasURL = *resource

	slog.Debug("NewNanoTDFHeaderFromReader", slog.Uint64("resource locator", uint64(resource.getLength())))

	// read ECC and Binding Mode
	oneBytes := make([]byte, 1)
	l, err = reader.Read(oneBytes)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)
	header.bindCfg = deserializeBindingCfg(oneBytes[0])

	// check  ephemeral ECC Params Enum
	if header.bindCfg.eccMode != ocrypto.ECCModeSecp256r1 {
		return header, 0, fmt.Errorf("current implementation of nano tdf only support secp256r1 curve")
	}

	// read  Payload and Sig Mode
	l, err = reader.Read(oneBytes)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)
	header.sigCfg = deserializeSignatureCfg(oneBytes[0])

	// Read policy type
	l, err = reader.Read(oneBytes)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)

	if oneBytes[0] != uint8(policyTypeEmbeddedPolicyEncrypted) {
		return header, 0, fmt.Errorf(" current implementation only support embedded policy type")
	}

	// read policy length
	twoBytes := make([]byte, 2)
	l, err = reader.Read(twoBytes)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)
	policyLength := binary.BigEndian.Uint16(twoBytes)
	slog.Debug("NewNanoTDFHeaderFromReader", slog.Uint64("policyLength", uint64(policyLength)))

	// read policy body
	policyBody := make([]byte, policyLength)
	l, err = reader.Read(policyBody)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)

	// read policy binding
	policyBinding := make([]byte, kNanoTDFGMACLength)
	l, err = reader.Read(policyBinding)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)

	ephemeralKeySize, err := getECCKeyLength(header.bindCfg.eccMode)
	if err != nil {
		return header, 0, fmt.Errorf("getECCKeyLength :%w", err)
	}

	// read ephemeral Key
	ephemeralKey := make([]byte, ephemeralKeySize)
	l, err = reader.Read(ephemeralKey)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)
	header.EphemeralKey = ephemeralKey

	slog.Debug("NewNanoTDFHeaderFromReader", slog.Uint64("header size", uint64(size)))

	return header, size, nil
}

//func (s SDK) CreateNanoTDF(writer io.Writer, reader io.ReadSeeker, config NanoTDFConfig) error {

func (s SDK) CreateNanoTDF(writer io.Writer, reader io.Reader, config NanoTDFConfig) (uint32, error) {

	var totalSize uint32 = 0
	buf := bytes.Buffer{}
	size, err := buf.ReadFrom(reader)
	if err != nil {
		return 0, err
	}

	if size > kMaxTDFSize {
		return 0, errors.New("exceeds max size for nano tdf")
	}

	kasURL, err := config.kasURL.getUrl()
	if err != nil {
		return 0, fmt.Errorf("config.kasURL failed:%w", err)
	}

	kasPublicKey, err := getECPublicKey(kasURL, s.dialOptions...)
	if err != nil {
		return 0, fmt.Errorf("getECPublicKey failed:%w", err)
	}

	slog.Debug("CreateNanoTDF", slog.String("header size", kasPublicKey))

	config.kasPublicKey, err = ocrypto.ECPubKeyFromPem([]byte(kasPublicKey))
	if err != nil {
		return 0, fmt.Errorf("ocrypto.ECPubKeyFromPem failed: %w", err)
	}

	// Create nano tdf header
	key, totalSize, err := writeNanoTDFHeader(writer, config)
	if err != nil {
		return 0, fmt.Errorf("writeNanoTDFHeader failed:%w", err)
	}

	slog.Debug("CreateNanoTDF", slog.Uint64("Header", uint64(totalSize)))

	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		return 0, fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	ivPadding := make([]byte, kIvPadding)
	iv, err := ocrypto.RandomBytes(kNanoTDFIvSize)
	if err != nil {
		return 0, fmt.Errorf("ocrypto.RandomBytes failed:%w", err)
	}

	tagSize, err := SizeOfAuthTagForCipher(config.sigCfg.cipher)
	if err != nil {
		return 0, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
	}

	cipherData, err := aesGcm.EncryptWithIVAndTagSize(append(ivPadding, iv...), buf.Bytes(), tagSize)
	if err != nil {
		return 0, err
	}

	// Write the length of the payload as int24
	cipherDataWithoutPadding := cipherData[kIvPadding:]
	uint32Buf := make([]byte, 4)
	binary.BigEndian.PutUint32(uint32Buf, uint32(len(cipherDataWithoutPadding)))
	l, err := writer.Write(uint32Buf[1:])
	if err != nil {
		return 0, err
	}
	totalSize += uint32(l)

	slog.Debug("CreateNanoTDF", slog.Uint64("payloadLength", uint64(len(cipherDataWithoutPadding))))

	// write cipher data
	l, err = writer.Write(cipherDataWithoutPadding)
	if err != nil {
		return 0, err
	}
	totalSize += uint32(l)

	return totalSize, nil
}

func (s SDK) ReadNanoTDF(writer io.Writer, reader io.ReadSeeker) (uint32, error) {

	header, headerSize, err := NewNanoTDFHeaderFromReader(reader)
	if err != nil {
		return 0, err
	}

	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	headerBuf := make([]byte, headerSize)
	_, err = reader.Read(headerBuf)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	kasURL, err := header.kasURL.getUrl()
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	encodedHeader := ocrypto.Base64Encode(headerBuf)

	client, err := newKASClient(s.dialOptions, s.tokenSource)
	if err != nil {
		return 0, fmt.Errorf("newKASClient failed: %w", err)
	}

	symmetricKey, err := client.unwrapNanoTDF(string(encodedHeader), kasURL)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	encoded := ocrypto.Base64Encode(symmetricKey)
	slog.Debug("ReadNanoTDF", slog.String("symmetricKey", string(encoded)))

	payloadLengthBuf := make([]byte, 4)
	_, err = reader.Read(payloadLengthBuf[1:])

	if err != nil {
		return 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}

	payloadLength := binary.BigEndian.Uint32(payloadLengthBuf)
	slog.Debug("ReadNanoTDF", slog.Uint64("payloadLength", uint64(payloadLength)))

	cipherDate := make([]byte, payloadLength)
	_, err = reader.Read(cipherDate)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	aesGcm, err := ocrypto.NewAESGcm(symmetricKey)
	if err != nil {
		return 0, fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	ivPadding := make([]byte, kIvPadding)
	iv := cipherDate[:kNanoTDFIvSize]
	if err != nil {
		return 0, fmt.Errorf("ocrypto.RandomBytes failed:%w", err)
	}

	tagSize, err := SizeOfAuthTagForCipher(header.sigCfg.cipher)
	if err != nil {
		return 0, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
	}

	decryptedData, err := aesGcm.DecryptWithIVAndTagSize(append(ivPadding, iv...), cipherDate[kNanoTDFIvSize:], tagSize)
	if err != nil {
		return 0, err
	}

	len, err := writer.Write(decryptedData)
	if err != nil {
		return 0, err
	}
	//print(payloadLength)
	//print(string(decryptedData))

	return uint32(len), nil
}

func getECPublicKey(kasURL string, opts ...grpc.DialOption) (string, error) {
	req := kas.PublicKeyRequest{}
	req.Algorithm = "ec:secp256r1"
	grpcAddress, err := getGRPCAddress(kasURL)
	if err != nil {
		return "", err
	}
	conn, err := grpc.Dial(grpcAddress, opts...)
	if err != nil {
		return "", fmt.Errorf("error connecting to grpc service at %s: %w", kasURL, err)
	}
	defer conn.Close()

	ctx := context.Background()
	serviceClient := kas.NewAccessServiceClient(conn)

	resp, err := serviceClient.PublicKey(ctx, &req)

	if err != nil {
		return "", fmt.Errorf("error making request to KAS: %w", err)
	}

	return resp.GetPublicKey(), nil
}

type requestBody struct {
	Algorithm       string    `json:"algorithm,omitempty"`
	KeyAccess       keyAccess `json:"keyAccess"`
	ClientPublicKey string    `json:"clientPublicKey"`
}

type keyAccess struct {
	Header        string `json:"header"`
	KeyAccessType string `json:"type"`
	Url           string `json:"url"`
	Protocol      string `json:"protocol"`
}

//func nanoTDFRewrap(header string, kasURL string) ([]byte, error) {
//
//	keypair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
//	if err != nil {
//		return nil, fmt.Errorf("ocrypto.NewECKeyPair failed :%w", err)
//	}
//
//	publicKeyAsPem, err := keypair.PublicKeyInPemFormat()
//	if err != nil {
//		return nil, fmt.Errorf("ocrypto.NewECKeyPair.PublicKeyInPemFormat failed :%w", err)
//	}
//
//	kAccess := keyAccess{
//		Header:        header,
//		KeyAccessType: "remote",
//		Url:           kasURL,
//		Protocol:      "kas",
//	}
//
//	rBody := requestBody{
//		Algorithm:       "ec:secp256r1",
//		KeyAccess:       kAccess,
//		ClientPublicKey: publicKeyAsPem,
//	}
//
//	_, err := json.Marshal(rBody)
//	if err != nil {
//
//	}
//}

func UInt24ToUInt32(b []byte) uint32 {
	buf := make([]byte, 4)
	//copy(buf[1:], b)
	copy(buf[:len(buf)-1], b)
	//fmt.Println(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(buf)), 2))
	return binary.LittleEndian.Uint32(buf)
}

func UInt32ToUInt24(s uint32) []byte {
	//fmt.Println(strconv.FormatUint(uint64(s), 2))
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, s)
	//return buf[1:]
	return buf[:len(buf)-1]
}
