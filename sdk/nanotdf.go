package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
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
// Support for nanoTDF operations
//
// See also the nanotdf_config.go interface
//
// ============================================================================================================

// / Constants
const (
	kMaxTDFSize = ((16 * 1024 * 1024) - 3 - 32) //nolint:gomnd // 16 mb - 3(iv) - 32(max auth tag)
	// kDatasetMaxMBBytes = 2097152                       // 2mb

	// Max size of the encrypted tdfs
	//  16mb payload
	// ~67kb of policy
	// 133 of signature
	// kMaxEncryptedNTDFSize = (16 * 1024 * 1024) + (68 * 1024) + 133 //nolint:gomnd // See comment block above

	kIvPadding                    = 9
	kNanoTDFIvSize                = 3
	kNanoTDFGMACLength            = 8
	kNanoTDFMagicStringAndVersion = "L1L"
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
	kasURL              ResourceLocator
	bindCfg             bindingConfig
	sigCfg              signatureConfig
	EphemeralKey        []byte
	EncryptedPolicyBody []byte
	PolicyBinding       []byte
}

// GetCipher -- get the cipher from the nano tdf header
func (header *NanoTDFHeader) GetCipher() CipherMode {
	return header.sigCfg.cipher
}

// ============================================================================================================

// embeddedPolicy - policy for data that is stored locally within the nanoTDF
type embeddedPolicy struct {
	lengthBody uint16
	body       []byte
}

// getLength - size in bytes of the serialized content of this object
// func (ep *embeddedPolicy) getLength() uint16 {
//	const (
//		kUint16Len = 2
//	)
//	return uint16(kUint16Len /* length word length */ + len(ep.body) /* body data length */)
// }

// writeEmbeddedPolicy - writes the content of the  to the supplied writer
func (ep embeddedPolicy) writeEmbeddedPolicy(writer io.Writer) error {
	// store uint16 in big endian format
	const (
		kUint16Len = 2
	)
	buf := make([]byte, kUint16Len)
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
// func (rp *remotePolicy) getLength() uint16 {
//	return rp.url.getLength()
// }

// ============================================================================================================

type bindingConfig struct {
	useEcdsaBinding bool
	padding         uint8
	eccMode         ocrypto.ECCMode
}

type signatureConfig struct {
	hasSignature  bool
	signatureMode ocrypto.ECCMode
	cipher        CipherMode
}

type policyInfo struct {
	body PolicyBody
	//	binding *eccSignature
}

// type eccSignature struct {
//	value []byte
// }

// type eccKey struct {
//	Key []byte
// }

type CipherMode int

const (
	cipherModeAes256gcm64Bit  CipherMode = 0
	cipherModeAes256gcm96Bit  CipherMode = 1
	cipherModeAes256gcm104Bit CipherMode = 2
	cipherModeAes256gcm112Bit CipherMode = 3
	cipherModeAes256gcm120Bit CipherMode = 4
	cipherModeAes256gcm128Bit CipherMode = 5
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
	cfg.cipher = CipherMode(b & 0b00001111) //nolint:gomnd // better readability as literal

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
// ECC info
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

// ============================================================================================================
// Auth Tag info
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
func SizeOfAuthTagForCipher(cipherType CipherMode) (int, error) {
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

// ============================================================================================================
// NanoTDF Header read/write
// ============================================================================================================

func writeNanoTDFHeader(writer io.Writer, config NanoTDFConfig) ([]byte, uint32, error) {
	var totalBytes uint32

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

	salt := versionSalt()

	symmetricKey, err := ocrypto.CalculateHKDF(salt, symKey)
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

	const (
		kIvLength = 12
	)
	iv := make([]byte, kIvLength)
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
	const (
		kSizeOfUint16 = 2
	)
	totalBytes += kSizeOfUint16 + uint32(len(embeddedP.body))

	digest := ocrypto.CalculateSHA256(embeddedP.body)
	binding := digest[len(digest)-kNanoTDFGMACLength:]
	l, err = writer.Write(binding)
	if err != nil {
		return nil, 0, err
	}
	totalBytes += uint32(l)

	ephemeralPublicKeyKey, _ := ocrypto.CompressedECPublicKey(config.bindCfg.eccMode, config.keyPair.PrivateKey.PublicKey)

	l, err = writer.Write(ephemeralPublicKeyKey)
	if err != nil {
		return nil, 0, err
	}
	totalBytes += uint32(l)

	return symmetricKey, totalBytes, nil
}

func NewNanoTDFHeaderFromReader(reader io.Reader) (NanoTDFHeader, uint32, error) {
	header := NanoTDFHeader{}
	var size uint32

	magicNumber := make([]byte, len(kNanoTDFMagicStringAndVersion))
	l, err := reader.Read(magicNumber)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	if magicNumber[0] != kNanoTDFMagicStringAndVersion[0] || magicNumber[1] != kNanoTDFMagicStringAndVersion[1] || magicNumber[2] != kNanoTDFMagicStringAndVersion[2] {
		return header, 0, fmt.Errorf(" io.Reader.Read magic number failed : %w", err)
	}
	size += uint32(l)

	if string(magicNumber) != kNanoTDFMagicStringAndVersion {
		return header, 0, fmt.Errorf("not a valid nano tdf")
	}

	// read resource locator
	resource, err := NewResourceLocatorFromReader(reader)
	if err != nil {
		return header, 0, fmt.Errorf("call to NewResourceLocatorFromReader failed :%w", err)
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
	const (
		kSizeOfUint16 = 2
	)
	twoBytes := make([]byte, kSizeOfUint16)
	l, err = reader.Read(twoBytes)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)
	policyLength := binary.BigEndian.Uint16(twoBytes)
	slog.Debug("NewNanoTDFHeaderFromReader", slog.Uint64("policyLength", uint64(policyLength)))

	// read policy body
	header.EncryptedPolicyBody = make([]byte, policyLength)
	l, err = reader.Read(header.EncryptedPolicyBody)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)

	// read policy binding
	header.PolicyBinding = make([]byte, kNanoTDFGMACLength)
	l, err = reader.Read(header.PolicyBinding)
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

// ============================================================================================================
// NanoTDF Encrypt
// ============================================================================================================

// CreateNanoTDF - reads plain text from the given reader and saves it to the writer, subject to the given options
func (s SDK) CreateNanoTDF(writer io.Writer, reader io.Reader, config NanoTDFConfig) (uint32, error) {
	var totalSize uint32
	buf := bytes.Buffer{}
	size, err := buf.ReadFrom(reader)
	if err != nil {
		return 0, err
	}

	if size > kMaxTDFSize {
		return 0, errors.New("exceeds max size for nano tdf")
	}

	kasURL, err := config.kasURL.getURL()
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

	ivPadded := make([]byte, 0, ocrypto.GcmStandardNonceSize)
	noncePadding := make([]byte, kIvPadding)
	ivPadded = append(ivPadded, noncePadding...)
	iv, err := ocrypto.RandomBytes(kNanoTDFIvSize)
	if err != nil {
		return 0, fmt.Errorf("ocrypto.RandomBytes failed:%w", err)
	}
	ivPadded = append(ivPadded, iv...)

	tagSize, err := SizeOfAuthTagForCipher(config.sigCfg.cipher)
	if err != nil {
		return 0, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
	}

	cipherData, err := aesGcm.EncryptWithIVAndTagSize(ivPadded, buf.Bytes(), tagSize)
	if err != nil {
		return 0, err
	}

	// Write the length of the payload as int24
	cipherDataWithoutPadding := cipherData[kIvPadding:]
	const (
		kUint32BufLen = 4
	)
	uint32Buf := make([]byte, kUint32BufLen)
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

// ============================================================================================================
// NanoTDF Decrypt
// ============================================================================================================

// ReadNanoTDF - read the nano tdf and return the decrypted data from it
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

	kasURL, err := header.kasURL.getURL()
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	encodedHeader := ocrypto.Base64Encode(headerBuf)

	rsaKeyPair, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return 0, fmt.Errorf("ocrypto.NewRSAKeyPair failed: %w", err)
	}

	client, err := newKASClient(s.dialOptions, s.tokenSource, rsaKeyPair)
	if err != nil {
		return 0, fmt.Errorf("newKASClient failed: %w", err)
	}

	symmetricKey, err := client.unwrapNanoTDF(string(encodedHeader), kasURL)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	encoded := ocrypto.Base64Encode(symmetricKey)
	slog.Debug("ReadNanoTDF", slog.String("symmetricKey", string(encoded)))

	const (
		kPayloadLoadLengthBufLength = 4
	)
	payloadLengthBuf := make([]byte, kPayloadLoadLengthBufLength)
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

	ivPadded := make([]byte, 0, ocrypto.GcmStandardNonceSize)
	noncePadding := make([]byte, kIvPadding)
	ivPadded = append(ivPadded, noncePadding...)
	iv := cipherDate[:kNanoTDFIvSize]
	ivPadded = append(ivPadded, iv...)

	tagSize, err := SizeOfAuthTagForCipher(header.sigCfg.cipher)
	if err != nil {
		return 0, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
	}

	decryptedData, err := aesGcm.DecryptWithIVAndTagSize(ivPadded, cipherDate[kNanoTDFIvSize:], tagSize)
	if err != nil {
		return 0, err
	}

	writeLen, err := writer.Write(decryptedData)
	if err != nil {
		return 0, err
	}
	// print(payloadLength)
	// print(string(decryptedData))

	return uint32(writeLen), nil
}

// getECPublicKey - Contact the specified KAS and get its public key
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
	URL           string `json:"url"`
	Protocol      string `json:"protocol"`
}

func versionSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte(kNanoTDFMagicStringAndVersion))
	return digest.Sum(nil)
}
