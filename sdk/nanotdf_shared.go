package sdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/nanobuilder"
)

// ============================================================================================================
// Internal Types & Constants (Implementation Details)
// ============================================================================================================

const (
	kIvPadding                    = 9
	kNanoTDFIvSize                = 3
	kNanoTDFGMACLength            = 8
	kNanoTDFMagicStringAndVersion = "L1L"
	kMaxIters                     = 1<<24 - 1

	ErrNanoTDFHeaderRead = Error("nanoTDF read error")
)

type CipherMode int

const (
	cipherModeAes256gcm64Bit  CipherMode = 0
	cipherModeAes256gcm96Bit  CipherMode = 1
	cipherModeAes256gcm104Bit CipherMode = 2
	cipherModeAes256gcm112Bit CipherMode = 3
	cipherModeAes256gcm120Bit CipherMode = 4
	cipherModeAes256gcm128Bit CipherMode = 5
)

// ============================================================================================================
// HeaderWriter Implementation (Satisfies nanobuilder.HeaderWriter[NanoTDFConfig])
// ============================================================================================================

type StandardHeaderWriter struct{}

func (s *StandardHeaderWriter) Write(writer io.Writer, config NanoTDFConfig) ([]byte, uint32, uint32, error) {
	// Handle Collection State
	if config.collectionCfg.useCollection {
		config.collectionCfg.mux.Lock()
		defer config.collectionCfg.mux.Unlock()

		iteration := config.collectionCfg.iterations
		config.collectionCfg.iterations++
		header := config.collectionCfg.header
		if iteration == kMaxIters {
			config.collectionCfg.iterations = 0
		}
		if iteration != 0 {
			n, err := writer.Write(header)
			return config.collectionCfg.symKey, uint32(n), iteration, err
		}
		buf := &bytes.Buffer{}
		writer = io.MultiWriter(writer, buf)
		defer func() { config.collectionCfg.header = buf.Bytes() }()
	}

	var totalBytes uint32

	// Magic Number
	l, err := writer.Write([]byte(kNanoTDFMagicStringAndVersion))
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// KAS URL
	err = config.kasURL.writeResourceLocator(writer)
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(config.kasURL.getLength())

	// Binding Config
	l, err = writer.Write([]byte{serializeBindingCfg(config.bindCfg)})
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Signature Config
	l, err = writer.Write([]byte{serializeSignatureCfg(config.GetSignatureConfig())})
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Policy Mode
	config.policy.body.mode = config.policyMode
	l, err = writer.Write([]byte{byte(config.policy.body.mode)})
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Policy Object
	policyObj, err := createPolicyObject(config.attributes)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("fail to create policy object:%w", err)
	}

	policyObjectAsStr, err := json.Marshal(policyObj)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("json.Marshal failed:%w", err)
	}

	// Key Derivation
	symmetricKey, err := createNanoTDFSymmetricKey(config)
	if err != nil {
		return nil, 0, 0, err
	}

	if config.collectionCfg.useCollection {
		config.collectionCfg.symKey = symmetricKey
	}

	// Embedded Policy
	embeddedP, err := createNanoTDFEmbeddedPolicy(symmetricKey, policyObjectAsStr, config)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to create embedded policy:%w", err)
	}

	err = embeddedP.writeEmbeddedPolicy(writer)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("writeEmbeddedPolicy failed:%w", err)
	}
	totalBytes += 2 + uint32(len(embeddedP.body))

	digest := ocrypto.CalculateSHA256(embeddedP.body)

	// Policy Binding
	if config.bindCfg.useEcdsaBinding {
		rBytes, sBytes, err := ocrypto.ComputeECDSASig(digest, config.keyPair.PrivateKey)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("ComputeECDSASig failed:%w", err)
		}
		writer.Write([]byte{uint8(len(rBytes))})
		writer.Write(rBytes)
		writer.Write([]byte{uint8(len(sBytes))})
		writer.Write(sBytes)
		totalBytes += uint32(1 + len(rBytes) + 1 + len(sBytes))
	} else {
		binding := digest[len(digest)-kNanoTDFGMACLength:]
		l, err = writer.Write(binding)
		if err != nil {
			return nil, 0, 0, err
		}
		totalBytes += uint32(l)
	}

	// Ephemeral Key
	ephemeralPublicKeyKey, _ := ocrypto.CompressedECPublicKey(config.bindCfg.eccMode, config.keyPair.PrivateKey.PublicKey)
	l, err = writer.Write(ephemeralPublicKeyKey)
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	return symmetricKey, totalBytes, 0, nil
}

// ============================================================================================================
// HeaderReader Implementation (Satisfies nanobuilder.HeaderReader)
// ============================================================================================================

type StandardHeaderReader struct{}

func (s *StandardHeaderReader) Read(reader io.Reader) (nanobuilder.HeaderInfo, []byte, error) {
	header, headerBuf, err := newNanoTDFHeaderFromReader(reader)
	if err != nil {
		return nil, nil, err
	}
	return header, headerBuf, nil
}

func NewNanoTDFHeaderFromReader(reader io.Reader) (*nanobuilder.NanoTDFHeader, int, error) {
	header, headerBuf, err := newNanoTDFHeaderFromReader(reader)
	if err != nil {
		return nil, 0, err
	}
	return header, len(headerBuf), nil
}
func newNanoTDFHeaderFromReader(reader io.Reader) (*nanobuilder.NanoTDFHeader, []byte, error) {
	// We read everything into a concrete struct
	header := nanobuilder.NanoTDFHeader{}
	var size uint32

	// Magic Number
	magicNumber := make([]byte, len(kNanoTDFMagicStringAndVersion))
	l, err := reader.Read(magicNumber)
	if err != nil {
		return nil, nil, fmt.Errorf("io.Reader.Read failed :%w", err)
	}
	if string(magicNumber) != kNanoTDFMagicStringAndVersion {
		return nil, nil, errors.New("not a valid nano tdf")
	}
	size += uint32(l)

	// Resource Locator
	resource, err := NewResourceLocatorFromReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("call to NewResourceLocatorFromReader failed :%w", err)
	}
	header.KasURL = *resource
	size += uint32(header.KasURL.Len())

	// Configs
	oneBytes := make([]byte, 1)
	l, err = reader.Read(oneBytes)
	if err != nil {
		return nil, nil, err
	}
	size += uint32(l)
	header.BindCfg = deserializeBindingCfg(oneBytes[0])

	if header.BindCfg.EccMode != ocrypto.ECCModeSecp256r1 {
		return nil, nil, errors.New("current implementation of nano tdf only support secp256r1 curve")
	}

	l, err = reader.Read(oneBytes)
	if err != nil {
		return nil, nil, err
	}
	size += uint32(l)
	header.SigCfg = deserializeSignatureCfg(oneBytes[0])

	// Policy
	l, err = reader.Read(oneBytes)
	if err != nil {
		return nil, nil, err
	}
	size += uint32(l)

	header.PolicyMode = nanobuilder.PolicyType(oneBytes[0])
	if err := validNanoTDFPolicyMode(header.PolicyMode); err != nil {
		return nil, nil, err
	}

	const kSizeOfUint16 = 2
	twoBytes := make([]byte, kSizeOfUint16)
	l, err = reader.Read(twoBytes)
	if err != nil {
		return nil, nil, err
	}
	size += uint32(l)
	policyLength := binary.BigEndian.Uint16(twoBytes)

	header.PolicyBody = make([]byte, policyLength)
	l, err = reader.Read(header.PolicyBody)
	if err != nil {
		return nil, nil, err
	}
	size += uint32(l)

	// Binding
	if header.GetBindingConfig().UseEcdsaBinding {
		// Read R
		reader.Read(oneBytes) // len
		size += 1
		header.EcdsaPolicyBindingR = make([]byte, oneBytes[0])
		l, _ = reader.Read(header.EcdsaPolicyBindingR)
		size += uint32(l)

		// Read S
		reader.Read(oneBytes) // len
		size += 1
		header.EcdsaPolicyBindingS = make([]byte, oneBytes[0])
		l, _ = reader.Read(header.EcdsaPolicyBindingS)
		size += uint32(l)
	} else {
		header.GmacPolicyBinding = make([]byte, kNanoTDFGMACLength)
		l, err = reader.Read(header.GmacPolicyBinding)
		size += uint32(l)
	}

	// Ephemeral Key
	ephemeralKeySize, err := getECCKeyLength(header.BindCfg.EccMode)
	if err != nil {
		return nil, nil, err
	}
	header.EphemeralKey = make([]byte, ephemeralKeySize)
	l, err = reader.Read(header.EphemeralKey)
	if err != nil {
		return nil, nil, err
	}
	size += uint32(l)

	// Rewind to get the full buffer
	readSeeker, ok := reader.(io.ReadSeeker)
	if !ok {
		return nil, nil, errors.New("reader must be a ReadSeeker")
	}
	_, err = readSeeker.Seek(0, io.SeekStart)
	if err != nil {
		return nil, nil, err
	}

	headerBuf := make([]byte, size)
	_, err = readSeeker.Read(headerBuf)
	if err != nil {
		return nil, nil, err
	}

	return &header, headerBuf, nil
}

// ============================================================================================================
// Encryptor Implementation (Satisfies nanobuilder.Encryptor)
// ============================================================================================================

type StandardEncryptor struct {
	UseCollection bool
}

func (e *StandardEncryptor) GenerateIV(iteration uint32) ([]byte, error) {
	if e.UseCollection {
		ivPadded := make([]byte, ocrypto.GcmStandardNonceSize) // 12 bytes
		iv := make([]byte, binary.MaxVarintLen32)
		binary.LittleEndian.PutUint32(iv, iteration)
		copy(ivPadded[kIvPadding:], iv[:kNanoTDFIvSize])
		return ivPadded, nil
	}
	return nonZeroRandomPaddedIV()
}

func (e *StandardEncryptor) GetTagSize(cipherEnum int) (int, error) {
	return SizeOfAuthTagForCipher(CipherMode(cipherEnum))
}

func (e *StandardEncryptor) Encrypt(payload, key, iv []byte, tagSize int) ([]byte, error) {
	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		return nil, err
	}

	// EncryptWithIVAndTagSize usually returns [IV][Ciphertext][Tag] (or similar based on library)
	// The NanoTDF spec writes the IV separate from the ciphertext.
	// We strip the IV padding from the start because nanobuilder expects just the ciphertext/tag to write.
	res, err := aesGcm.EncryptWithIVAndTagSize(iv, payload, tagSize)
	if err != nil {
		return nil, err
	}

	return res[kIvPadding:], nil
}

func (e *StandardEncryptor) Decrypt(ciphertext, key []byte, tagSize int) ([]byte, error) {
	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		return nil, err
	}

	// Reconstruct the padded IV from the ciphertext prefix
	ivPadded := make([]byte, 0, ocrypto.GcmStandardNonceSize)
	noncePadding := make([]byte, kIvPadding)
	ivPadded = append(ivPadded, noncePadding...)

	// The first 3 bytes of ciphertext are the IV
	realIV := ciphertext[:kNanoTDFIvSize]
	ivPadded = append(ivPadded, realIV...)

	// The rest is actual encrypted data
	actualCiphertext := ciphertext[kNanoTDFIvSize:]

	return aesGcm.DecryptWithIVAndTagSize(ivPadded, actualCiphertext, tagSize)
}

// ============================================================================================================
// KeyCache Implementation (Satisfies nanobuilder.KeyCache)
// ============================================================================================================

// Note: This relies on collectionStore defined in nanotdf_collectionstore.go which matches this signature

// ============================================================================================================
// Internal Helpers
// ============================================================================================================

func nonZeroRandomPaddedIV() ([]byte, error) {
	loopCount := 1
	for {
		ivPadded := make([]byte, 0, ocrypto.GcmStandardNonceSize)
		noncePadding := make([]byte, kIvPadding)
		ivPadded = append(ivPadded, noncePadding...)
		iv, err := ocrypto.RandomBytes(kNanoTDFIvSize)
		if err != nil {
			return nil, fmt.Errorf("ocrypto.RandomBytes failed:%w", err)
		}
		ivPadded = append(ivPadded, iv...)
		for _, b := range ivPadded {
			if b != 0 {
				return ivPadded, nil
			}
		}
		if loopCount >= 10 {
			return nil, errors.New("nonZeroPaddedIV loop exceeded limit")
		}
		loopCount++
	}
}

func SizeOfAuthTagForCipher(cipherType CipherMode) (int, error) {
	switch cipherType {
	case cipherModeAes256gcm64Bit:
		return 8, nil
	case cipherModeAes256gcm96Bit:
		return 12, nil
	case cipherModeAes256gcm104Bit:
		return 13, nil
	case cipherModeAes256gcm112Bit:
		return 14, nil
	case cipherModeAes256gcm120Bit:
		return 15, nil
	case cipherModeAes256gcm128Bit:
		return 16, nil
	default:
		return 0, fmt.Errorf("unknown cipher mode:%d", cipherType)
	}
}

func createNanoTDFSymmetricKey(config NanoTDFConfig) ([]byte, error) {
	if config.kasPublicKey == nil {
		return nil, errors.New("KAS public key is required for encrypted policy mode")
	}
	ecdhKey, err := ocrypto.ConvertToECDHPrivateKey(config.keyPair.PrivateKey)
	if err != nil {
		return nil, err
	}
	symKey, err := ocrypto.ComputeECDHKeyFromECDHKeys(config.kasPublicKey, ecdhKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	digest.Write([]byte(kNanoTDFMagicStringAndVersion))
	salt := digest.Sum(nil)
	return ocrypto.CalculateHKDF(salt, symKey)
}

func getECCKeyLength(curve ocrypto.ECCMode) (uint8, error) {
	switch curve {
	case ocrypto.ECCModeSecp256r1:
		return 33, nil
	case ocrypto.ECCModeSecp256k1:
		return 33, nil
	case ocrypto.ECCModeSecp384r1:
		return 49, nil
	case ocrypto.ECCModeSecp521r1:
		return 67, nil
	default:
		return 0, fmt.Errorf("unknown cipher mode:%d", curve)
	}
}

type bindingConfig struct {
	useEcdsaBinding bool
	eccMode         ocrypto.ECCMode
}

type signatureConfig struct {
	hasSignature  bool
	signatureMode ocrypto.ECCMode
	cipher        CipherMode
}

type collectionConfig struct {
	iterations    uint32
	header        []byte
	useCollection bool
	symKey        []byte
	mux           sync.Mutex
}

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
	slog.Debug("writeEmbeddedPolicy", slog.Uint64("policy_length", uint64(ep.lengthBody)))

	if _, err := writer.Write(ep.body); err != nil {
		return err
	}
	slog.Debug("writeEmbeddedPolicy", slog.Uint64("policy_body", uint64(len(ep.body))))

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

func deserializeBindingCfg(b byte) nanobuilder.BindingConfig {
	cfg := nanobuilder.BindingConfig{}
	cfg.UseEcdsaBinding = (b >> 7 & 0b00000001) == 1
	cfg.EccMode = ocrypto.ECCMode(b & 0b00000111)
	return cfg
}

func serializeBindingCfg(bindCfg bindingConfig) byte {
	var bindSerial byte = 0x00
	if bindCfg.useEcdsaBinding {
		bindSerial |= 0b10000000
	}
	bindSerial |= (byte(bindCfg.eccMode) & 0b00000111)
	return bindSerial
}

func deserializeSignatureCfg(b byte) nanobuilder.SignatureConfig {
	cfg := nanobuilder.SignatureConfig{}
	cfg.HasSignature = (b >> 7 & 0b000000001) == 1
	cfg.SignatureMode = ocrypto.ECCMode((b >> 4) & 0b00000111)
	cfg.Cipher = nanobuilder.CipherMode(b & 0b00001111)
	return cfg
}

func serializeSignatureCfg(sigCfg nanobuilder.SignatureConfig) byte {
	var sigSerial byte = 0x00
	if sigCfg.HasSignature {
		sigSerial |= 0b10000000
	}
	sigSerial |= byte((sigCfg.SignatureMode)&0b00000111) << 4
	sigSerial |= byte((sigCfg.Cipher) & 0b00001111)
	return sigSerial
}
