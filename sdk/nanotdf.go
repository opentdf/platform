package sdk

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/sdkconnect"

	"github.com/opentdf/platform/lib/ocrypto"
)

// ============================================================================================================
// Support for nanoTDF operations
//
// See also the nanotdf_config.go interface
//
// ============================================================================================================

// / Constants
const (
	kMaxTDFSize = ((16 * 1024 * 1024) - 3 - 32) //nolint:mnd // 16 mb - 3(iv) - 32(max auth tag)
	// kDatasetMaxMBBytes = 2097152                       // 2mb

	// Max size of the encrypted tdfs
	//  16mb payload
	// ~67kb of policy
	// 133 of signature
	// kMaxEncryptedNTDFSize = (16 * 1024 * 1024) + (68 * 1024) + 133 //nolint:mnd // See comment block above

	kIvPadding                    = 9
	kNanoTDFIvSize                = 3
	kNanoTDFGMACLength            = 8
	kNanoTDFMagicStringAndVersion = "L1L"
	kMaxIters                     = 1<<24 - 1
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
	PolicyMode          PolicyType
	PolicyBody          []byte
	gmacPolicyBinding   []byte
	ecdsaPolicyBindingR []byte
	ecdsaPolicyBindingS []byte
}

func NewNanoTDFHeaderFromReader(reader io.Reader) (NanoTDFHeader, uint32, error) {
	header := NanoTDFHeader{}
	var size uint32

	// Read and validate magic number
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
		return header, 0, errors.New("not a valid nano tdf")
	}

	// Read resource locator
	resource, err := NewResourceLocatorFromReader(reader)
	if err != nil {
		return header, 0, fmt.Errorf("call to NewResourceLocatorFromReader failed :%w", err)
	}
	size += uint32(resource.getLength())
	header.kasURL = *resource

	slog.Debug("checkpoint NewNanoTDFHeaderFromReader", slog.Uint64("resource_locator", uint64(resource.getLength())))

	// Read ECC and Binding Mode
	oneBytes := make([]byte, 1)
	l, err = reader.Read(oneBytes)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)
	header.bindCfg = deserializeBindingCfg(oneBytes[0])

	// Check ephemeral ECC Params Enum
	if header.bindCfg.eccMode != ocrypto.ECCModeSecp256r1 {
		return header, 0, errors.New("current implementation of nano tdf only support secp256r1 curve")
	}

	// Read Payload and Sig Mode
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

	policyMode := PolicyType(oneBytes[0])
	if err := validNanoTDFPolicyMode(policyMode); err != nil {
		return header, 0, errors.Join(fmt.Errorf("unsupported policy mode: %v", policyMode), err)
	}

	// Read policy length
	const kSizeOfUint16 = 2
	twoBytes := make([]byte, kSizeOfUint16)
	l, err = reader.Read(twoBytes)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)
	policyLength := binary.BigEndian.Uint16(twoBytes)
	slog.Debug("checkpoint NewNanoTDFHeaderFromReader", slog.Uint64("policy_length", uint64(policyLength)))

	// Read policy body
	header.PolicyMode = policyMode
	header.PolicyBody = make([]byte, policyLength)
	l, err = reader.Read(header.PolicyBody)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)

	// Read policy binding
	if header.bindCfg.useEcdsaBinding { //nolint:nestif // TODO: refactor
		// Read rBytes len and its contents
		l, err = reader.Read(oneBytes)
		if err != nil {
			return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
		}
		size += uint32(l)

		header.ecdsaPolicyBindingR = make([]byte, oneBytes[0])
		l, err = reader.Read(header.ecdsaPolicyBindingR)
		if err != nil {
			return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
		}
		size += uint32(l)

		// Read sBytes len and its contents
		l, err = reader.Read(oneBytes)
		if err != nil {
			return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
		}
		size += uint32(l)

		header.ecdsaPolicyBindingS = make([]byte, oneBytes[0])
		l, err = reader.Read(header.ecdsaPolicyBindingS)
		if err != nil {
			return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
		}
		size += uint32(l)
	} else {
		header.gmacPolicyBinding = make([]byte, kNanoTDFGMACLength)
		l, err = reader.Read(header.gmacPolicyBinding)
		if err != nil {
			return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
		}
		size += uint32(l)
	}

	ephemeralKeySize, err := getECCKeyLength(header.bindCfg.eccMode)
	if err != nil {
		return header, 0, fmt.Errorf("getECCKeyLength :%w", err)
	}

	// Read ephemeral Key
	ephemeralKey := make([]byte, ephemeralKeySize)
	l, err = reader.Read(ephemeralKey)
	if err != nil {
		return header, 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}
	size += uint32(l)
	header.EphemeralKey = ephemeralKey

	slog.Debug("checkpoint NewNanoTDFHeaderFromReader", slog.Uint64("header_size", uint64(size)))

	return header, size, nil
}

func (header *NanoTDFHeader) GetKasURL() ResourceLocator {
	return header.kasURL
}

// GetCipher -- get the cipher from the nano tdf header
func (header *NanoTDFHeader) GetCipher() CipherMode {
	return header.sigCfg.cipher
}

func (header *NanoTDFHeader) IsEcdsaBindingEnabled() bool {
	return header.bindCfg.useEcdsaBinding
}

func (header *NanoTDFHeader) ECCurve() (elliptic.Curve, error) {
	return ocrypto.GetECCurveFromECCMode(header.bindCfg.eccMode)
}

func (header *NanoTDFHeader) VerifyPolicyBinding() (bool, error) {
	curve, err := ocrypto.GetECCurveFromECCMode(header.bindCfg.eccMode)
	if err != nil {
		return false, err
	}

	digest := ocrypto.CalculateSHA256(header.PolicyBody)
	if header.IsEcdsaBindingEnabled() {
		ephemeralECDSAPublicKey, err := ocrypto.UncompressECPubKey(curve, header.EphemeralKey)
		if err != nil {
			return false, err
		}

		return ocrypto.VerifyECDSASig(digest,
			header.ecdsaPolicyBindingR,
			header.ecdsaPolicyBindingS,
			ephemeralECDSAPublicKey), nil
	}
	binding := digest[len(digest)-kNanoTDFGMACLength:]
	return bytes.Equal(binding, header.gmacPolicyBinding), nil
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
// | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
// ---------------------------------
// | E | x | x | x | x | M | M | M |
// ---------------------------------
// bit 7 - use ECDSA
// bit 6-3 - reserved
// bit 2-0 - ECC Curve enum

// deserializeBindingCfg - read byte of binding config into bindingConfig struct
func deserializeBindingCfg(b byte) bindingConfig {
	cfg := bindingConfig{}
	// Shift to low nybble test low bit
	cfg.useEcdsaBinding = (b >> 7 & 0b00000001) == 1 //nolint:mnd // better readability as literal
	// shift to low nybble and use low 3 bits
	cfg.eccMode = ocrypto.ECCMode(b & 0b00000111) //nolint:mnd // better readability as literal

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
	bindSerial |= (byte(bindCfg.eccMode) & 0b00000111) //nolint:mnd // better readability as literal

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
	cfg.hasSignature = (b >> 7 & 0b000000001) == 1 //nolint:mnd // better readability as literal
	// Shift high nybble down and mask for eccmode value
	cfg.signatureMode = ocrypto.ECCMode((b >> 4) & 0b00000111) //nolint:mnd // better readability as literal
	// Mask low nybble for cipher value
	cfg.cipher = CipherMode(b & 0b00001111) //nolint:mnd // better readability as literal

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
	sigSerial |= byte((sigCfg.signatureMode)&0b00000111) << 4 //nolint:mnd // better readability as literal
	// Mask low nybble of cipher
	sigSerial |= byte((sigCfg.cipher) & 0b00001111) //nolint:mnd // better readability as literal

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
// NanoTDF Collection Header Store
// ============================================================================================================

const (
	kDefaultExpirationTime   = 5 * time.Minute
	kDefaultCleaningInterval = 10 * time.Minute
)

type collectionStore struct {
	cache          sync.Map
	expireDuration time.Duration
	closeChan      chan struct{}
}

type collectionStoreEntry struct {
	key             []byte
	encryptedHeader []byte
	expire          time.Time
}

func newCollectionStore(expireDuration, cleaningInterval time.Duration) *collectionStore {
	store := &collectionStore{expireDuration: expireDuration, cache: sync.Map{}, closeChan: make(chan struct{})}
	store.startJanitor(cleaningInterval)
	return store
}

func (c *collectionStore) startJanitor(cleaningInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(cleaningInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				c.cache.Range(func(key, value any) bool {
					entry, _ := value.(*collectionStoreEntry)
					if now.Compare(entry.expire) >= 0 {
						c.cache.Delete(key)
					}
					return true
				})
			case <-c.closeChan:
				return
			}
		}
	}()
}

func (c *collectionStore) store(header, key []byte) {
	hash := ocrypto.SHA256AsHex(header)
	expire := time.Now().Add(c.expireDuration)
	c.cache.Store(string(hash), &collectionStoreEntry{key: key, encryptedHeader: header, expire: expire})
}

func (c *collectionStore) get(header []byte) ([]byte, bool) {
	hash := ocrypto.SHA256AsHex(header)
	itemIntf, ok := c.cache.Load(string(hash))
	if !ok {
		return nil, false
	}
	item, _ := itemIntf.(*collectionStoreEntry)
	// check for hash collision
	if bytes.Equal(item.encryptedHeader, header) {
		return item.key, true
	}
	return nil, false
}

func (c *collectionStore) close() {
	c.closeChan <- struct{}{}
}

// ============================================================================================================
// NanoTDF Header read/write
// ============================================================================================================

func writeNanoTDFHeader(writer io.Writer, config NanoTDFConfig) ([]byte, uint32, uint32, error) {
	if config.collectionCfg.useCollection {
		// If concurrently writing, we must know what iteration we are on in a threadsafe way
		// also when we need to safely read the header to ensure not rewritten in next max iteration
		config.collectionCfg.mux.Lock()
		defer config.collectionCfg.mux.Unlock()

		// Store iteration and header and increment iteration
		iteration := config.collectionCfg.iterations
		config.collectionCfg.iterations++
		header := config.collectionCfg.header
		// Reset iteration if reached max iters
		if iteration == kMaxIters {
			config.collectionCfg.iterations = 0
		}
		// Return saved header
		if iteration != 0 {
			n, err := writer.Write(header)
			return config.collectionCfg.symKey, uint32(n), iteration, err
		}
		// First Iteration: header has not been calculated, will write to header and save for later use.
		buf := &bytes.Buffer{}
		writer = io.MultiWriter(writer, buf)
		defer func() { config.collectionCfg.header = buf.Bytes() }()
	}

	var totalBytes uint32

	// Write the magic number
	l, err := writer.Write([]byte(kNanoTDFMagicStringAndVersion))
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	slog.Debug("writeNanoTDFHeader", slog.Uint64("magic_number", uint64(len(kNanoTDFMagicStringAndVersion))))

	// Write the kas url
	err = config.kasURL.writeResourceLocator(writer)
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(config.kasURL.getLength())
	slog.Debug("writeNanoTDFHeader", slog.Uint64("resource_locator_number", uint64(config.kasURL.getLength())))

	// Write ECC And Binding Mode
	l, err = writer.Write([]byte{serializeBindingCfg(config.bindCfg)})
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Write Payload and Sig Mode
	l, err = writer.Write([]byte{serializeSignatureCfg(config.sigCfg)})
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Write policy mode
	config.policy.body.mode = config.policyMode
	l, err = writer.Write([]byte{byte(config.policy.body.mode)})
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Create policy object
	policyObj, err := createPolicyObject(config.attributes)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("fail to create policy object:%w", err)
	}

	policyObjectAsStr, err := json.Marshal(policyObj)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("json.Marshal failed:%w", err)
	}

	// Create the symmetric key
	symmetricKey, err := createNanoTDFSymmetricKey(config)
	if err != nil {
		return nil, 0, 0, err
	}

	// Set the symmetric key in the collection config
	if config.collectionCfg.useCollection {
		config.collectionCfg.symKey = symmetricKey
	}

	embeddedP, err := createNanoTDFEmbeddedPolicy(symmetricKey, policyObjectAsStr, config)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to create embedded policy:%w", err)
	}

	err = embeddedP.writeEmbeddedPolicy(writer)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("writeEmbeddedPolicy failed:%w", err)
	}

	// size of uint16
	const kSizeOfUint16 = 2
	totalBytes += kSizeOfUint16 + uint32(len(embeddedP.body))

	digest := ocrypto.CalculateSHA256(embeddedP.body)

	if config.bindCfg.useEcdsaBinding { //nolint:nestif // TODO: refactor
		rBytes, sBytes, err := ocrypto.ComputeECDSASig(digest, config.keyPair.PrivateKey)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("ComputeECDSASig failed:%w", err)
		}

		// write rBytes len and rBytes contents
		l, err = writer.Write([]byte{uint8(len(rBytes))})
		if err != nil {
			return nil, 0, 0, err
		}
		totalBytes += uint32(l)

		l, err = writer.Write(rBytes)
		if err != nil {
			return nil, 0, 0, err
		}
		totalBytes += uint32(l)

		// write sBytes len and sBytes contents
		l, err = writer.Write([]byte{uint8(len(sBytes))})
		if err != nil {
			return nil, 0, 0, err
		}
		totalBytes += uint32(l)

		l, err = writer.Write(sBytes)
		if err != nil {
			return nil, 0, 0, err
		}
		totalBytes += uint32(l)
	} else {
		binding := digest[len(digest)-kNanoTDFGMACLength:]
		l, err = writer.Write(binding)
		if err != nil {
			return nil, 0, 0, err
		}
		totalBytes += uint32(l)
	}

	ephemeralPublicKeyKey, _ := ocrypto.CompressedECPublicKey(config.bindCfg.eccMode, config.keyPair.PrivateKey.PublicKey)

	l, err = writer.Write(ephemeralPublicKeyKey)
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	return symmetricKey, totalBytes, 0, nil
}

func nonZeroRandomPaddedIV() ([]byte, error) {
	const (
		loopCountLimit = 10
	)
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
		// all zero IV, this is extremely rare so should be able to be addressed in the next loop
		if loopCount >= loopCountLimit { // crazy, there must be an issue with the constants
			return nil, errors.New("nonZeroPaddedIV loop exceeded limit")
		}
		loopCount++
	}
}

// ============================================================================================================
// NanoTDF Encrypt
// ============================================================================================================

// CreateNanoTDF - reads plain text from the given reader and saves it to the writer, subject to the given options
func (s SDK) CreateNanoTDF(writer io.Writer, reader io.Reader, config NanoTDFConfig) (uint32, error) {
	if writer == nil {
		return 0, errors.New("writer is nil")
	}
	if reader == nil {
		return 0, errors.New("reader is nil")
	}
	var totalSize uint32
	buf := bytes.Buffer{}
	size, err := buf.ReadFrom(reader)
	if err != nil {
		return 0, err
	}

	if size > kMaxTDFSize {
		return 0, errors.New("exceeds max size for nano tdf")
	}

	ki, err := getKasInfoForNanoTDF(&s, &config)
	if err != nil {
		return 0, fmt.Errorf("getKasInfoForNanoTDF failed: %w", err)
	}

	config.kasPublicKey, err = ocrypto.ECPubKeyFromPem([]byte(ki.PublicKey))
	if err != nil {
		return 0, fmt.Errorf("ocrypto.ECPubKeyFromPem failed: %w", err)
	}

	// Create nano tdf header
	key, totalSize, iteration, err := writeNanoTDFHeader(writer, config)
	if err != nil {
		return 0, fmt.Errorf("writeNanoTDFHeader failed:%w", err)
	}

	slog.Debug("checkpoint CreateNanoTDF", slog.Uint64("header", uint64(totalSize)))

	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		return 0, fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}
	var ivPadded []byte
	if config.collectionCfg.useCollection {
		ivPadded = make([]byte, gcmIvSize)
		iv := make([]byte, binary.MaxVarintLen32)
		binary.LittleEndian.PutUint32(iv, iteration)
		copy(ivPadded[kIvPadding:], iv[:kNanoTDFIvSize])
	} else {
		ivPadded, err = nonZeroRandomPaddedIV()
		if err != nil {
			return 0, err
		}
	}

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

	slog.Debug("checkpoint CreateNanoTDF", slog.Uint64("payload_length", uint64(len(cipherDataWithoutPadding))))

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

type NanoTDFDecryptHandler struct {
	reader io.ReadSeeker
	writer io.Writer

	header    NanoTDFHeader
	headerBuf []byte

	config *NanoTDFReaderConfig
}

type NanoTDFReader struct {
	reader          io.ReadSeeker
	tokenSource     auth.AccessTokenSource
	httpClient      *http.Client
	connectOptions  []connect.ClientOption
	collectionStore *collectionStore
	authV2Client    sdkconnect.AuthorizationServiceClientV2

	header     NanoTDFHeader
	headerBuf  []byte
	payloadKey []byte

	config              *NanoTDFReaderConfig
	requiredObligations *Obligations
}

func createNanoTDFDecryptHandler(reader io.ReadSeeker, writer io.Writer, opts ...NanoTDFReaderOption) (*NanoTDFDecryptHandler, error) {
	nanoTdfReaderConfig, err := newNanoTDFReaderConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("newNanoTDFReaderConfig failed: %w", err)
	}
	return &NanoTDFDecryptHandler{
		reader: reader,
		writer: writer,
		config: nanoTdfReaderConfig,
	}, nil
}

func (n *NanoTDFDecryptHandler) CreateRewrapRequest(ctx context.Context) (map[string]*kas.UnsignedRewrapRequest_WithPolicyRequest, error) {
	var err error
	n.header, n.headerBuf, err = getNanoTDFHeader(n.reader)
	if err != nil {
		return nil, err
	}

	return createNanoRewrapRequest(ctx, n.config, n.header, n.headerBuf)
}

func (n *NanoTDFDecryptHandler) Decrypt(ctx context.Context, result []kaoResult) (int, error) {
	return decryptNanoTDF(ctx, n.reader, n.writer, result, &n.header)
}

// What do we need:
// 1. Get obligations before decrypting a file
// 2. Store obligations triggered during decrypting a file

// No current way to return obligations for NanoTDF, since there is no reader.
func (s SDK) LoadNanoTDF(reader io.ReadSeeker, opts ...NanoTDFReaderOption) (*NanoTDFReader, error) {
	nanoTdfReaderConfig, err := newNanoTDFReaderConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("newNanoTDFReaderConfig failed: %w", err)
	}

	if len(nanoTdfReaderConfig.fulfillableObligationFQNs) == 0 && len(s.fulfillableObligationFQNs) > 0 {
		nanoTdfReaderConfig.fulfillableObligationFQNs = s.fulfillableObligationFQNs
	}

	if len(nanoTdfReaderConfig.kasAllowlist) == 0 && !nanoTdfReaderConfig.ignoreAllowList { //nolint:nestif // handling the case where kasAllowlist is not provided
		if s.KeyAccessServerRegistry != nil {
			platformEndpoint, err := s.PlatformConfiguration.platformEndpoint()
			if err != nil {
				return nil, fmt.Errorf("retrieving platformEndpoint failed: %w", err)
			}
			// retrieve the registered kases if not provided
			allowList, err := allowListFromKASRegistry(context.Background(), s.KeyAccessServerRegistry, platformEndpoint)
			if err != nil {
				return nil, fmt.Errorf("allowListFromKASRegistry failed: %w", err)
			}
			nanoTdfReaderConfig.kasAllowlist = allowList
		} else {
			slog.Error("no KAS allowlist provided and no KeyAccessServerRegistry available")
			return nil, errors.New("no KAS allowlist provided and no KeyAccessServerRegistry available")
		}
	}

	header, headerBuf, err := getNanoTDFHeader(reader)
	if err != nil {
		return nil, fmt.Errorf("getNanoTDFHeader: %w", err)
	}

	return &NanoTDFReader{
		reader:          reader,
		tokenSource:     s.tokenSource,
		httpClient:      s.conn.Client,
		connectOptions:  s.conn.Options,
		config:          nanoTdfReaderConfig,
		collectionStore: s.collectionStore,
		header:          header,
		headerBuf:       headerBuf,
		authV2Client:    s.AuthorizationV2,
	}, nil
}

// Do all network behavior (Rewrap request)
func (n *NanoTDFReader) Init(ctx context.Context) error {
	if n.payloadKey != nil {
		return nil
	}

	return n.getNanoRewrapKey(ctx)
}

func (n *NanoTDFReader) DecryptNanoTDF(ctx context.Context, writer io.Writer) (int, error) {
	if n.payloadKey == nil {
		err := n.getNanoRewrapKey(ctx)
		if err != nil {
			return 0, err
		}
	}

	return decryptNanoTDF(ctx, n.reader, writer, []kaoResult{{SymmetricKey: n.payloadKey}}, &n.header)
}

// ReadNanoTDF - read the nano tdf and return the decrypted data from it
func (s SDK) ReadNanoTDF(writer io.Writer, reader io.ReadSeeker, opts ...NanoTDFReaderOption) (int, error) {
	return s.ReadNanoTDFContext(context.Background(), writer, reader, opts...)
}

// ReadNanoTDFContext - allows cancelling the reader
func (s SDK) ReadNanoTDFContext(ctx context.Context, writer io.Writer, reader io.ReadSeeker, opts ...NanoTDFReaderOption) (int, error) {
	r, err := s.LoadNanoTDF(reader, opts...) //nolint:contextcheck // context not needed for loading
	if err != nil {
		return 0, fmt.Errorf("LoadNanoTDF: %w", err)
	}

	err = r.getNanoRewrapKey(ctx)
	if err != nil {
		return 0, fmt.Errorf("getNanoRewrapKey: %w", err)
	}

	return r.DecryptNanoTDF(ctx, writer)
}

/*
* Will return the required obligations for the TDF.
* If the obligations were populated from an Init() or DecryptNanoTDF() call, this function will return those.
* If obligations were not populated, this function will parse the policy from the TDF
* and call Authorization Service to get the required obligations.
*
* Note:
* For NanoTDF, obligations can only be returned on-demand for (via Authorization Service) if the
* policy mode is plaintext.
 */
func (n *NanoTDFReader) Obligations(ctx context.Context) (Obligations, error) {
	if n.requiredObligations != nil && len(n.requiredObligations.FQNs) > 0 {
		return *n.requiredObligations, nil
	}

	attributes, err := n.dataAttributes()
	if err != nil {
		return Obligations{}, errors.Join(err, errDataAttributes)
	}

	requiredObligations, err := getObligations(ctx, n.authV2Client, attributes, n.config.fulfillableObligationFQNs)
	if err != nil {
		return Obligations{}, err
	}

	n.requiredObligations = &Obligations{FQNs: requiredObligations}
	return *n.requiredObligations, nil
}

func (n *NanoTDFReader) dataAttributes() ([]string, error) {
	var policyObj PolicyObject
	switch n.header.PolicyMode {
	case NanoTDFPolicyModePlainText:
		err := json.Unmarshal(n.header.PolicyBody, &policyObj)
		if err != nil {
			return nil, fmt.Errorf("json.Unmarshal failed:%w", err)
		}
	case NanoTDFPolicyModeEncrypted, NanoTDFPolicyModeEncryptedPolicyKeyAccess, NanoTDFPolicyModeRemote:
		return nil, fmt.Errorf("cannot get attributes from policy for policy mode: %v", n.header.PolicyMode)
	default:
		return nil, fmt.Errorf("unsupported policy mode: %v", n.header.PolicyMode)
	}

	var attributes []string
	for _, attr := range policyObj.Body.DataAttributes {
		attributes = append(attributes, attr.Attribute)
	}
	return attributes, nil
}

func (n *NanoTDFReader) getNanoRewrapKey(ctx context.Context) error {
	req, err := createNanoRewrapRequest(ctx, n.config, n.header, n.headerBuf)
	if err != nil {
		return fmt.Errorf("CreateRewrapRequest: %w", err)
	}

	if n.collectionStore != nil {
		if key, found := n.collectionStore.get(n.headerBuf); found {
			n.payloadKey = key
			return nil
		}
	}

	client := newKASClient(n.httpClient, n.connectOptions, n.tokenSource, nil, n.config.fulfillableObligationFQNs)
	kasURL, err := n.header.kasURL.GetURL()
	if err != nil {
		return fmt.Errorf("nano header kasUrl: %w", err)
	}

	policyResult, err := client.nanoUnwrap(ctx, req[kasURL])
	if err != nil {
		return fmt.Errorf("rewrap failed: %w", err)
	}
	result, ok := policyResult["policy"]
	if !ok || len(result.kaoRes) != 1 {
		return errors.New("policy was not found in rewrap response")
	}
	if result.kaoRes[0].Error != nil {
		return fmt.Errorf("rewrapError: %w", result.kaoRes[0].Error)
	}

	if n.collectionStore != nil {
		n.collectionStore.store(n.headerBuf, result.kaoRes[0].SymmetricKey)
	}

	n.requiredObligations = &Obligations{FQNs: result.obligations}
	n.payloadKey = result.kaoRes[0].SymmetricKey

	return nil
}

func versionSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte(kNanoTDFMagicStringAndVersion))
	return digest.Sum(nil)
}

// createNanoTDFSymmetricKey creates the symmetric key for nanoTDF header
func createNanoTDFSymmetricKey(config NanoTDFConfig) ([]byte, error) {
	if config.kasPublicKey == nil {
		return nil, errors.New("KAS public key is required for encrypted policy mode")
	}

	ecdhKey, err := ocrypto.ConvertToECDHPrivateKey(config.keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ConvertToECDHPrivateKey failed:%w", err)
	}

	symKey, err := ocrypto.ComputeECDHKeyFromECDHKeys(config.kasPublicKey, ecdhKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ComputeECDHKeyFromEC failed:%w", err)
	}

	salt := versionSalt()
	symmetricKey, err := ocrypto.CalculateHKDF(salt, symKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}

	return symmetricKey, nil
}

func getKasInfoForNanoTDF(s *SDK, config *NanoTDFConfig) (*KASInfo, error) {
	var err error
	// * Attempt to use base key if present and ECC.
	ki, err := getNanoKasInfoFromBaseKey(s)
	if err == nil {
		err = updateConfigWithBaseKey(ki, config)
		if err == nil {
			return ki, nil
		}
	}

	slog.Debug("getNanoKasInfoFromBaseKey failed, falling back to default kas", slog.String("error", err.Error()))

	kasURL, err := config.kasURL.GetURL()
	if err != nil {
		return nil, fmt.Errorf("config.kasURL failed:%w", err)
	}
	if kasURL == "https://" || kasURL == "http://" {
		return nil, errors.New("config.kasUrl is empty")
	}
	ki, err = s.getPublicKey(context.Background(), kasURL, config.bindCfg.eccMode.String(), "")
	if err != nil {
		return nil, fmt.Errorf("getECPublicKey failed:%w", err)
	}

	// update KAS URL with kid if set
	if ki.KID != "" && !s.nanoFeatures.noKID {
		err = config.kasURL.setURLWithIdentifier(kasURL, ki.KID)
		if err != nil {
			return nil, fmt.Errorf("getECPublicKey setURLWithIdentifier failed:%w", err)
		}
	}

	return ki, nil
}

func updateConfigWithBaseKey(ki *KASInfo, config *NanoTDFConfig) error {
	ecMode, err := ocrypto.ECKeyTypeToMode(ocrypto.KeyType(ki.Algorithm))
	if err != nil {
		return fmt.Errorf("ocrypto.ECKeyTypeToMode failed: %w", err)
	}
	err = config.kasURL.setURLWithIdentifier(ki.URL, ki.KID)
	if err != nil {
		return fmt.Errorf("config.kasURL setURLWithIdentifier failed: %w", err)
	}
	config.bindCfg.eccMode = ecMode

	return nil
}

func getNanoKasInfoFromBaseKey(s *SDK) (*KASInfo, error) {
	baseKey, err := getBaseKey(context.Background(), *s)
	if err != nil {
		return nil, err
	}

	// Check if algorithm is one of the supported EC algorithms
	algorithm := baseKey.GetPublicKey().GetAlgorithm()
	if algorithm != policy.Algorithm_ALGORITHM_EC_P256 &&
		algorithm != policy.Algorithm_ALGORITHM_EC_P384 &&
		algorithm != policy.Algorithm_ALGORITHM_EC_P521 {
		return nil, fmt.Errorf("base key algorithm is not supported for nano: %s", algorithm)
	}

	alg, err := formatAlg(baseKey.GetPublicKey().GetAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("formatAlg failed: %w", err)
	}

	return &KASInfo{
		URL:       baseKey.GetKasUri(),
		PublicKey: baseKey.GetPublicKey().GetPem(),
		KID:       baseKey.GetPublicKey().GetKid(),
		Algorithm: alg,
	}, nil
}

func getNanoTDFHeader(reader io.ReadSeeker) (NanoTDFHeader, []byte, error) {
	var err error
	var headerSize uint32
	var header NanoTDFHeader
	header, headerSize, err = NewNanoTDFHeaderFromReader(reader)
	if err != nil {
		return header, []byte{}, err
	}
	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return header, []byte{}, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	headerBuf := make([]byte, headerSize)
	_, err = reader.Read(headerBuf)
	if err != nil {
		return header, []byte{}, fmt.Errorf("readSeeker.Read failed: %w", err)
	}

	return header, headerBuf, nil
}

func createNanoRewrapRequest(ctx context.Context, config *NanoTDFReaderConfig, header NanoTDFHeader, headerBuf []byte) (map[string]*kas.UnsignedRewrapRequest_WithPolicyRequest, error) {
	kasURL, err := header.kasURL.GetURL()
	if err != nil {
		return nil, err
	}

	if config.ignoreAllowList {
		slog.WarnContext(ctx, "kasAllowlist is ignored, kas url is allowed", slog.String("kas_url", kasURL))
	} else if !config.kasAllowlist.IsAllowed(kasURL) {
		return nil, fmt.Errorf("KasAllowlist: kas url %s is not allowed", kasURL)
	}

	req := &kas.UnsignedRewrapRequest_WithPolicyRequest{
		KeyAccessObjects: []*kas.UnsignedRewrapRequest_WithKeyAccessObject{
			{
				KeyAccessObjectId: "kao-0",
				KeyAccessObject:   &kas.KeyAccess{KasUrl: kasURL, Header: headerBuf},
			},
		},
		Policy: &kas.UnsignedRewrapRequest_WithPolicy{
			Id: "policy",
		},
		Algorithm: "ec:secp256r1",
	}
	return map[string]*kas.UnsignedRewrapRequest_WithPolicyRequest{kasURL: req}, nil
}

func decryptNanoTDF(ctx context.Context, reader io.ReadSeeker, writer io.Writer, result []kaoResult, header *NanoTDFHeader) (int, error) {
	var err error
	if len(result) != 1 {
		return 0, errors.New("improper result from kas")
	}

	if result[0].Error != nil {
		return 0, result[0].Error
	}
	key := result[0].SymmetricKey

	const (
		kPayloadLoadLengthBufLength = 4
	)
	payloadLengthBuf := make([]byte, kPayloadLoadLengthBufLength)
	_, err = reader.Read(payloadLengthBuf[1:])
	if err != nil {
		return 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}

	payloadLength := binary.BigEndian.Uint32(payloadLengthBuf)
	slog.DebugContext(ctx, "decrypt", slog.Uint64("payload_length", uint64(payloadLength)))

	cipherData := make([]byte, payloadLength)
	_, err = reader.Read(cipherData)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		return 0, fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	ivPadded := make([]byte, 0, ocrypto.GcmStandardNonceSize)
	noncePadding := make([]byte, kIvPadding)
	ivPadded = append(ivPadded, noncePadding...)
	iv := cipherData[:kNanoTDFIvSize]
	ivPadded = append(ivPadded, iv...)

	tagSize, err := SizeOfAuthTagForCipher(header.sigCfg.cipher)
	if err != nil {
		return 0, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
	}

	decryptedData, err := aesGcm.DecryptWithIVAndTagSize(ivPadded, cipherData[kNanoTDFIvSize:], tagSize)
	if err != nil {
		return 0, err
	}

	writeLen, err := writer.Write(decryptedData)
	if err != nil {
		return 0, err
	}

	return writeLen, nil
}
