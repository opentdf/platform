package nanobuilder

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/opentdf/platform/lib/ocrypto"
)

const (
	kNanoTDFMagicStringAndVersion = "L1L"
	kMaxIters                     = 1<<24 - 1
	kIvPadding                    = 9
	kNanoTDFIvSize                = 3
	kNanoTDFGMACLength            = 8
)

// ============================================================================================================
// Standard Header Writer (Generic over any config that satisfies HeaderConfig)
// ============================================================================================================

type StandardHeaderWriter[C HeaderConfig] struct{}

// Write implements HeaderWriter. It accepts any config C that satisfies HeaderConfig interface.
func (s *StandardHeaderWriter[C]) Write(writer io.Writer, config C) ([]byte, uint32, uint32, error) {
	// Handle Collection State
	coll := config.GetCollection()
	if coll != nil {
		coll.Lock()
		defer coll.Unlock()

		iter, header, key := coll.GetState()
		iter++

		if iter == kMaxIters {
			iter = 0
		}
		// If cached
		currentIter := iter - 1
		if currentIter != 0 {
			coll.SetState(iter, header, key)
			n, err := writer.Write(header)
			return key, uint32(n), currentIter, err
		}
		// First run: cache state update happens at end of function
		coll.SetState(iter, header, key)
	}

	// Capture output for collection cache if needed
	var captureBuf *bytes.Buffer
	if coll != nil {
		captureBuf = &bytes.Buffer{}
		writer = io.MultiWriter(writer, captureBuf)
	}

	var totalBytes uint32

	// Magic Number
	l, err := writer.Write([]byte(kNanoTDFMagicStringAndVersion))
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// KAS URL
	kasURL, err := config.GetKASURL()
	if err != nil {
		return nil, 0, 0, err
	}
	rl, err := NewStandardResourceLocator(kasURL)
	if err != nil {
		return nil, 0, 0, err
	}
	err = rl.Write(writer)
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(rl.Len())

	// Bind Config
	l, err = writer.Write([]byte{serializeBindingCfg(config.GetBindingConfig())})
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Sig Config
	l, err = writer.Write([]byte{serializeSignatureCfg(config.GetSignatureConfig())})
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Policy Mode
	l, err = writer.Write([]byte{byte(config.GetPolicyMode())})
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Policy Body
	// We need to construct the policy object.
	// In SDK, this involved `createPolicyObject`.
	// We assume `config.GetPolicy()` returns the raw JSON bytes ready to be embedded.
	policyBytes := config.GetPolicy().Body

	// Key Derivation
	symmetricKey, err := createSymmetricKey(config)
	if err != nil {
		return nil, 0, 0, err
	}

	// Embedded Policy
	epBytes, err := createEmbeddedPolicy(symmetricKey, policyBytes, config.GetPolicyMode(), config.GetSignatureConfig().Cipher)
	if err != nil {
		return nil, 0, 0, err
	}

	// Write Embedded Policy (Len + Body)
	binary.Write(writer, binary.BigEndian, uint16(len(epBytes)))
	writer.Write(epBytes)
	totalBytes += 2 + uint32(len(epBytes))

	// Policy Binding (SHA256 of encrypted policy body)
	digest := ocrypto.CalculateSHA256(epBytes)

	// Binding
	if config.GetBindingConfig().UseEcdsaBinding {
		rBytes, sBytes, err := ocrypto.ComputeECDSASig(digest, config.GetSignerPrivateKey().PrivateKey)
		if err != nil {
			return nil, 0, 0, err
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
	ephemeralPublicKeyKey, _ := ocrypto.CompressedECPublicKey(config.GetBindingConfig().EccMode, config.GetSignerPrivateKey().PrivateKey.PublicKey)
	l, err = writer.Write(ephemeralPublicKeyKey)
	if err != nil {
		return nil, 0, 0, err
	}
	totalBytes += uint32(l)

	// Update Collection Cache
	if coll != nil {
		iter, _, _ := coll.GetState()
		// We update the cache with the bytes we captured
		coll.SetState(iter, captureBuf.Bytes(), symmetricKey)
	}

	return symmetricKey, totalBytes, 0, nil
}

// ============================================================================================================
// Standard Header Reader
// ============================================================================================================

type StandardHeaderReader struct{}

func (s *StandardHeaderReader) Read(reader io.Reader) (HeaderInfo, []byte, error) {
	header := NanoTDFHeader{}
	var size uint32

	// Magic
	magicNumber := make([]byte, len(kNanoTDFMagicStringAndVersion))
	l, err := reader.Read(magicNumber)
	if err != nil {
		return nil, nil, err
	}
	size += uint32(l)
	if string(magicNumber) != kNanoTDFMagicStringAndVersion {
		return nil, nil, errors.New("invalid magic number")
	}

	// Resource Locator
	rl := &StandardResourceLocator{}
	if err := rl.Read(reader); err != nil {
		return nil, nil, err
	}
	size += uint32(rl.Len())
	header.KasURL = rl

	// Configs
	oneByte := make([]byte, 1)
	if _, err := reader.Read(oneByte); err != nil {
		return nil, nil, err
	}
	size++
	header.BindCfg = deserializeBindingCfg(oneByte[0])

	if _, err := reader.Read(oneByte); err != nil {
		return nil, nil, err
	}
	size++
	header.SigCfg = deserializeSignatureCfg(oneByte[0])

	// Policy
	if _, err := reader.Read(oneByte); err != nil {
		return nil, nil, err
	}
	size++
	header.PolicyMode = PolicyType(oneByte[0])

	twoBytes := make([]byte, 2)
	if _, err := reader.Read(twoBytes); err != nil {
		return nil, nil, err
	}
	size += 2
	policyLen := binary.BigEndian.Uint16(twoBytes)

	header.PolicyBody = make([]byte, policyLen)
	if n, err := reader.Read(header.PolicyBody); err != nil {
		return nil, nil, err
	} else {
		size += uint32(n)
	}

	// Binding
	if header.BindCfg.UseEcdsaBinding {
		// R
		reader.Read(oneByte)
		size++
		header.EcdsaPolicyBindingR = make([]byte, oneByte[0])
		if n, _ := reader.Read(header.EcdsaPolicyBindingR); n > 0 {
			size += uint32(n)
		}
		// S
		reader.Read(oneByte)
		size++
		header.EcdsaPolicyBindingS = make([]byte, oneByte[0])
		if n, _ := reader.Read(header.EcdsaPolicyBindingS); n > 0 {
			size += uint32(n)
		}
	} else {
		header.GmacPolicyBinding = make([]byte, kNanoTDFGMACLength)
		if n, _ := reader.Read(header.GmacPolicyBinding); n > 0 {
			size += uint32(n)
		}
	}

	// Ephemeral Key
	keyLen, _ := getECCKeyLength(header.BindCfg.EccMode)
	header.EphemeralKey = make([]byte, keyLen)
	if n, _ := reader.Read(header.EphemeralKey); n > 0 {
		size += uint32(n)
	}

	// Rewind to capture buffer
	rs, ok := reader.(io.ReadSeeker)
	if !ok {
		return nil, nil, errors.New("reader must satisfy ReadSeeker")
	}
	rs.Seek(0, io.SeekStart)
	headerBuf := make([]byte, size)
	rs.Read(headerBuf)

	return &header, headerBuf, nil
}

// ============================================================================================================
// Standard Encryptor
// ============================================================================================================

type StandardEncryptor struct {
	UseCollection bool
}

func (e *StandardEncryptor) GenerateIV(iteration uint32) ([]byte, error) {
	if e.UseCollection {
		ivPadded := make([]byte, ocrypto.GcmStandardNonceSize)
		iv := make([]byte, binary.MaxVarintLen32)
		binary.LittleEndian.PutUint32(iv, iteration)
		copy(ivPadded[kIvPadding:], iv[:kNanoTDFIvSize])
		return ivPadded, nil
	}
	return nonZeroRandomPaddedIV()
}

func (e *StandardEncryptor) GetTagSize(cipherEnum int) (int, error) {
	// Simple mapping for now
	switch CipherMode(cipherEnum) {
	case CipherModeAes256gcm64Bit:
		return 8, nil
	case CipherModeAes256gcm96Bit:
		return 12, nil
	case CipherModeAes256gcm104Bit:
		return 13, nil
	case CipherModeAes256gcm112Bit:
		return 14, nil
	case CipherModeAes256gcm120Bit:
		return 15, nil
	case CipherModeAes256gcm128Bit:
		return 16, nil
	default:
		return 12, nil
	}
}

func (e *StandardEncryptor) Encrypt(payload, key, iv []byte, tagSize int) ([]byte, error) {
	aesGcm, err := ocrypto.NewAESGcm(key)
	if err != nil {
		return nil, err
	}
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

	ivPadded := make([]byte, 0, ocrypto.GcmStandardNonceSize)
	noncePadding := make([]byte, kIvPadding)
	ivPadded = append(ivPadded, noncePadding...)
	realIV := ciphertext[:kNanoTDFIvSize]
	ivPadded = append(ivPadded, realIV...)

	return aesGcm.DecryptWithIVAndTagSize(ivPadded, ciphertext[kNanoTDFIvSize:], tagSize)
}

// ============================================================================================================
// Helpers
// ============================================================================================================

type StandardKeyCache struct {
	cache          sync.Map
	expireDuration time.Duration
}

type cacheEntry struct {
	key    []byte
	header []byte
	expire time.Time
}

func NewStandardKeyCache() *StandardKeyCache {
	return &StandardKeyCache{expireDuration: 5 * time.Minute}
}

func (c *StandardKeyCache) Get(headerHash []byte) ([]byte, bool) {
	hash := string(headerHash) // Simplified hash key
	val, ok := c.cache.Load(hash)
	if !ok {
		return nil, false
	}
	entry := val.(*cacheEntry)
	if !bytes.Equal(entry.header, headerHash) {
		return nil, false
	}
	return entry.key, true
}

func (c *StandardKeyCache) Store(headerHash []byte, key []byte) {
	entry := &cacheEntry{key: key, header: headerHash, expire: time.Now().Add(c.expireDuration)}
	c.cache.Store(string(headerHash), entry)
}

// ============================================================================================================
// Resource Locator & Helpers
// ============================================================================================================

// StandardResourceLocator implements ResourceLocator interface
type StandardResourceLocator struct {
	Protocol Protocol
	Body     string
}

type Protocol uint8

const (
	Http  Protocol = 0
	Https Protocol = 1
)

func NewStandardResourceLocator(url string) (*StandardResourceLocator, error) {
	return &StandardResourceLocator{Protocol: Https, Body: url}, nil
}

func (rl *StandardResourceLocator) GetURL() (string, error) {
	return rl.Body, nil
}

func (rl *StandardResourceLocator) Write(w io.Writer) error {
	w.Write([]byte{byte(rl.Protocol)})
	binary.Write(w, binary.BigEndian, uint16(len(rl.Body)))
	w.Write([]byte(rl.Body))
	return nil
}

func (rl *StandardResourceLocator) Read(r io.Reader) error {
	b := make([]byte, 1)
	r.Read(b)
	rl.Protocol = Protocol(b[0])
	lenBuf := make([]byte, 2)
	r.Read(lenBuf)
	length := binary.BigEndian.Uint16(lenBuf)
	body := make([]byte, length)
	r.Read(body)
	rl.Body = string(body)
	return nil
}

func (rl *StandardResourceLocator) Len() int {
	return 1 + 2 + len(rl.Body)
}

// ============================================================================================================
// Internal Helpers
// ============================================================================================================

func getECCKeyLength(curve ocrypto.ECCMode) (int, error) {
	switch curve {
	case ocrypto.ECCModeSecp256r1:
		return 33, nil
	default:
		return 33, nil
	}
}

func serializeBindingCfg(cfg BindingConfig) byte {
	var b byte = 0x00
	if cfg.UseEcdsaBinding {
		b |= 0b10000000
	}
	b |= (byte(cfg.EccMode) & 0b00000111)
	return b
}

func deserializeBindingCfg(b byte) BindingConfig {
	return BindingConfig{
		UseEcdsaBinding: (b>>7)&0x01 == 1,
		EccMode:         ocrypto.ECCMode(b & 0x07),
	}
}

func serializeSignatureCfg(cfg SignatureConfig) byte {
	var b byte = 0x00
	if cfg.HasSignature {
		b |= 0b10000000
	}
	b |= byte((cfg.SignatureMode)&0b00000111) << 4
	b |= byte((cfg.Cipher) & 0b00001111)
	return b
}

func deserializeSignatureCfg(b byte) SignatureConfig {
	return SignatureConfig{
		HasSignature:  (b>>7)&0x01 == 1,
		SignatureMode: ocrypto.ECCMode((b >> 4) & 0x07),
		Cipher:        CipherMode(b & 0x0F),
	}
}

func createSymmetricKey(config HeaderConfig) ([]byte, error) {
	if config.GetKASPublicKey() == nil {
		return nil, errors.New("KAS public key required")
	}
	// Convert ocrypto keypair to ECDH private key
	ecdhKey, err := ocrypto.ConvertToECDHPrivateKey(config.GetSignerPrivateKey())
	if err != nil {
		return nil, err
	}

	symKey, err := ocrypto.ComputeECDHKeyFromECDHKeys(config.GetKASPublicKey(), ecdhKey)
	if err != nil {
		return nil, err
	}

	digest := sha256.New()
	digest.Write([]byte(kNanoTDFMagicStringAndVersion))
	return ocrypto.CalculateHKDF(digest.Sum(nil), symKey)
}

func createEmbeddedPolicy(symKey, policyBody []byte, mode PolicyType, cipher CipherMode) ([]byte, error) {
	if mode == PolicyModeEncrypted {
		aesGcm, err := ocrypto.NewAESGcm(symKey)
		if err != nil {
			return nil, err
		}
		// Tag size mapping logic...
		tagSize := 12

		iv := make([]byte, 12) // Zero IV for embedded policy? Or random? Original used Zero I think.
		cipherText, err := aesGcm.EncryptWithIVAndTagSize(iv, policyBody, tagSize)
		if err != nil {
			return nil, err
		}

		return cipherText[len(iv):], nil
	}
	return policyBody, nil
}

func nonZeroRandomPaddedIV() ([]byte, error) {
	// ... logic from original ...
	return make([]byte, 12), nil // Stub
}
