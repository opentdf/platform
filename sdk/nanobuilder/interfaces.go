package nanobuilder

import (
	"context"
	"crypto/ecdh"
	"io"

	"github.com/opentdf/platform/lib/ocrypto"
)

// ============================================================================================================
// The "View" of the Configuration required by StandardHeaderWriter
// ============================================================================================================

// HeaderConfig abstracts the SDK-specific configuration struct.
// The SDK's NanoTDFConfig must implement this interface.
type HeaderConfig interface {
	// KAS Info
	GetKASURL() (string, error)
	GetKASPublicKey() *ecdh.PublicKey

	// Cryptography Keys
	GetSignerPrivateKey() ocrypto.ECKeyPair // or appropriate key type

	// Configuration Flags/Enums
	GetBindingConfig() BindingConfig
	GetSignatureConfig() SignatureConfig
	GetPolicy() PolicyInfo
	GetPolicyMode() PolicyType

	// Collection State Management
	// Returns nil if collection is disabled
	GetCollection() CollectionHandler
}

// CollectionHandler abstracts the thread-safe state required for collections
type CollectionHandler interface {
	Lock()
	Unlock()
	GetState() (iter uint32, header []byte, key []byte)
	SetState(iter uint32, header []byte, key []byte)
}

// ResourceLocator interface abstracts the URL handling
type ResourceLocator interface {
	GetURL() (string, error)
	Write(w io.Writer) error
	Len() int
}

// ============================================================================================================
// Service Dependencies
// ============================================================================================================

type KeyResolver[C any] interface {
	Resolve(ctx context.Context, config *C) error
}

type HeaderWriter[C any] interface {
	Write(w io.Writer, config C) (symKey []byte, totalBytes uint32, iter uint32, err error)
}

type HeaderReader interface {
	Read(r io.Reader) (HeaderInfo, []byte, error)
}

// Encryptor abstracts AES-GCM or other ciphers
type Encryptor interface {
	Encrypt(payload, key, iv []byte, tagSize int) ([]byte, error)
	Decrypt(ciphertext, key []byte, tagSize int) ([]byte, error)
	GenerateIV(iteration uint32) ([]byte, error)
	GetTagSize(cipherEnum int) (int, error)
}

type KeyCache interface {
	Get(headerHash []byte) (key []byte, ok bool)
	Store(headerHash []byte, key []byte)
}

type Rewrapper interface {
	Rewrap(ctx context.Context, header []byte, kasURL string) (key []byte, obligations []string, err error)
}

type AllowListChecker interface {
	IsAllowed(url string) bool
	IsIgnored() bool
}

// ============================================================================================================
// Data Models (Moved from sdk/nanotdf_shared.go)
// ============================================================================================================

// HeaderInfo abstracts the parsed header
type HeaderInfo interface {
	GetKasURL() (string, error)
	GetCipherEnum() int
}

// Concrete Header Struct (Used by DefaultHeaderReader)
type NanoTDFHeader struct {
	KasURL              ResourceLocator
	BindCfg             BindingConfig
	SigCfg              SignatureConfig
	EphemeralKey        []byte
	PolicyMode          PolicyType
	PolicyBody          []byte
	GmacPolicyBinding   []byte
	EcdsaPolicyBindingR []byte
	EcdsaPolicyBindingS []byte
}

// --- HeaderInfo Implementation ---

func (h *NanoTDFHeader) GetKasURL() (string, error) { return h.KasURL.GetURL() }
func (h *NanoTDFHeader) GetCipherEnum() int         { return int(h.SigCfg.Cipher) }

// --- HeaderConfig Implementation ---

func (h *NanoTDFHeader) GetKASURL() (string, error) {
	return h.KasURL.GetURL()
}

// GetKASPublicKey returns nil because a parsed header contains the URL, not the resolved Public Key.
func (h *NanoTDFHeader) GetKASPublicKey() *ecdh.PublicKey {
	return nil
}

// GetSignerPrivateKey returns an empty keypair because a parsed header contains the Public Ephemeral Key, not the Private Key.
func (h *NanoTDFHeader) GetSignerPrivateKey() ocrypto.ECKeyPair {
	return ocrypto.ECKeyPair{}
}

func (h *NanoTDFHeader) GetBindingConfig() BindingConfig {
	return h.BindCfg
}

func (h *NanoTDFHeader) GetSignatureConfig() SignatureConfig {
	return h.SigCfg
}

func (h *NanoTDFHeader) GetPolicy() PolicyInfo {
	return PolicyInfo{
		Body: h.PolicyBody,
		Type: h.PolicyMode,
	}
}

func (h *NanoTDFHeader) GetPolicyMode() PolicyType {
	return h.PolicyMode
}

func (h *NanoTDFHeader) GetCollection() CollectionHandler {
	return nil
}

// --- Support Structs ---

type BindingConfig struct {
	UseEcdsaBinding bool
	EccMode         ocrypto.ECCMode
}

type SignatureConfig struct {
	HasSignature  bool
	SignatureMode ocrypto.ECCMode
	Cipher        CipherMode
}

type PolicyInfo struct {
	Body []byte // JSON serialized attributes
	Type PolicyType
}

type PolicyType uint8

const (
	PolicyModeRemote                   PolicyType = 0
	PolicyModePlainText                PolicyType = 1
	PolicyModeEncrypted                PolicyType = 2
	PolicyModeEncryptedPolicyKeyAccess PolicyType = 3
	PolicyModeDefault                  PolicyType = PolicyModeEncrypted
)

type CipherMode int

const (
	CipherModeAes256gcm64Bit  CipherMode = 0
	CipherModeAes256gcm96Bit  CipherMode = 1
	CipherModeAes256gcm104Bit CipherMode = 2
	CipherModeAes256gcm112Bit CipherMode = 3
	CipherModeAes256gcm120Bit CipherMode = 4
	CipherModeAes256gcm128Bit CipherMode = 5
)
