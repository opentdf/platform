package providers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256" // Using SHA256 for OAEP as a default
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath" // Use filepath for safer path joining

	"github.com/opentdf/platform/service/pkg/cryptoproviders"
)

const (
	FileProviderIdentifier = "file"
)

// FileProviderConfig holds configuration for the file provider
type FileProviderConfig struct {
	// BasePath is the root directory where key files are stored.
	// Key paths provided in operations will be relative to this path.
	BasePath string `json:"basePath"`
}

// FileProvider implements the CryptoProvider interface using local files for key storage.
// It assumes key references contain file paths relative to a base directory.
type FileProvider struct {
	config FileProviderConfig
}

// NewFileProvider creates a new FileProvider instance.
func NewFileProvider(config FileProviderConfig) (*FileProvider, error) {
	if config.BasePath == "" {
		return nil, fmt.Errorf("basePath cannot be empty for file provider")
	}
	// Ensure base path exists and is a directory
	info, err := os.Stat(config.BasePath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("file provider base path '%s' does not exist: %w", config.BasePath, err)
	}
	if err != nil {
		return nil, fmt.Errorf("error checking file provider base path '%s': %w", config.BasePath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("file provider base path '%s' is not a directory", config.BasePath)
	}

	return &FileProvider{config: config}, nil
}

// Identifier returns the provider's unique identifier.
func (p *FileProvider) Identifier() string {
	return FileProviderIdentifier
}

// resolvePath safely combines the base path with the relative key path.
func (p *FileProvider) resolvePath(relativePath []byte) (string, error) {
	// Clean the relative path to prevent directory traversal
	relPath := filepath.Clean(string(relativePath))
	// Ensure it's still relative after cleaning (e.g., didn't become absolute or try to go above root)
	if filepath.IsAbs(relPath) || relPath == ".." || filepath.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid relative key path: %s", string(relativePath))
	}
	absPath := filepath.Join(p.config.BasePath, relPath)
	return absPath, nil
}

// EncryptSymmetric is not implemented for general symmetric encryption by this provider.
func (p *FileProvider) EncryptSymmetric(ctx context.Context, key []byte, data []byte) ([]byte, error) {
	return nil, cryptoproviders.ErrOperationFailed{Op: "EncryptSymmetric", Err: fmt.Errorf("not implemented by file provider")}
}

// DecryptSymmetric is used for unwrapping keys (e.g., Mode 2 private key unwrapping).
// Assumes 'keyPath' points to the KEK file and 'wrappedKey' is the data to decrypt (AES-GCM).
func (p *FileProvider) DecryptSymmetric(ctx context.Context, keyPath []byte, wrappedKey []byte) ([]byte, error) {
	kekFilePath, err := p.resolvePath(keyPath)
	if err != nil {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptSymmetric (resolve KEK path)", Err: err}
	}

	kek, err := os.ReadFile(kekFilePath)
	if err != nil {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptSymmetric (read KEK)", Err: fmt.Errorf("failed to read KEK file %s: %w", kekFilePath, err)}
	}

	// Standard Go AES-GCM decryption
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptSymmetric (new cipher)", Err: fmt.Errorf("failed to create AES cipher: %w", err)}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptSymmetric (new GCM)", Err: fmt.Errorf("failed to create GCM: %w", err)}
	}

	nonceSize := gcm.NonceSize()
	if len(wrappedKey) < nonceSize {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptSymmetric (nonce size)", Err: fmt.Errorf("ciphertext too short")}
	}

	nonce, ciphertext := wrappedKey[:nonceSize], wrappedKey[nonceSize:]
	unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil) // No additional authenticated data
	if err != nil {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptSymmetric (GCM open)", Err: fmt.Errorf("failed to decrypt/unwrap key: %w", err)}
	}

	return unwrappedKey, nil
}

// EncryptAsymmetric encrypts data using a public key read from a file.
func (p *FileProvider) EncryptAsymmetric(ctx context.Context, opts cryptoproviders.EncryptOpts) (cipherText []byte, ephemeralKey []byte, err error) {
	if opts.KeyRef.IsEC() {
		return nil, nil, cryptoproviders.ErrOperationFailed{Op: "EncryptAsymmetric (EC)", Err: fmt.Errorf("EC encryption not implemented by file provider")}
	}
	if !opts.KeyRef.IsRSA() {
		return nil, nil, cryptoproviders.ErrOperationFailed{Op: "EncryptAsymmetric", Err: fmt.Errorf("unsupported algorithm: %v", opts.KeyRef.Algorithm)}
	}

	pubKeyFilePath, err := p.resolvePath(opts.KeyRef.GetRawBytes())
	if err != nil {
		return nil, nil, cryptoproviders.ErrOperationFailed{Op: "EncryptAsymmetric (resolve pubkey path)", Err: err}
	}

	pubKeyBytes, err := os.ReadFile(pubKeyFilePath)
	if err != nil {
		return nil, nil, cryptoproviders.ErrOperationFailed{Op: "EncryptAsymmetric (read public key)", Err: fmt.Errorf("failed to read public key file %s: %w", pubKeyFilePath, err)}
	}

	// Parse the public key (assuming PEM format)
	block, _ := pem.Decode(pubKeyBytes)
	if block == nil {
		return nil, nil, cryptoproviders.ErrOperationFailed{Op: "EncryptAsymmetric (decode PEM)", Err: fmt.Errorf("failed to decode PEM block containing public key")}
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS1 if PKIX fails
		rsaPub, errPkcs1 := x509.ParsePKCS1PublicKey(block.Bytes)
		if errPkcs1 != nil {
			return nil, nil, cryptoproviders.ErrOperationFailed{Op: "EncryptAsymmetric (parse public key)", Err: fmt.Errorf("failed to parse public key (tried PKIX and PKCS1): %v / %v", err, errPkcs1)}
		}
		pub = rsaPub
	}

	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, nil, cryptoproviders.ErrOperationFailed{Op: "EncryptAsymmetric (type assertion)", Err: fmt.Errorf("key is not an RSA public key")}
	}

	// Determine hash for OAEP
	oaepHash := sha256.New() // Default to SHA256
	// TODO: Allow hash selection via opts.Hash if needed, mapping crypto.Hash to hash.Hash
	// For now, hardcoding SHA256 which is common.

	encryptedBytes, err := rsa.EncryptOAEP(oaepHash, rand.Reader, rsaPubKey, opts.Data, nil) // No label
	if err != nil {
		return nil, nil, cryptoproviders.ErrOperationFailed{Op: "EncryptAsymmetric (RSA OAEP)", Err: fmt.Errorf("RSA encryption failed: %w", err)}
	}

	return encryptedBytes, nil, nil // No ephemeral key for RSA
}

// DecryptAsymmetric decrypts data using a private key read from a file.
// Handles KEK unwrapping (Mode 1) if opts.KEK is provided.
func (p *FileProvider) DecryptAsymmetric(ctx context.Context, opts cryptoproviders.DecryptOpts) ([]byte, error) {
	if opts.KeyRef.IsEC() {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (EC)", Err: fmt.Errorf("EC decryption not implemented by file provider")}
	}
	if !opts.KeyRef.IsRSA() {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric", Err: fmt.Errorf("unsupported algorithm: %v", opts.KeyRef.Algorithm)}
	}

	privKeyFilePath, err := p.resolvePath(opts.KeyRef.GetRawBytes())
	if err != nil {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (resolve privkey path)", Err: err}
	}

	privKeyBytes, err := os.ReadFile(privKeyFilePath)
	if err != nil {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (read private key)", Err: fmt.Errorf("failed to read private key file %s: %w", privKeyFilePath, err)}
	}

	// If KEK is provided, assume the private key file is encrypted/wrapped (AES-GCM).
	if len(opts.KEK) > 0 {
		// Use standard Go AES-GCM decryption to unwrap the key
		block, err := aes.NewCipher(opts.KEK)
		if err != nil {
			return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (unwrap: new cipher)", Err: fmt.Errorf("failed to create AES cipher for KEK: %w", err)}
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (unwrap: new GCM)", Err: fmt.Errorf("failed to create GCM for KEK: %w", err)}
		}
		nonceSize := gcm.NonceSize()
		if len(privKeyBytes) < nonceSize {
			return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (unwrap: nonce size)", Err: fmt.Errorf("wrapped key file content too short")}
		}
		nonce, ciphertext := privKeyBytes[:nonceSize], privKeyBytes[nonceSize:]
		unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (unwrap: GCM open)", Err: fmt.Errorf("failed to unwrap private key %s with provided KEK: %w", privKeyFilePath, err)}
		}
		privKeyBytes = unwrappedKey // Use the unwrapped key bytes going forward
	}

	// Parse the private key (assuming PEM PKCS1 or PKCS8 format)
	block, _ := pem.Decode(privKeyBytes)
	if block == nil {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (decode PEM)", Err: fmt.Errorf("failed to decode PEM block containing private key")}
	}

	var privKey *rsa.PrivateKey
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		privKey = priv
	} else {
		// Try parsing as PKCS8
		privInterface, errPkcs8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errPkcs8 != nil {
			return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (parse private key)", Err: fmt.Errorf("failed to parse private key (tried PKCS1 and PKCS8): %v / %v", err, errPkcs8)}
		}
		var ok bool
		privKey, ok = privInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (type assertion)", Err: fmt.Errorf("key parsed from PKCS8 is not an RSA private key")}
		}
	}

	// Determine hash for OAEP
	oaepHash := sha256.New() // Default to SHA256
	// TODO: Allow hash selection via opts if needed

	decryptedBytes, err := rsa.DecryptOAEP(oaepHash, rand.Reader, privKey, opts.CipherText, nil) // No label
	if err != nil {
		return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric (RSA OAEP)", Err: fmt.Errorf("RSA decryption failed: %w", err)}
	}

	return decryptedBytes, nil
}
