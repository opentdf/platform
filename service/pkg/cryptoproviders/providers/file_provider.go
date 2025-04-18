package providers

import (
	"context" // Using SHA256 for OAEP as a default
	"fmt"
	"os"
	"path/filepath" // Use filepath for safer path joining

	"github.com/opentdf/platform/service/logger"
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
	config          FileProviderConfig
	defaultProvider *Default
	l               *logger.Logger
}

// NewFileProvider creates a new FileProvider instance.
func NewFileProvider(config FileProviderConfig, l *logger.Logger) (*FileProvider, error) {
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

	fp := &FileProvider{
		config:          config,
		defaultProvider: NewDefault(l),
		l:               l,
	}
	return fp, nil
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
	// Explicitly return not implemented error to align with AWS provider behavior
	return nil, cryptoproviders.ErrOperationFailed{Op: "EncryptSymmetric", Err: fmt.Errorf("not implemented by file provider")}
}

func (p *FileProvider) DecryptSymmetric(ctx context.Context, keyPath []byte, wrappedKey []byte) ([]byte, error) {
	// return unimplemented error for symmetric decryption
	return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptSymmetric", Err: fmt.Errorf("not implemented by file provider")}
}

func (p *FileProvider) UnwrapKey(ctx context.Context, pkCtx *cryptoproviders.PrivateKeyContext, kek []byte) ([]byte, error) {
	if pkCtx.File.Path == "" {
		return nil, fmt.Errorf("file path is empty in PrivateKeyContext")
	}

	absPath, err := p.resolvePath([]byte(pkCtx.File.Path))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve key file path: %w", err)
	}

	keyBytes, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	if !pkCtx.File.Encrypted {
		return keyBytes, nil // If not encrypted, return the key directly
	}

	pkCtx.WrappedKey = keyBytes

	return p.defaultProvider.UnwrapKey(ctx, pkCtx, kek)
}

// EncryptAsymmetric encrypts data using a public key read from a file.
func (p *FileProvider) EncryptAsymmetric(ctx context.Context, opts cryptoproviders.EncryptOpts) (cipherText []byte, ephemeralKey []byte, err error) {
	return nil, nil, cryptoproviders.ErrOperationFailed{Op: "EncryptAsymmetric", Err: fmt.Errorf("not implemented by file provider")}
}

// DecryptAsymmetric decrypts data using a private key read from a file.
func (p *FileProvider) DecryptAsymmetric(ctx context.Context, opts cryptoproviders.DecryptOpts) ([]byte, error) {
	return nil, cryptoproviders.ErrOperationFailed{Op: "DecryptAsymmetric", Err: fmt.Errorf("not implemented by file provider")}
}
