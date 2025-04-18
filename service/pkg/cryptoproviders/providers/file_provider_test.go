package providers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cryptoproviders"
	"github.com/stretchr/testify/suite"
)

// mockLogger is a minimal mock logger for testing purposes.
type mockLogger struct{}

func (m *mockLogger) Debug(args ...interface{})                 {}
func (m *mockLogger) Debugf(format string, args ...interface{}) {}
func (m *mockLogger) Info(args ...interface{})                  {}
func (m *mockLogger) Infof(format string, args ...interface{})  {}
func (m *mockLogger) Warn(args ...interface{})                  {}
func (m *mockLogger) Warnf(format string, args ...interface{})  {}
func (m *mockLogger) Error(args ...interface{})                 {}
func (m *mockLogger) Errorf(format string, args ...interface{}) {}
func (m *mockLogger) Fatal(args ...interface{})                 {}
func (m *mockLogger) Fatalf(format string, args ...interface{}) {}
func (m *mockLogger) Panic(args ...interface{})                 {}
func (m *mockLogger) Panicf(format string, args ...interface{}) {}
func (m *mockLogger) With(args ...interface{}) *logger.Logger   { return logger.CreateTestLogger() } // Return a real logger for With

type FileProviderSuite struct {
	suite.Suite
	tempDir string
	logger  *logger.Logger
}

// SetupSuite creates a temporary directory for the test suite.
func (s *FileProviderSuite) SetupSuite() {
	tempDir, err := os.MkdirTemp("", "file_provider_test_")
	s.Require().NoError(err, "Failed to create temporary directory for suite")
	s.tempDir = tempDir
	s.logger = logger.CreateTestLogger()
}

// TearDownSuite removes the temporary directory after the test suite finishes.
func (s *FileProviderSuite) TearDownSuite() {
	err := os.RemoveAll(s.tempDir)
	s.Require().NoError(err, "Failed to remove temporary directory for suite")
	s.tempDir = ""
	s.logger = nil
}

// TestFileProviderSuite runs the FileProviderSuite.
func TestFileProviderSuite(t *testing.T) {
	suite.Run(t, new(FileProviderSuite))
}

// --- Helper Functions (adapted for suite) ---

// generateRSAKeys generates a new RSA key pair and saves them to files in PEM format.
func (s *FileProviderSuite) generateRSAKeys(dir string, privKeyFile, pubKeyFile string) (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048) // Use 2048 for testing
	s.Require().NoError(err)
	pubKey := &privKey.PublicKey

	// Save private key (PKCS1 PEM)
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privKeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes})
	err = os.WriteFile(filepath.Join(dir, privKeyFile), privKeyPem, 0600)
	s.Require().NoError(err)

	// Save public key (PKIX PEM)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	s.Require().NoError(err)
	pubKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	err = os.WriteFile(filepath.Join(dir, pubKeyFile), pubKeyPem, 0600)
	s.Require().NoError(err)

	return privKey, pubKey
}

// wrapKey encrypts data (e.g., a private key PEM) using AES-GCM with the given KEK.
func (s *FileProviderSuite) wrapKey(kek, dataToWrap []byte) []byte {
	block, err := aes.NewCipher(kek)
	s.Require().NoError(err)
	gcm, err := cipher.NewGCM(block)
	s.Require().NoError(err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	s.Require().NoError(err)
	wrapped := gcm.Seal(nonce, nonce, dataToWrap, nil)
	return wrapped
}

// --- Test Methods ---

func (s *FileProviderSuite) TestNewFileProvider_Success() {
	config := FileProviderConfig{BasePath: s.tempDir}
	provider, err := NewFileProvider(config, s.logger)
	s.Require().NoError(err)
	s.Assert().NotNil(provider)
	s.Assert().Equal(s.tempDir, provider.config.BasePath)
}

func (s *FileProviderSuite) TestNewFileProvider_Error_BasePathEmpty() {
	config := FileProviderConfig{BasePath: ""}
	_, err := NewFileProvider(config, s.logger)
	s.Require().Error(err)
	s.Assert().Contains(err.Error(), "basePath cannot be empty")
}

func (s *FileProviderSuite) TestNewFileProvider_Error_BasePathNotExist() {
	nonExistentPath := filepath.Join(s.tempDir, "nonexistent")
	config := FileProviderConfig{BasePath: nonExistentPath}
	_, err := NewFileProvider(config, s.logger)
	s.Require().Error(err)
	s.Assert().Contains(err.Error(), "does not exist")
}

func (s *FileProviderSuite) TestNewFileProvider_Error_BasePathIsFile() {
	filePath := filepath.Join(s.tempDir, "testfile.txt")
	err := os.WriteFile(filePath, []byte("hello"), 0600)
	s.Require().NoError(err)

	config := FileProviderConfig{BasePath: filePath}
	_, err = NewFileProvider(config, s.logger)
	s.Require().Error(err)
	s.Assert().Contains(err.Error(), "is not a directory")
}

func (s *FileProviderSuite) TestIdentifier() {
	provider := FileProvider{} // Doesn't need config for Identifier()
	s.Assert().Equal(FileProviderIdentifier, provider.Identifier())
}

func (s *FileProviderSuite) TestResolvePath_Success_ValidRelativePath() {
	config := FileProviderConfig{BasePath: s.tempDir}
	provider, err := NewFileProvider(config, s.logger)
	s.Require().NoError(err)

	relPath := "keys/mykey.pem"
	expectedPath := filepath.Join(s.tempDir, "keys", "mykey.pem")
	resolvedPath, err := provider.resolvePath([]byte(relPath))
	s.Require().NoError(err)
	s.Assert().Equal(expectedPath, resolvedPath)
}

func (s *FileProviderSuite) TestResolvePath_Success_ValidRelativePath_NoSubdir() {
	config := FileProviderConfig{BasePath: s.tempDir}
	provider, err := NewFileProvider(config, s.logger)
	s.Require().NoError(err)

	relPath := "mykey.pem"
	expectedPath := filepath.Join(s.tempDir, "mykey.pem")
	resolvedPath, err := provider.resolvePath([]byte(relPath))
	s.Require().NoError(err)
	s.Assert().Equal(expectedPath, resolvedPath)
}

func (s *FileProviderSuite) TestResolvePath_Error_AbsolutePath() {
	config := FileProviderConfig{BasePath: s.tempDir}
	provider, err := NewFileProvider(config, s.logger)
	s.Require().NoError(err)

	absPath := "/etc/passwd"
	_, err = provider.resolvePath([]byte(absPath))
	s.Require().Error(err)
	s.Assert().Contains(err.Error(), "invalid relative key path")
}

func (s *FileProviderSuite) TestResolvePath_Error_PathTraversal_Up() {
	config := FileProviderConfig{BasePath: s.tempDir}
	provider, err := NewFileProvider(config, s.logger)
	s.Require().NoError(err)

	relPath := "../secrets.txt"
	_, err = provider.resolvePath([]byte(relPath))
	s.Require().Error(err)
	s.Assert().Contains(err.Error(), "invalid relative key path")
}

func (s *FileProviderSuite) TestResolvePath_Error_PathTraversal_UpDir() {
	config := FileProviderConfig{BasePath: s.tempDir}
	provider, err := NewFileProvider(config, s.logger)
	s.Require().NoError(err)

	relPath := "../../etc/passwd"
	_, err = provider.resolvePath([]byte(relPath))
	s.Require().Error(err)
	s.Assert().Contains(err.Error(), "invalid relative key path")
}

func (s *FileProviderSuite) TestResolvePath_Success_ValidRelativePath_WithBase() {
	config := FileProviderConfig{BasePath: s.tempDir}
	provider, err := NewFileProvider(config, s.logger)
	s.Require().NoError(err)

	// Even if it resolves within BasePath after Join, Clean should handle it safely
	relPath := "keys/../mykey.pem" // Resolves to mykey.pem, but uses '..'
	expectedPath := filepath.Join(s.tempDir, "mykey.pem")
	resolvedPath, err := provider.resolvePath([]byte(relPath))
	s.Require().NoError(err) // filepath.Clean handles this case safely
	s.Assert().Equal(expectedPath, resolvedPath)
}

func (s *FileProviderSuite) TestResolvePath_Success_EmptyPath() {
	config := FileProviderConfig{BasePath: s.tempDir}
	provider, err := NewFileProvider(config, s.logger)
	s.Require().NoError(err)

	// Empty path resolves to base path which is valid usage
	relPath := ""
	expectedPath := s.tempDir
	resolvedPath, err := provider.resolvePath([]byte(relPath))
	s.Require().NoError(err)
	s.Assert().Equal(expectedPath, resolvedPath)
}

func (s *FileProviderSuite) TestEncryptSymmetric_NotImplemented() {
	provider := FileProvider{} // Config doesn't matter for this check
	_, err := provider.EncryptSymmetric(context.Background(), []byte("key"), []byte("data"))
	s.Require().Error(err)
	s.Assert().ErrorAs(err, &cryptoproviders.ErrOperationFailed{})
	s.Assert().Contains(err.Error(), "not implemented by file provider")
}
