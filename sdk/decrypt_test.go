package sdk

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecryptBytes_InvalidCiphertext(t *testing.T) {
	sdk := newSDK()

	plaintext, err := sdk.DecryptBytes(t.Context(), []byte("not a valid tdf"))

	require.ErrorIs(t, err, ErrTDFNotDecryptable)
	require.Nil(t, plaintext)
}

func TestDecryptTo_InvalidCiphertext(t *testing.T) {
	sdk := newSDK()
	var dest bytes.Buffer

	err := sdk.DecryptTo(t.Context(), &dest, []byte("not a valid tdf"))

	require.ErrorIs(t, err, ErrTDFNotDecryptable)
	require.Empty(t, dest.Bytes())
}

// DecryptBytes checks the plaintext size (via Seek, from the manifest's
// segment sizes) before buffering anything, so this never needs a working
// KAS to reach the size check.
func TestDecryptBytes_RejectsPayloadOverSizeLimit(t *testing.T) {
	sdk := newSDK()
	sdk.wellknownConfiguration = newMockWellKnownService(createWellKnown(nil), nil)
	plaintext := []byte("this plaintext is bigger than our lowered test limit")

	var ciphertext bytes.Buffer
	_, err := sdk.CreateTDF(&ciphertext, bytes.NewReader(plaintext), func(tdfConfig *TDFConfig) error {
		tdfConfig.kasInfoList = []KASInfo{{
			URL:       "example.com",
			PublicKey: mockRSAPublicKey1,
			Default:   true,
		}}
		return nil
	})
	require.NoError(t, err)

	original := maxDecryptBytesSize
	maxDecryptBytesSize = int64(len(plaintext)) - 1
	defer func() { maxDecryptBytesSize = original }()

	got, err := sdk.DecryptBytes(t.Context(), ciphertext.Bytes())

	require.ErrorIs(t, err, ErrTDFNotDecryptable)
	require.Nil(t, got)
}

func TestDecryptBytes_OptionErrorSurfaces(t *testing.T) {
	sdk := newSDK()
	failErr := errors.New("boom")
	failingOption := TDFReaderOption(func(*TDFReaderConfig) error {
		return failErr
	})

	plaintext, err := sdk.DecryptBytes(t.Context(), []byte("not a valid tdf"), failingOption)

	require.ErrorIs(t, err, failErr)
	require.ErrorIs(t, err, ErrTDFNotDecryptable)
	require.Nil(t, plaintext)
}

func TestDecryptTo_OptionErrorSurfaces(t *testing.T) {
	sdk := newSDK()
	failErr := errors.New("boom")
	failingOption := TDFReaderOption(func(*TDFReaderConfig) error {
		return failErr
	})
	var dest bytes.Buffer

	err := sdk.DecryptTo(t.Context(), &dest, []byte("not a valid tdf"), failingOption)

	require.ErrorIs(t, err, failErr)
	require.ErrorIs(t, err, ErrTDFNotDecryptable)
	require.Empty(t, dest.Bytes())
}

func TestDecryptFile_MissingInput(t *testing.T) {
	sdk := newSDK()
	inputPath := filepath.Join(t.TempDir(), "does-not-exist.tdf")
	outputPath := filepath.Join(t.TempDir(), "out.txt")

	err := sdk.DecryptFile(t.Context(), inputPath, outputPath)

	require.Error(t, err)
	require.ErrorContains(t, err, inputPath)
	_, statErr := os.Stat(outputPath)
	require.True(t, os.IsNotExist(statErr))
}

func TestDecryptFile_UnwritableOutput(t *testing.T) {
	sdk := newSDK()
	inputPath := filepath.Join(t.TempDir(), "in.tdf")
	require.NoError(t, os.WriteFile(inputPath, []byte("not a valid tdf"), 0o600))
	outputPath := filepath.Join(t.TempDir(), "missing-dir", "out.txt")

	err := sdk.DecryptFile(t.Context(), inputPath, outputPath)

	require.Error(t, err)
	require.ErrorContains(t, err, outputPath)
}

func TestDecryptFile_RemovesOutputOnLoadFailure(t *testing.T) {
	sdk := newSDK()
	inputPath := filepath.Join(t.TempDir(), "in.tdf")
	require.NoError(t, os.WriteFile(inputPath, []byte("not a valid tdf"), 0o600))
	outputPath := filepath.Join(t.TempDir(), "out.txt")

	err := sdk.DecryptFile(t.Context(), inputPath, outputPath)

	require.ErrorIs(t, err, ErrTDFNotDecryptable)
	_, statErr := os.Stat(outputPath)
	require.True(t, os.IsNotExist(statErr))
}

func TestDecryptFile_PreservesExistingOutputOnLoadFailure(t *testing.T) {
	sdk := newSDK()
	inputPath := filepath.Join(t.TempDir(), "in.tdf")
	require.NoError(t, os.WriteFile(inputPath, []byte("not a valid tdf"), 0o600))
	outputPath := filepath.Join(t.TempDir(), "out.txt")
	original := []byte("pre-existing content that must survive a failed decrypt")
	require.NoError(t, os.WriteFile(outputPath, original, 0o600))

	err := sdk.DecryptFile(t.Context(), inputPath, outputPath)

	require.ErrorIs(t, err, ErrTDFNotDecryptable)
	got, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	require.Equal(t, original, got)
}

func TestDecryptFile_RejectsSamePath(t *testing.T) {
	sdk := newSDK()
	path := filepath.Join(t.TempDir(), "same.tdf")
	original := []byte("must not be touched")
	require.NoError(t, os.WriteFile(path, original, 0o600))

	err := sdk.DecryptFile(t.Context(), path, path)

	require.Error(t, err)
	require.ErrorContains(t, err, path)
	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, original, got)
}

func TestDecryptFile_RejectsSameFileViaDifferentPath(t *testing.T) {
	sdk := newSDK()
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "in.tdf")
	linkedPath := filepath.Join(dir, "link.tdf")
	original := []byte("must not be touched")
	require.NoError(t, os.WriteFile(inputPath, original, 0o600))
	require.NoError(t, os.Link(inputPath, linkedPath))

	err := sdk.DecryptFile(t.Context(), inputPath, linkedPath)

	require.Error(t, err)
	got, readErr := os.ReadFile(inputPath)
	require.NoError(t, readErr)
	require.Equal(t, original, got)
}

func TestDecryptFile_RejectsDirectoryOutputPath(t *testing.T) {
	sdk := newSDK()
	inputPath := filepath.Join(t.TempDir(), "in.tdf")
	require.NoError(t, os.WriteFile(inputPath, []byte("not a valid tdf"), 0o600))
	outputPath := filepath.Join(t.TempDir(), "a-directory")
	require.NoError(t, os.Mkdir(outputPath, 0o700))

	err := sdk.DecryptFile(t.Context(), inputPath, outputPath)

	require.Error(t, err)
	require.ErrorContains(t, err, outputPath)
	info, statErr := os.Stat(outputPath)
	require.NoError(t, statErr)
	require.True(t, info.IsDir())
}

func TestDecryptFile_OptionErrorSurfaces(t *testing.T) {
	sdk := newSDK()
	inputPath := filepath.Join(t.TempDir(), "in.tdf")
	require.NoError(t, os.WriteFile(inputPath, []byte("not a valid tdf"), 0o600))
	outputPath := filepath.Join(t.TempDir(), "out.txt")
	failErr := errors.New("boom")
	failingOption := TDFReaderOption(func(*TDFReaderConfig) error {
		return failErr
	})

	err := sdk.DecryptFile(t.Context(), inputPath, outputPath, failingOption)

	require.ErrorIs(t, err, failErr)
	require.ErrorIs(t, err, ErrTDFNotDecryptable)
	_, statErr := os.Stat(outputPath)
	require.True(t, os.IsNotExist(statErr))
}

// White-box coverage for finalizeOutput's rename mechanics, independent of
// LoadTDF/decryption.
func TestFinalizeOutput_NoExistingOutput(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "out.txt")
	tmp, err := os.CreateTemp(dir, ".decrypt-*.tmp")
	require.NoError(t, err)
	tmpPath := tmp.Name()
	_, err = tmp.WriteString("plaintext")
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	require.NoError(t, finalizeOutput(tmpPath, outputPath))

	got, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	require.Equal(t, "plaintext", string(got))
	_, statErr := os.Stat(tmpPath)
	require.True(t, os.IsNotExist(statErr))
}

// Covers the previously-untested replace-existing-output path. Note this
// can't reproduce the Windows-specific bug it guards against (finalizeOutput
// renaming onto a backupPath that os.CreateTemp had already created): POSIX
// os.Rename silently replaces an existing destination, so a missing
// os.Remove(backupPath) would be invisible on Linux/macOS CI. This asserts
// the platform-independent outcome — correct content, no leftover
// temp/backup files.
func TestFinalizeOutput_ReplacesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(outputPath, []byte("stale content"), 0o600))
	tmp, err := os.CreateTemp(dir, ".decrypt-*.tmp")
	require.NoError(t, err)
	tmpPath := tmp.Name()
	_, err = tmp.WriteString("fresh plaintext")
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	require.NoError(t, finalizeOutput(tmpPath, outputPath))

	got, readErr := os.ReadFile(outputPath)
	require.NoError(t, readErr)
	require.Equal(t, "fresh plaintext", string(got))

	entries, readDirErr := os.ReadDir(dir)
	require.NoError(t, readDirErr)
	require.Len(t, entries, 1, "no leftover temp or backup files should remain: %v", entries)
	require.Equal(t, "out.txt", entries[0].Name())
}
