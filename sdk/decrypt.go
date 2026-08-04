package sdk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxDecryptBytesSize caps the plaintext size DecryptBytes will buffer into
// memory. Payloads larger than this should use DecryptTo, DecryptFile (both
// stream to their destination instead of buffering), or LoadTDF directly.
// A var, not a const, so tests can override it rather than constructing a
// multi-gigabyte fixture.
var maxDecryptBytesSize int64 = 1 << 30 // 1 GiB

// DecryptBytes decrypts a TDF payload held in memory and returns the
// plaintext. A thin wrapper over [SDK.LoadTDF] + [Reader.WriteTo] for the
// common case where the ciphertext already fits comfortably in memory:
//
//	plaintext, err := sdk.DecryptBytes(ciphertext)
//
// Rejects payloads over 1 GiB up front, before buffering anything, since
// DecryptBytes holds the full plaintext in memory. For streaming, very
// large payloads, or reading manifest data (attributes, assertions)
// between load and write, call [SDK.LoadTDF] directly, or use [SDK.DecryptTo]
// / [SDK.DecryptFile], which stream to their destination instead of
// buffering.
func (s SDK) DecryptBytes(ciphertext []byte, opts ...TDFReaderOption) ([]byte, error) {
	reader, err := s.LoadTDF(bytes.NewReader(ciphertext), opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTDFNotDecryptable, err)
	}

	size, err := reader.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTDFNotDecryptable, err)
	}
	if size > maxDecryptBytesSize {
		return nil, fmt.Errorf("%w: plaintext is %d bytes, exceeds the %d byte limit for DecryptBytes; use DecryptTo, DecryptFile, or LoadTDF directly for large payloads", ErrTDFNotDecryptable, size, maxDecryptBytesSize)
	}
	if _, err = reader.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTDFNotDecryptable, err)
	}

	var buf bytes.Buffer
	buf.Grow(int(size))
	if _, err = reader.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTDFDecryptFailed, err)
	}
	return buf.Bytes(), nil
}

// DecryptTo decrypts a TDF payload held in memory and writes the plaintext
// to out. A thin wrapper over [SDK.LoadTDF] + [Reader.WriteTo] for callers
// who already have a destination writer (a file, os.Stdout, an HTTP
// response, etc.) and don't need the plaintext held in memory:
//
//	err := sdk.DecryptTo(os.Stdout, ciphertext)
func (s SDK) DecryptTo(out io.Writer, ciphertext []byte, opts ...TDFReaderOption) error {
	reader, err := s.LoadTDF(bytes.NewReader(ciphertext), opts...)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTDFNotDecryptable, err)
	}
	if _, err = reader.WriteTo(out); err != nil {
		return fmt.Errorf("%w: %w", ErrTDFDecryptFailed, err)
	}
	return nil
}

// DecryptFile decrypts the TDF at inputPath and writes the plaintext to
// outputPath. A thin wrapper over [SDK.LoadTDF] + [Reader.WriteTo] for the
// common file-to-file case; streams directly from disk rather than
// buffering the ciphertext or plaintext in memory:
//
//	err := sdk.DecryptFile("secret.tdf", "secret.txt")
//
// Plaintext is written to a temp file in outputPath's directory (created
// with mode 0600, since it holds decrypted content) and only renamed onto
// outputPath once decryption fully succeeds. A pre-existing file at
// outputPath is therefore never touched, truncated, or deleted if
// decryption fails partway — the rename is the only step that can change
// it, and that only happens on success. On any failure the temp file is
// removed; if that removal itself also fails, both errors are returned via
// [errors.Join] so callers can detect the leftover temp file with
// [errors.Is]/[errors.As] instead of it failing silently.
//
// If outputPath already exists as a file, it's moved aside to a reserved
// backup name before the rename rather than removed outright: unlike
// POSIX, Windows' rename fails rather than replaces when the destination
// exists, so an existing file has to be out of the way first. If the
// rename then fails for any other reason, the backup is restored, so a
// pre-existing outputPath is never left destroyed by a failed finalize —
// only a successful finalize discards it. An existing outputPath that's a
// directory is rejected up front (before LoadTDF runs) rather than moved
// aside or removed.
//
// inputPath and outputPath must not refer to the same file: the final
// rename would replace the input while it may still be open, which some
// platforms (notably Windows) reject or handle inconsistently. DecryptFile
// checks with [os.SameFile] and returns an error up front rather than
// relying on platform-specific rename-over-an-open-file semantics.
func (s SDK) DecryptFile(inputPath, outputPath string, opts ...TDFReaderOption) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input TDF %s: %w", inputPath, err)
	}
	defer in.Close()

	outInfo, outStatErr := os.Stat(outputPath)
	if outStatErr == nil {
		if inInfo, inStatErr := in.Stat(); inStatErr == nil && os.SameFile(inInfo, outInfo) {
			return fmt.Errorf("inputPath and outputPath must not be the same file: %s", outputPath)
		}
		if outInfo.IsDir() {
			return fmt.Errorf("outputPath %s is a directory, not a file", outputPath)
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(outputPath), ".decrypt-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputPath, err)
	}
	tmpPath := tmp.Name()

	reader, err := s.LoadTDF(in, opts...)
	if err != nil {
		loadErr := fmt.Errorf("%w: %w", ErrTDFNotDecryptable, err)
		if closeErr := tmp.Close(); closeErr != nil {
			loadErr = errors.Join(loadErr, closeErr)
		}
		return joinTempFileCleanup(loadErr, tmpPath)
	}

	_, writeErr := reader.WriteTo(tmp)
	closeErr := tmp.Close()
	switch {
	case writeErr != nil:
		decryptErr := fmt.Errorf("%w: %w", ErrTDFDecryptFailed, writeErr)
		if closeErr != nil {
			decryptErr = errors.Join(decryptErr, closeErr)
		}
		return joinTempFileCleanup(decryptErr, tmpPath)
	case closeErr != nil:
		return joinTempFileCleanup(closeErr, tmpPath)
	}

	return finalizeOutput(tmpPath, outputPath)
}

// finalizeOutput renames tmpPath onto outputPath, now that decryption has
// fully succeeded.
//
// os.Rename fails on Windows when outputPath already exists (unlike POSIX,
// which replaces it atomically), so an existing outputPath is moved aside
// to a reserved backup name first rather than removed outright: if the
// rename then fails for some other reason (a transient permission/lock
// issue, antivirus scanning, etc.), the backup is moved back into place so
// a pre-existing file is never left destroyed by a failed finalize. The
// backup is discarded once the rename succeeds. outputPath is rejected
// outright if it's an existing directory, rather than being moved aside or
// removed like a file would be.
func finalizeOutput(tmpPath, outputPath string) error {
	fi, statErr := os.Stat(outputPath)
	switch {
	case statErr != nil:
		// Nothing at outputPath to preserve; rename directly.
		if renameErr := os.Rename(tmpPath, outputPath); renameErr != nil {
			return joinTempFileCleanup(fmt.Errorf("failed to finalize output file %s: %w", outputPath, renameErr), tmpPath)
		}
		return nil
	case fi.IsDir():
		return joinTempFileCleanup(fmt.Errorf("outputPath %s is a directory, not a file", outputPath), tmpPath)
	}

	backup, err := os.CreateTemp(filepath.Dir(outputPath), ".decrypt-bak-*.tmp")
	if err != nil {
		return joinTempFileCleanup(fmt.Errorf("failed to prepare to replace existing output file %s: %w", outputPath, err), tmpPath)
	}
	backupPath := backup.Name()
	_ = backup.Close()
	// os.CreateTemp leaves backupPath occupied; free it before renaming
	// outputPath onto it, since os.Rename fails on Windows when the
	// destination already exists.
	if removeErr := os.Remove(backupPath); removeErr != nil {
		return joinTempFileCleanup(fmt.Errorf("failed to prepare to replace existing output file %s: %w", outputPath, removeErr), tmpPath)
	}

	if renameErr := os.Rename(outputPath, backupPath); renameErr != nil {
		return joinTempFileCleanup(fmt.Errorf("failed to prepare to replace existing output file %s: %w", outputPath, renameErr), tmpPath)
	}

	if renameErr := os.Rename(tmpPath, outputPath); renameErr != nil {
		finalizeErr := fmt.Errorf("failed to finalize output file %s: %w", outputPath, renameErr)
		if restoreErr := os.Rename(backupPath, outputPath); restoreErr != nil {
			return joinTempFileCleanup(errors.Join(finalizeErr, fmt.Errorf("failed to restore original output file %s from backup %s: %w", outputPath, backupPath, restoreErr)), tmpPath)
		}
		return joinTempFileCleanup(finalizeErr, tmpPath)
	}
	if removeErr := os.Remove(backupPath); removeErr != nil {
		return fmt.Errorf("output file %s finalized, but failed to remove backup %s: %w", outputPath, backupPath, removeErr)
	}
	return nil
}

// joinTempFileCleanup removes tmpPath and, if that removal itself fails,
// joins the removal error with err rather than discarding it.
func joinTempFileCleanup(err error, tmpPath string) error {
	if removeErr := os.Remove(tmpPath); removeErr != nil {
		return errors.Join(err, removeErr)
	}
	return err
}
