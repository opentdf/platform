package utils

import (
	"fmt"
	"io"
	"os"
)

func ReadBytesFromFile(filePath string, maxBytes int64) ([]byte, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file at path %s: %w", filePath, err)
	}

	// Check if the file size exceeds the limit
	if fileInfo.Size() > maxBytes {
		return nil, fmt.Errorf("file size exceeds the limit of %d bytes", maxBytes)
	}

	fileToEncrypt, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file at path %s: %w", filePath, err)
	}
	defer fileToEncrypt.Close()

	// Limit the reader to the specified maximum number of bytes
	limitedReader := io.LimitReader(fileToEncrypt, maxBytes)
	bytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read bytes from file at path %s: %w", filePath, err)
	}

	return bytes, nil
}
