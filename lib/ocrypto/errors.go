package ocrypto

import "errors"

// ErrInvalidKeyData is returned when key data is invalid (empty, nil, or wrong size)
var ErrInvalidKeyData = errors.New("invalid key data")

// ErrInvalidCiphertext is returned when ciphertext or input data is invalid (empty, wrong size, etc.)
var ErrInvalidCiphertext = errors.New("invalid ciphertext")
