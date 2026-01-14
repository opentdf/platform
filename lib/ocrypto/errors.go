package ocrypto

import "errors"

// ErrInvalidKeyData is returned when key data is invalid (empty, nil, or wrong size)
var ErrInvalidKeyData = errors.New("invalid key data")
