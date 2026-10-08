package store

import (
	"errors"
)

var (
	ErrStoredValueInvalid   = errors.New("error: invalid stored value")
	ErrEncryptedDataInvalid = errors.New("error: invalid encrypted data")

	ErrNamespaceInvalid   = errors.New("error: invalid namespace")
	ErrKeyInvalid         = errors.New("error: invalid namespace")
	ErrValueEmpty         = errors.New("error: value cannot be empty")
	ErrValueBadCharacters = errors.New("error: value contains invalid characters")

	ErrLengthExceeded = errors.New("error: length exceeded")

	ErrStoreDriverSetup = errors.New("error: store driver setup failed")
)
