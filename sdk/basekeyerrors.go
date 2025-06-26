package sdk

import "errors"

var (
	ErrBaseKeyNotFound        = errors.New("base key not found in well-known configuration")
	ErrBaseKeyInvalidFormat   = errors.New("base key has invalid format")
	ErrBaseKeyEmpty           = errors.New("base key is empty or not provided")
	ErrMarshalBaseKeyFailed   = errors.New("failed to marshal base key configuration")
	ErrUnmarshalBaseKeyFailed = errors.New("failed to unmarshal base key configuration")
)
