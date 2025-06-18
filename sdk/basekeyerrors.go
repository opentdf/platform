package sdk

import "errors"

var (
	errBaseKeyNotFound        = errors.New("base key not found in well-known configuration")
	errBaseKeyInvalidFormat   = errors.New("base key has invalid format")
	errBaseKeyEmpty           = errors.New("base key is empty or not provided")
	errMarshalBaseKeyFailed   = errors.New("failed to marshal base key configuration")
	errUnmarshalBaseKeyFailed = errors.New("failed to unmarshal base key configuration")
)
