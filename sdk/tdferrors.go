package sdk

import (
	"errors"
	"fmt"
)

var (
	ErrFileTooLarge            = errors.New("tdf: can't create tdf larger than 64gb")
	ErrRootSigValidation       = errors.New("tdf: failed integrity check on root signature")
	ErrSegSizeMismatch         = errors.New("tdf: mismatch encrypted segment size in manifest")
	ErrTDFReaderFailed         = errors.New("tdf: fail to read bytes from TDFReader")
	ErrWriteFailed             = errors.New("tdf: io.writer fail to write all bytes")
	ErrSegSigValidation        = errors.New("tdf: failed integrity check on segment hash")
	ErrTDFPayloadReadFail      = errors.New("tdf: fail to read payload from tdf")
	ErrInvalidKasInfo          = errors.New("tdf: kas information is missing")
	ErrKasPubKeyMissing        = errors.New("tdf: kas public key is missing")
	ErrTDFPayloadInvalidOffset = errors.New("sdk.Reader.ReadAt: negative offset")
	ErrRewrapBadRequest        = errors.New("tdf: rewrap request 400")
	ErrRewrapForbidden         = errors.New("tdf: rewrap request 403")
	ErrRootSignatureFailure    = errors.New("tdf: issue verifying root signature")
)

// Custom error struct with a string field
type ErrAssertionFailure struct {
	ID string
}

// Implement the Error() method to satisfy the error interface
func (e ErrAssertionFailure) Error() string {
	return fmt.Sprintf("tdf: issue verifying assertions, id: %s", e.ID)
}
