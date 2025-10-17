package sdk

import (
	"errors"
	"fmt"
)

var (
	errFileTooLarge     = errors.New("tdf: can't create tdf larger than 64gb")
	errWriteFailed      = errors.New("tdf: io.writer fail to write all bytes")
	errInvalidKasInfo   = errors.New("tdf: kas information is missing")
	errKasPubKeyMissing = errors.New("tdf: kas public key is missing")

	// Exposed tamper detection errors, Catch all possible tamper errors with errors.Is(ErrTampered)
	ErrTampered                = errors.New("tamper detected")
	ErrRootSigValidation       = fmt.Errorf("[%w] tdf: failed integrity check on root signature", ErrTampered)
	ErrSegSizeMismatch         = fmt.Errorf("[%w] tdf: mismatch encrypted segment size in manifest", ErrTampered)
	ErrSegSigValidation        = fmt.Errorf("[%w] tdf: failed integrity check on segment hash", ErrTampered)
	ErrTDFPayloadReadFail      = fmt.Errorf("[%w] tdf: fail to read payload from tdf", ErrTampered)
	ErrTDFPayloadInvalidOffset = fmt.Errorf("[%w] sdk.Reader.ReadAt: negative offset", ErrTampered)
	ErrRewrapBadRequest        = fmt.Errorf("[%w] tdf: rewrap request 400", ErrTampered)
	ErrRootSignatureFailure    = fmt.Errorf("[%w] tdf: issue verifying root signature", ErrTampered)
	ErrRewrapForbidden         = errors.New("tdf: rewrap request 403")
)

// Custom error struct for Assertion errors
type ErrAssertionFailure struct { //nolint:errname // match naming of existing errors
	ID string
}

func (e ErrAssertionFailure) Error() string {
	return fmt.Errorf("[%w] tdf: issue verifying assertions, id: %s", ErrTampered, e.ID).Error()
}

func (e ErrAssertionFailure) Unwrap() error {
	return ErrTampered
}
