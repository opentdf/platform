package security

const (
	ErrCertNotFound         = Error("not found")
	ErrNoKeys               = Error("keys not found")
	ErrKeyPairInfoNotFound  = Error("key pair info not found")
	ErrKeyPairInfoMalformed = Error("key pair info malformed")
	ErrCertificateEncode    = Error("certificate encode error")
	ErrPublicKeyMarshal     = Error("public key marshal error")
	ErrHSMUnexpected        = Error("hsm unexpected")
	ErrHSMDecrypt           = Error("hsm decrypt error")
	ErrHSMNotFound          = Error("hsm unavailable")
	ErrKeyConfig            = Error("key configuration error")
	ErrUnknownHashFunction  = Error("unknown hash function")
)

type Error string

func (e Error) Error() string {
	return string(e)
}
