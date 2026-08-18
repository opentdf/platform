package sdk

import "errors"

var (
	// ErrTDFNotDecryptable marks DecryptBytes/DecryptTo/DecryptFile as having
	// failed before decryption began — the input itself isn't decryptable
	// (corrupt/invalid TDF bytes, a rejected TDFReaderOption, a schema
	// validation failure). Retrying with the same input won't help. Test for
	// it with errors.Is(err, ErrTDFNotDecryptable); the underlying LoadTDF
	// error remains reachable through the same chain.
	ErrTDFNotDecryptable = errors.New("tdf: input is not decryptable")

	// ErrTDFDecryptFailed marks DecryptBytes/DecryptTo/DecryptFile as having
	// failed during decryption itself — most commonly a KAS rewrap failure
	// (the caller isn't entitled), but also writer errors or payload
	// integrity errors. Test for it with errors.Is(err, ErrTDFDecryptFailed);
	// the underlying Reader.WriteTo error remains reachable through the same
	// chain.
	ErrTDFDecryptFailed = errors.New("tdf: decrypt failed")
)
