package tdf3

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"log/slog"
)

const (
	ErrHsmEncrypt = Error("hsm encrypt error")
)

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	bytes, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, msg, nil)
	if err != nil {
		slog.Error("failed ot encrypt with sha1", "err", err)
		return nil, errors.Join(ErrHsmEncrypt, err)
	}
	return bytes, nil
}

type Error string

func (e Error) Error() string {
	return string(e)
}
