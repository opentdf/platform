package tdf3

import (
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
)

func TestEncryptWithPublicKeyFailure(t *testing.T) {
	// Small size of PublicKey
	mockKey := &rsa.PublicKey{
		N: big.NewInt(123),
		E: 2048,
	}

	t.Log(mockKey.Size())

	output, err := EncryptWithPublicKey([]byte{}, mockKey)

	t.Log(output)

	if err == nil {
		t.Errorf("Expected  error, but got: %v", err)
	}
	if !errors.Is(err, ErrHsmEncrypt) {
		t.Errorf("Expected ErrHsmEncrypt, but got: %v", err)
	}
}
