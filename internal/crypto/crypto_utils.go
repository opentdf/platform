package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// CalculateSHA256 Calculate the SHA256 checksum of the data(32 bytes).
func CalculateSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// SHA256AsHex Calculate the SHA256 checksum of the data and return
// in hex format(64 bytes).
func SHA256AsHex(data []byte) []byte {
	hash := CalculateSHA256(data)
	dst := make([]byte, hex.EncodedLen(len(hash)))
	hex.Encode(dst, hash)
	return dst
}

// CalculateSHA256Hmac Calculate the hmac of the data with given secret.
func CalculateSHA256Hmac(secret, data []byte) []byte {
	// Create a new HMAC by defining the hash type and the secret
	hash := hmac.New(sha256.New, secret)

	// compute the HMAC
	hash.Write(data)
	dataHmac := hash.Sum(nil)

	return dataHmac
}

// SHA256HmacAsHex Calculate the hmac of the data with given secret
// and return in hex format.
func SHA256HmacAsHex(secret, data []byte) []byte {
	hmacAsBytes := CalculateSHA256Hmac(secret, data)
	dst := make([]byte, hex.EncodedLen(len(hmacAsBytes)))
	hex.Encode(dst, hmacAsBytes)
	return dst
}

// Base64Encode Encode the data to base64 encoding.
// Note: bas64 encoding causing ~33% overhead.
func Base64Encode(data []byte) []byte {
	outData := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(outData, data)
	return outData
}

// Base64Decode Decode the data using base64 decoding.
func Base64Decode(data []byte) ([]byte, error) {
	outData := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	actualLen, err := base64.StdEncoding.Decode(outData, data)
	if err != nil {
		return nil, fmt.Errorf("base64.StdEncoding.Decode failed: %w", err)
	}

	return outData[:actualLen], nil
}

// RandomBytes Generates random bytes of given size.
func RandomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		return nil, fmt.Errorf("rand.Read failed: %w", err)
	}

	return data, nil
}
