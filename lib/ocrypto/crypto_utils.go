package ocrypto

import "github.com/opentdf/platform/lib/ocrypto/cryptoutil"

// CalculateSHA256 Calculate the SHA256 checksum of the data(32 bytes).
func CalculateSHA256(data []byte) []byte {
	return cryptoutil.CalculateSHA256(data)
}

// SHA256AsHex Calculate the SHA256 checksum of the data and return
// in hex format(64 bytes).
func SHA256AsHex(data []byte) []byte {
	return cryptoutil.SHA256AsHex(data)
}

// CalculateSHA256Hmac Calculate the hmac of the data with given secret.
func CalculateSHA256Hmac(secret, data []byte) []byte {
	return cryptoutil.CalculateSHA256Hmac(secret, data)
}

// SHA256HmacAsHex Calculate the hmac of the data with given secret
// and return in hex format.
func SHA256HmacAsHex(secret, data []byte) []byte {
	return cryptoutil.SHA256HmacAsHex(secret, data)
}

// Base64Encode Encode the data to base64 encoding.
// Note: bas64 encoding causing ~33% overhead.
func Base64Encode(data []byte) []byte {
	return cryptoutil.Base64Encode(data)
}

// Base64Decode Decode the data using base64 decoding.
func Base64Decode(data []byte) ([]byte, error) {
	return cryptoutil.Base64Decode(data)
}

// RandomBytes Generates random bytes of given size.
func RandomBytes(size int) ([]byte, error) {
	return cryptoutil.RandomBytes(size)
}
