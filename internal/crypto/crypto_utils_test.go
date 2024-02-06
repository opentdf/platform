package crypto

import (
	"testing"
)

func Test_SHA256AsHex(t *testing.T) {
	calculatedHashInHex := SHA256AsHex([]byte(""))
	emptyStrHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if string(calculatedHashInHex) != emptyStrHash {
		t.Fatalf("calculateSHA256 failed for empty string: expected:%s actual:%s",
			emptyStrHash, string(calculatedHashInHex))
	}

	calculatedHashInHex = SHA256AsHex([]byte("Virtru"))

	// echo -n "Virtru" | openssl dgst -sha256
	strHash := "3755b34e3d57021229951c8753484654458cbdb3c6ae5ca3f0bacf5e6112cd27"
	if string(calculatedHashInHex) != strHash {
		t.Fatalf("calculateSHA256 failed for string: expected:%s actual:%s",
			strHash, string(calculatedHashInHex))
	}

	// Create 2mb buffer and fill with character 'X'
	twoMB := 2 * 1024 * 1024
	twoMbBuffer := make([]byte, twoMB)
	for index := 0; index < len(twoMbBuffer); index++ {
		twoMbBuffer[index] = 'X'
	}

	calculatedHashInHex = SHA256AsHex(twoMbBuffer)
	twoMbHash := "4689a79943566678fcb6c278d5d219848f85df420e88349ab7e20937390068b5"
	if string(calculatedHashInHex) != twoMbHash {
		t.Fatalf("calculateSHA256 failed for empty string: expected:%s actual:%s",
			twoMbHash, string(calculatedHashInHex))
	}
}

func Test_SHA256HmacAsHex(t *testing.T) {
	secret := "secret"
	simpleString := "HelloWorld"

	// $ echo -n "HelloWorld" | openssl dgst -sha256 -hmac "secret"
	expectedHmac := "2e91612bb72b29d82f32789d063de62d5897a4ee5d3b5d34459801b94397b099"

	sha256Hmac := SHA256HmacAsHex([]byte(secret), []byte(simpleString))
	if expectedHmac != string(sha256Hmac) {
		t.Fatalf("sha256HmacAsHe failed for simple string:%s expected:%s actual:%s",
			simpleString, expectedHmac, string(sha256Hmac))
	}

	// Create 2mb buffer and fill with character 'X'
	twoMB := 2 * 1024 * 1024
	twoMbBuffer := make([]byte, twoMB)
	for index := 0; index < len(twoMbBuffer); index++ {
		twoMbBuffer[index] = 'X'
	}

	//  $ more 2MBofXChar.txt | openssl dgst -sha256 -hmac "secret"
	expectedHmacForTwoMbBuffer := "347117193af6eeccf0d967cae3e105a1c53fc7c0294263356e651590984f544e"
	sha256Hmac = SHA256HmacAsHex([]byte(secret), twoMbBuffer)
	if expectedHmacForTwoMbBuffer != string(sha256Hmac) {
		t.Fatalf("sha256HmacAsHe failed for 2mb buffer expected:%s actual:%s",
			expectedHmacForTwoMbBuffer, string(sha256Hmac))
	}
}

func Test_Base64EncodeAndDecode(t *testing.T) {
	testBase64("Hello, World!", "SGVsbG8sIFdvcmxkIQ==", t)
	testBase64("", "", t)
	testBase64("f", "Zg==", t)
	testBase64("fo", "Zm8=", t)
	testBase64("foob", "Zm9vYg==", t)
	testBase64("fooba", "Zm9vYmE=", t)
	testBase64("foobar", "Zm9vYmFy", t)
}

func testBase64(in, out string, t *testing.T) {
	encoded := Base64Encode([]byte(in))
	if string(encoded) != out {
		t.Fatalf("Base64 encode failed actual:%s expected:%s", string(encoded), out)
	}

	decoded, err := Base64Decode([]byte(out))
	if err != nil {
		t.Fatal(err)
	}

	if string(decoded) != in {
		t.Fatalf("Base64 decode failed actual:%s expected:%s", string(decoded), in)
	}
}

func TestSHA256HmacAsHex(t *testing.T) {
	secret := "secret"
	simpleString := "HelloWorld"

	// echo -n "HelloWorld" | openssl dgst -binary -hmac "secret" | openssl base64
	expectedHmac := "LpFhK7crKdgvMnidBj3mLViXpO5dO100RZgBuUOXsJk="
	bas64Decoded, err := Base64Decode([]byte(expectedHmac))
	if err != nil {
		t.Fatalf("faile to decode sha256 hmac:%v", err)
	}

	sha256Hmac := CalculateSHA256Hmac([]byte(secret), []byte(simpleString))
	if string(bas64Decoded) != string(sha256Hmac) {
		t.Fatalf("CalculateSHA256Hmac failed for simple string:%s expected:%s actual:%s",
			simpleString, string(bas64Decoded), string(sha256Hmac))
	}
}
