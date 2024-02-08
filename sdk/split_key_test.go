package sdk

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
)

func TestNewSplitKeyFromKasInfo(t *testing.T) {
	attributes := []string{
		"https://example.com/attr/Classification/value/S",
		"https://example.com/attr/Classification/value/X",
	}
	sampleMetaData := `{"displayName" : "openTDF go sdk"}`

	for _, test := range testHarnesses {
		kasInfoList := test.kasInfoList
		for index := range kasInfoList {
			kasInfoList[index].publicKey = mockKasPublicKey
		}

		sKey, err := newSplitKeyFromKasInfo(test.kasInfoList, attributes, sampleMetaData)
		if err != nil {
			t.Fatalf("tdf.newSplitKeyFromKasInfo failed: %v", err)
		}

		manifest, err := sKey.getManifest()
		if err != nil {
			t.Fatalf("tdf.splitKey.getManifest failed: %v", err)
		}

		if len(manifest.KeyAccessObjs) == 0 {
			t.Fatalf("fail: key access object missing from the manifest")
		}

		if len(manifest.KeyAccessObjs[0].EncryptedMetadata) == 0 {
			t.Fatalf("fail: meta data missing from the manifest")
		}
	}
}

type FakeUnwrapper struct {
	decrypt      crypto.AsymDecryption
	publicKeyPEM string
}

func NewFakeUnwrapper(kasPrivateKey string) (FakeUnwrapper, error) {
	block, _ := pem.Decode([]byte(kasPrivateKey))
	if block == nil {
		return FakeUnwrapper{}, errors.New("failed to parse PEM formatted private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return FakeUnwrapper{}, fmt.Errorf("x509.ParsePKCS8PrivateKey failed: %w", err)
	}
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey([]byte(kasPrivateKey))
		if err != nil {
			return FakeUnwrapper{}, fmt.Errorf("could not create fake unwrapper:%v", err)
		}
	}
	publicKey := privKey.(*rsa.PrivateKey).PublicKey
	privateBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&publicKey),
	}
	publicKeyPEM := new(strings.Builder)
	pem.Encode(publicKeyPEM, &privateBlock)
	asymDecrypt, err := crypto.NewAsymDecryption(kasPrivateKey)
	if err != nil {
		return FakeUnwrapper{}, err
	}

	return FakeUnwrapper{decrypt: asymDecrypt, publicKeyPEM: publicKeyPEM.String()}, nil
}

func (fake FakeUnwrapper) Unwrap(keyAccess KeyAccess, policy string) ([]byte, error) {
	wrappedKey, err := crypto.Base64Decode([]byte(keyAccess.WrappedKey))
	if err != nil {
		return nil, err
	}
	return fake.decrypt.Decrypt(wrappedKey)
}

func (fake FakeUnwrapper) GetKASInfo(keyAccess KeyAccess) (KASInfo, error) {
	return KASInfo{url: keyAccess.KasURL, publicKey: fake.publicKeyPEM}, nil
}

//nolint:gocognit
func TestNewSplitKeyFromManifest(t *testing.T) {
	kasPrivateKey := `-----BEGIN PRIVATE KEY-----
	MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOpiotrvV2i5h6
	clHMzDGgh3h/kMa0LoGx2OkDPd8jogycUh7pgE5GNiN2lpSmFkjxwYMXnyrwr9Ex
	yczBWJ7sRGDCDaQg5fjVUIloZ8FJVbn+sEcfQ9iX6vmI9/S++oGK79QM3V8M8cp4
	1r/T1YVmuzUHE1say/TLHGhjtGkxHDF8qFy6Z2rYFTCVJQHNqGmwNVGd0qG7gim8
	6Hawu/CMYj4jG9oITlj8rJtQOaJ6ZqemQVoNmb3j1LkyeUKzRIt+86aoBiz+T3Tf
	OEvXF6xgBj3XoiOhPYK+abFPYcrArvb6oubT8NjjQoj3j0sXWUnIIMg+e4f+XNVU
	54ZzDaLZAgMBAAECggEBALb0yK0PlMUyzHnEUwXV1y5AIoAWhsYp0qvJ1msHUVKz
	+yQ/VJz4+tQQxI8OvGbbnhNkd5LnWdYkYzsIZl7b/kBCPcQw3Zo+4XLCzhUAn1E1
	M+n42c8le1LtN6Z7mVWoZh7DPONy7t+ABvm7b7S1+1i78DPmgCeWYZGeAhIcPXG6
	5AxWIV3jigxksE6kYY9Y7DmtsZgMRrdV7SU8VtgPtT7tua8z5/U3Av0WINyKBSoM
	0yDHsAg57KnM8znx2JWLtHd0Mk5bBuu2DLbtyKNrVUAUuMPzrLGBh9S9QRd934KU
	uFAi1TEfgEachnGgSHJpzVzr2ur1tifABnQ7GNXObe0CgYEA6KowK0subdDY+uGW
	ciP2XDAMerbJJeL0/UIGPb/LUmskniio2493UBGgY2FsRyvbzJ+/UAOjIPyIxhj7
	78ZyVG8BmIzKan1RRVh//O+5yvks/eTOYjWeQ1Lcgqs3q4YAO13CEBZgKWKTUomg
	mskFJq04tndeSIyhDaW+BuWaXA8CgYEA42ABz3pql+DH7oL5C4KYBymK6wFBBOqk
	dVk+ftyJQ6PzuZKpfsu4aPIjKm71lkTgK6O9o08s3SckAdu6vLukq2TZFF+a+9OI
	lu5ww7GvfdMTgLAaFchD4bPlOInh1KVjBc1MwGXpl0ROde5pi8+WUrv9QJuoQfB/
	4rhYdbJLSpcCgYA41mqSCPm8pgp7r2RbWeGzP6Gs0L5u3PTQcbKonxQCfF4jrPcj
	O/b/vm6aGJClClfVsyi/WUQeqNKY4j2Zo7cGXV/cbnh8b0TNVgNePQn8Rcbx91Vb
	tJGHDNUFruIYqtGfrxXbbDvtoEExJqHvbjAt9J8oJB0KSCCH/vdfI/QDjQKBgQCD
	xLPH5Y24js/O7aAeh4RLQkv7fTKNAt5kE2AgbPYveOhZ9yC7Fpy8VPcENGGmwCuZ
	nr7b0ZqSX4iCezBxB92aZktXf0B2CFT0AyLehi7JoHWA8o1rai/MsVB5v45ciawl
	RKDiLy18OF2wAoawO5FGSSOvOYX9EL9MSMEbFESF6QKBgCVlZ9pPC+55rGT6AcEL
	tUpDs+/wZvcmfsFd8xC5mMUN0DatAVzVAUI95+tQaWU3Uj+bqHq0lC6Wy2VceG0D
	D+7EicjdGFN/2WVPXiYX1fblkxasZY+wChYBrPLjA9g0qOzzmXbRBph5QxDuQjJ6
	qcddVKB624a93ZBssn7OivnR
	-----END PRIVATE KEY-----`

	sampleManifest := `{
  "encryptionInformation": {
    "type": "split",
    "policy": "eyJ1dWlkIjoiMmQyY2ZjMzQtYjg5MC0xMWVlLWEyMDgtYjJjMDM2M2FlNjI5IiwiQm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W10sImRpc3NlbSI6W119fQ==",
    "keyAccess": [
      {
        "type": "kWrapped",
        "url": "http://localhost:65432/api/kas",
        "protocol": "kas",
        "wrappedKey": "DfWZxVju4DIkSAu/QRHI04pLnBciASSDRokJ5gdDjx8fnh5jNsoyGQ63ekJgGEQp0r5CZqCIUHny7RU52LyMQuTz+lNLJKsZ3n9jDim5TbfzR2ETYAaAySzEPtUsVUWxwXHeHY8YNvb3nu8DuGCO2VadascqU9lZt6KOZ6Vr5JBOH3TukvTb0twHeJoBfyT+4HKSh27sdSOSNWOSuQkcbKGbcrAuTaV50jABphlW01gCfUv1N0BF3nWF30xOzpVl3BFwS/dA8bVVIckTLP6M456cWL6YrqHefwVA1Igrks/uVolL9sN1xS+nNlVVFCgipVz3I3wwgSTjhg5QD8YUcg==",
        "policyBinding": "MDczYTJiYjE0MmZiODIxNTA3MjI2ZDBiYmNhMTM0ZmQyNDQ0YzJkODAwNmRjMjMxYjY2OWVhNTZlNzYyNTY1Nw==",
        "encryptedMetadata": ""
      },
      {
        "type": "kWrapped",
        "url": "http://localhost:65432/api/kas",
        "protocol": "kas",
        "wrappedKey": "rz13UFBazveewf7gHzEZZeg6Y5hjcVaz05W4VTlqVBxcNvJGajcXFIaeVCUgMf1++LOyqlqy6lIT+QpSG4pksXBCr7DeBrzvrXd4PUPlzFVDdZFbV22AZviSNQWe9IJyiZLt8L6RaHZcUfK2Gy2rUvXVr8o70xSjOvNAzp4nGJZPTSfbgSTo0aFPqgSvk+SmWNZl6eA98woCYO/SnSkHDWzuz7eSKcooiWoZD/XV71SpY+vHZaNwToEH4lhOxBTzNvPCX8cxi/2a6bygw4ma/bpepwwERS3SLg0cqDdQhQ95j34Y2aVzx3tSUntr33X0DHLimp1RKOTFdiPiAAnfuQ==",
        "policyBinding": "MWQ3NmEwNjk2NWU5ZDZiNDQzM2U2ZTQ3MTU0NTEyYTQ0NjYwZGFiZDkyYjYzMTI3ZDUzMjE5NDJmMDg4YTNhOQ==",
        "encryptedMetadata": ""
      }
    ],
    "method": {
      "algorithm": "AES-256-GCM",
      "iv": "",
      "isStreamable": true
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "MWI0NWNmMzJkMDliOWI5YjJmNDk1YTk0NzhjMmJjMzMyODFhM2U5YjgxOTE0ZWY0NDI2ZGFkODkyMDEzY2VlMg=="
      },
      "segmentHashAlg": "GMAC",
      "segmentSizeDefault": 2097152,
      "encryptedSegmentSizeDefault": 2097180,
      "segments": [
        {
          "hash": "NTZkZTg4NmE2MDhkNTU5OTU0N2RiNmRiNjNmMWExY2U=",
          "segmentSize": 1024,
          "encryptedSegmentSize": 1052
        }
      ]
    }
  },
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "mimeType": "application/octet-stream",
    "isEncrypted": true
  }
}`
	rewrapper, err := NewFakeUnwrapper(kasPrivateKey)
	if err != nil {
		t.Fatalf("error creating fake unwrapper: %v", err)
	}

	manifestObj := &Manifest{}
	err = json.Unmarshal([]byte(sampleManifest), manifestObj)
	if err != nil {
		t.Fatalf("json.Unmarshal failed:%v", err)
	}

	// mock the kas url
	for index := range manifestObj.EncryptionInformation.KeyAccessObjs {
		manifestObj.EncryptionInformation.KeyAccessObjs[index].KasURL = "http://kas" + fmt.Sprint(index) + ".example.org"
	}

	sKey, err := newSplitKeyFromManifest(rewrapper, *manifestObj)
	if err != nil {
		t.Errorf("newSplitKeyFromManifest failed: %v", err)
	}

	if len(sKey.tdfKeyAccessObjects) != 2 {
		t.Errorf("split key key access objects count don't match: expected %v, got %v", len(sKey.tdfKeyAccessObjects), 2)
	}

	expectedSplitKey := "6788741d1a659ac43693ffba933d8eaded57fad1705558fba98a89605fb56ab8"
	if hex.EncodeToString(sKey.key[:]) != expectedSplitKey {
		t.Errorf("split key is valid explected:%v, got %v", expectedSplitKey, hex.EncodeToString(sKey.key[:]))
	}
}
