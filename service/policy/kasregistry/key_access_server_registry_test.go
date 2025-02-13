package kasregistry

import (
	"strings"
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/stretchr/testify/require"
)

func getValidator() *protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

const (
	validSecureURI     = "https://example.net"
	validInsecureURI   = "http://local.something.com"
	validUUID          = "00000000-0000-0000-0000-000000000000"
	errMessageUUID     = "string.uuid"
	errRequiredField   = "required_fields"
	errExclusiveFields = "exclusive_fields"
	errMessageURI      = "string.uri"
	errMessageMinLen   = "string.min_len"
	errMessageRequired = "required"
)

var (
	remotePubKey = &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: validSecureURI + "/public_key",
		},
	}

	fakeCachedKey = &policy.PublicKey{
		PublicKey: &policy.PublicKey_Cached{
			Cached: &policy.KasPublicKeySet{
				Keys: []*policy.KasPublicKey{
					{
						Pem: "fake PEM",
						Kid: "fake KID",
						Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1,
					},
				},
			},
		},
	}
	fakeURI = "https://someuri.com"
	fakeID  = "6321ea85-ca04-466f-aefb-174bcdbc0612"
)

func Test_GetKeyAccessServerRequest(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.GetKeyAccessServerRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name: "Invalid KasId in Identifier (empty string)",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_KasId{
					KasId: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID, // Assuming errMessageUUID is defined elsewhere
		},
		{
			name: "Invalid KasId in Identifier (invalid UUID)",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_KasId{
					KasId: "invalid-uuid",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid KasId in Identifier",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_KasId{
					KasId: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Invalid Deprecated Id (empty string)",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_KasId{
					KasId: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID, // Assuming errMessageUUID is defined elsewhere
		},
		{
			name: "Invalid Deprecated Id (invalid UUID)",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_KasId{
					KasId: "invalid-uuid",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid Deprecated Id",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_KasId{
					KasId: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Invalid Kas Identifier URI",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_Uri{
					Uri: "invalid-uri",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Invalid Kas Identifier URI (empty string)",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_Uri{
					Uri: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Valid Kas Identifier URI",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_Uri{
					Uri: validSecureURI,
				},
			},
			expectError: false,
		},
		{
			name: "Invalid Kas Identifier Name (empty string)",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_Name{
					Name: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageMinLen,
		},
		{
			name: "Valid Kas Identifier Name",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_Name{
					Name: "kas-name",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid can't have both Deprecated Id and Identifier",
			req: &kasregistry.GetKeyAccessServerRequest{
				Identifier: &kasregistry.GetKeyAccessServerRequest_Name{
					Name: "kas-name",
				},
				Id: validUUID,
			},
			expectError:  true,
			errorMessage: errExclusiveFields,
		},
		{
			name:         "Invalid no Id or Identifier",
			req:          &kasregistry.GetKeyAccessServerRequest{},
			expectError:  true,
			errorMessage: errRequiredField,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_DeleteKeyAccessServerRequest_Succeeds(t *testing.T) {
	req := &kasregistry.DeleteKeyAccessServerRequest{}
	v := getValidator()

	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req.Id = validUUID
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_ListKeyAccessServerGrantsRequest_Fails(t *testing.T) {
	v := getValidator()
	bad := []struct {
		id       string
		uri      string
		scenario string
	}{
		{
			"",
			"missing.scheme",
			"bad URI format",
		},
		{
			"bad-id-format",
			validSecureURI,
			"invalid UUID",
		},
	}

	for _, test := range bad {
		req := &kasregistry.ListKeyAccessServerGrantsRequest{
			KasId:  test.id,
			KasUri: test.uri,
		}
		err := v.Validate(req)
		require.Error(t, err, test.scenario)
	}
}

func Test_ListKeyAccessServerGrantsRequest_Succeeds(t *testing.T) {
	v := getValidator()

	good := []struct {
		id       string
		uri      string
		scenario string
	}{
		{
			validUUID,
			validSecureURI,
			"both https URI and ID",
		},
		{
			validUUID,
			validInsecureURI,
			"both http URI and ID",
		},
		{
			validUUID,
			"",
			"no optional URI",
		},
		{
			"",
			validSecureURI,
			"no optional KAS ID",
		},
		{
			"",
			"",
			"neither optional ID nor URI",
		},
	}

	for _, test := range good {
		req := &kasregistry.ListKeyAccessServerGrantsRequest{
			KasId:  test.id,
			KasUri: test.uri,
		}
		err := v.Validate(req)
		require.NoError(t, err, test.scenario)
	}
}

func Test_CreateKeyAccessServer_Succeeds(t *testing.T) {
	good := []struct {
		uri      string
		key      *policy.PublicKey
		name     string
		scenario string
	}{
		{
			fakeURI,
			fakeCachedKey,
			"",
			"no optional KAS name & cached key",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas_name",
			"included KAS name & cached key",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name",
			"hyphenated KAS name",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name123",
			"numeric KAS name",
		},
		{
			fakeURI,
			fakeCachedKey,
			"KASnameIsMiXeDCaSe",
			"mixed case KAS name",
		},
		{
			fakeURI,
			remotePubKey,
			"",
			"no optional KAS name & remote key",
		},
	}

	for _, test := range good {
		createReq := &kasregistry.CreateKeyAccessServerRequest{
			Uri:       test.uri,
			PublicKey: test.key,
			Name:      test.name,
		}

		err := getValidator().Validate(createReq)
		require.NoError(t, err, test.scenario+" should be valid")
	}
}

func Test_CreateKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		uri      string
		key      *policy.PublicKey
		name     string
		scenario string
	}{
		{
			"",
			fakeCachedKey,
			"",
			"no uri",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas name",
			"kas name has spaces",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas_name_",
			"kas name ends in underscore",
		},
		{
			fakeURI,
			fakeCachedKey,
			"_kas_name",
			"kas name starts with underscore",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name-",
			"kas name ends in hyphen",
		},
		{
			fakeURI,
			fakeCachedKey,
			"-kas-name",
			"kas name starts with hyphen",
		},
		{
			fakeURI,
			fakeCachedKey,
			strings.Repeat("a", 254),
			"name too long",
		},
		{
			fakeURI,
			nil,
			"",
			"no public key",
		},
		{
			fakeURI,
			&policy.PublicKey{
				PublicKey: &policy.PublicKey_Remote{
					Remote: "bad format",
				},
			},
			"",
			"remote public key bad format",
		},
	}

	for _, test := range bad {
		createReq := &kasregistry.CreateKeyAccessServerRequest{
			Uri:       test.uri,
			PublicKey: test.key,
			Name:      test.name,
		}

		err := getValidator().Validate(createReq)
		require.Error(t, err, test.scenario+" should be invalid")
	}
}

func Test_UpdateKeyAccessServer_Succeeds(t *testing.T) {
	good := []struct {
		uri      string
		key      *policy.PublicKey
		name     string
		scenario string
	}{
		{
			fakeURI,
			fakeCachedKey,
			"",
			"no optional KAS name",
		},
		{
			fakeURI + "/somewhere-over-the-rainbow",
			nil,
			"",
			"only URI",
		},
		{
			"",
			fakeCachedKey,
			"",
			"only cached key",
		},
		{
			"",
			remotePubKey,
			"",
			"only remote key",
		},
		{
			"",
			nil,
			"KASnameIsMiXeDCaSe",
			"mixed case KAS name",
		},
		{
			fakeURI,
			remotePubKey,
			"new-name1",
			"everything included",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name",
			"hyphenated KAS name",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name123",
			"numeric KAS name",
		},
	}

	for _, test := range good {
		updateReq := &kasregistry.UpdateKeyAccessServerRequest{
			Id:        fakeID,
			Uri:       test.uri,
			PublicKey: test.key,
			Name:      test.name,
		}

		err := getValidator().Validate(updateReq)
		require.NoError(t, err, test.scenario+" should be valid")
	}
}

func Test_UpdateKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		id       string
		uri      string
		key      *policy.PublicKey
		name     string
		scenario string
	}{
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas name",
			"kas name has spaces",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas_name_",
			"kas name ends in underscore",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"_kas_name",
			"kas name starts with underscore",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas-name-",
			"kas name ends in hyphen",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"-kas-name",
			"kas name starts with hyphen",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			strings.Repeat("a", 254),
			"name too long",
		},
		{
			validUUID,
			fakeURI,
			&policy.PublicKey{
				PublicKey: &policy.PublicKey_Remote{
					Remote: "bad URL",
				},
			},
			"",
			"remote public key bad format",
		},
		{
			"bad-id",
			fakeURI,
			fakeCachedKey,
			"",
			"invalid id",
		},
		{
			"",
			fakeURI,
			fakeCachedKey,
			"",
			"no id",
		},
	}

	for _, test := range bad {
		updateReq := &kasregistry.UpdateKeyAccessServerRequest{
			Id:        test.id,
			Uri:       test.uri,
			PublicKey: test.key,
			Name:      test.name,
		}

		err := getValidator().Validate(updateReq)
		require.Error(t, err, "scenario should be invalid: "+test.scenario)
	}
}

func Test_UpdateKeyAccessServer_ShouldRequireID(t *testing.T) {
	updateReq := &kasregistry.UpdateKeyAccessServerRequest{
		Uri: fakeURI,
	}

	err := getValidator().Validate(updateReq)
	require.Error(t, err, "ID should be required")
}

func Test_Verify_Public_Keys(t *testing.T) {
	keys := []struct {
		key         string
		kid         string
		alg         policy.KasPublicKeyAlgEnum
		expectedErr error
		description string
		name        string
	}{
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsdI4JGPwMm4od4yxKiKZKq+d+AQQ\ntaDueUULEOdYQxL0IGmWRYGvyQ7nB+gZuB0DxbVjzZttqYIOIVYPfUV94g==\n-----END PUBLIC KEY-----\n",
			kid:         "ec256",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1,
			expectedErr: nil,
			description: "EC256 Key and Alg match",
			name:        "ec256",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsdI4JGPwMm4od4yxKiKZKq+d+AQQ\ntaDueUULEOdYQxL0IGmWRYGvyQ7nB+gZuB0DxbVjzZttqYIOIVYPfUV94g==\n-----END PUBLIC KEY-----\n",
			kid:         "ec256-bad",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1,
			expectedErr: ErrInvalidECKeyCurve,
			description: "EC256 Curve mismatch",
			name:        "bad ec256",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsdI4JGPwMm4od4yxKiKZKq+d+AQQ\ntaDueUULEOdYQxL0IGmWRYGvyQ7nB+gZuB0DxbVjzZttqYIOIVYPfUV94g==\n-----END PUBLIC KEY-----\n",
			kid:         "ec256-bad-rsa",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
			expectedErr: ErrKeyAlgMismatch,
			description: "EC256 Key Submitted as RSA",
			name:        "bad ec256 rsa",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsNHDYFiXZ4rppZ3A2f02mCSZAFR9NyHx\nz/68UxN+yuQuVKzxk8GdS7ty0+zhGRUbw2WZQk9Pehrp9eA56j1MN5c9gQiIm0PF\nHxQD4Fl2ipIA2KS3j/wIp/Ue96HzQGcX\n-----END PUBLIC KEY-----\n",
			kid:         "ec384",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1,
			expectedErr: nil,
			description: "EC384 Key and Alg match",
			name:        "ec384",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsNHDYFiXZ4rppZ3A2f02mCSZAFR9NyHx\nz/68UxN+yuQuVKzxk8GdS7ty0+zhGRUbw2WZQk9Pehrp9eA56j1MN5c9gQiIm0PF\nHxQD4Fl2ipIA2KS3j/wIp/Ue96HzQGcX\n-----END PUBLIC KEY-----\n",
			kid:         "ec384-bad",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1,
			expectedErr: ErrInvalidECKeyCurve,
			description: "EC384 Key and Alg mismatch",
			name:        "bad ec384",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsNHDYFiXZ4rppZ3A2f02mCSZAFR9NyHx\nz/68UxN+yuQuVKzxk8GdS7ty0+zhGRUbw2WZQk9Pehrp9eA56j1MN5c9gQiIm0PF\nHxQD4Fl2ipIA2KS3j/wIp/Ue96HzQGcX\n-----END PUBLIC KEY-----\n",
			kid:         "ec384-bad-rsa",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
			expectedErr: ErrKeyAlgMismatch,
			description: "EC384 Key Submitted as RSA",
			name:        "bad ec384 rsa",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAGvC9aOQpUifTgBQ+aSFm1fn2m5Fb\nOv5Xc+qrT1LcHlX2vYPVfKVsqkjb0dg6LrrKWB6+UuS44y0GDAMln1KPfnkBb2+b\n6gLkYlAUpLV7RtyzBSktmLOkViGauYlR+9gKT2B5+hiL8lsLeh7khj6XEL+CVVgS\nswYGVPb345XuIdrvhBs=\n-----END PUBLIC KEY-----\n",
			kid:         "ec",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1,
			expectedErr: nil,
			description: "EC521 Key and Alg match",
			name:        "ec521",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAGvC9aOQpUifTgBQ+aSFm1fn2m5Fb\nOv5Xc+qrT1LcHlX2vYPVfKVsqkjb0dg6LrrKWB6+UuS44y0GDAMln1KPfnkBb2+b\n6gLkYlAUpLV7RtyzBSktmLOkViGauYlR+9gKT2B5+hiL8lsLeh7khj6XEL+CVVgS\nswYGVPb345XuIdrvhBs=\n-----END PUBLIC KEY-----\n",
			kid:         "ec521-bad",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1,
			expectedErr: ErrInvalidECKeyCurve,
			description: "EC384 Curve mismatch",
			name:        "bad ec521",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAGvC9aOQpUifTgBQ+aSFm1fn2m5Fb\nOv5Xc+qrT1LcHlX2vYPVfKVsqkjb0dg6LrrKWB6+UuS44y0GDAMln1KPfnkBb2+b\n6gLkYlAUpLV7RtyzBSktmLOkViGauYlR+9gKT2B5+hiL8lsLeh7khj6XEL+CVVgS\nswYGVPb345XuIdrvhBs=\n-----END PUBLIC KEY-----\n",
			kid:         "ec521-bad-rsa",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
			expectedErr: ErrKeyAlgMismatch,
			description: "EC384 Key Submitted as RSA",
			name:        "bad ec521 rsa",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjTa+bW/aJRwmR2O6s2Op\nTobrMdMJE1NSnEF89C4+wn8R4bQ6uanY1Xd7/w3ffRoINqUDaL4PYgHuCInQB58d\nMbBE2qhDIoLdtr6XfThkLYarmjynkNRTN8d/UBu+85C7lMnjxxKxbhFEX/5Py43G\nvNontQhYaL4Ar8RfkXmXQjJIRZGJo1bvdXvhQeZtb4zckKwhS3xl3SV+gD1Tgujt\nO74cfkUZAzieED5aK4eZMCsF2kl47CdcoUvVsKWHGXRL9W/lb6HNE7Bx1Re12uma\nhX6wpexS7W1oW2LBeVdCi1Hb18W86Sud3Xw4ZDe0VlvmwUi3hwapJvpFyspI51Eb\nPwIDAQAB\n-----END PUBLIC KEY-----\n",
			kid:         "rsa2048",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
			expectedErr: nil,
			description: "RSA2048 Key and Alg match",
			name:        "rsa2048",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjTa+bW/aJRwmR2O6s2Op\nTobrMdMJE1NSnEF89C4+wn8R4bQ6uanY1Xd7/w3ffRoINqUDaL4PYgHuCInQB58d\nMbBE2qhDIoLdtr6XfThkLYarmjynkNRTN8d/UBu+85C7lMnjxxKxbhFEX/5Py43G\nvNontQhYaL4Ar8RfkXmXQjJIRZGJo1bvdXvhQeZtb4zckKwhS3xl3SV+gD1Tgujt\nO74cfkUZAzieED5aK4eZMCsF2kl47CdcoUvVsKWHGXRL9W/lb6HNE7Bx1Re12uma\nhX6wpexS7W1oW2LBeVdCi1Hb18W86Sud3Xw4ZDe0VlvmwUi3hwapJvpFyspI51Eb\nPwIDAQAB\n-----END PUBLIC KEY-----\n",
			kid:         "rsa2048-bad",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096,
			expectedErr: ErrInvalidRSAKeySize,
			description: "RSA2048 Key and Alg mismatch",
			name:        "bad rsa2048",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjTa+bW/aJRwmR2O6s2Op\nTobrMdMJE1NSnEF89C4+wn8R4bQ6uanY1Xd7/w3ffRoINqUDaL4PYgHuCInQB58d\nMbBE2qhDIoLdtr6XfThkLYarmjynkNRTN8d/UBu+85C7lMnjxxKxbhFEX/5Py43G\nvNontQhYaL4Ar8RfkXmXQjJIRZGJo1bvdXvhQeZtb4zckKwhS3xl3SV+gD1Tgujt\nO74cfkUZAzieED5aK4eZMCsF2kl47CdcoUvVsKWHGXRL9W/lb6HNE7Bx1Re12uma\nhX6wpexS7W1oW2LBeVdCi1Hb18W86Sud3Xw4ZDe0VlvmwUi3hwapJvpFyspI51Eb\nPwIDAQAB\n-----END PUBLIC KEY-----\n",
			kid:         "rsa2048-bad-ec",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1,
			expectedErr: ErrKeyAlgMismatch,
			description: "RSA2048 Key Submitted as EC",
			name:        "bad rsa2048 ec",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkrbxePKjeQccK2dVr6BO\nKpqolI6w6pi2l6M++za6e1YCvgv8vM2T4qh6OjoWawAE5K4CkOOdOhVme39GbglL\neSF1i09oHYJIj94IdNgzWj8GL9NGrZZgQ8qNcW7mtyGRz62/j//dblu4RF4/qTOe\nrDtr5lL7+IfvVvbhzoPRRDfmqnlnSpbfddSsCoeZy9FS+J/hyVueF4dTWuILb/NF\nhawqAK33Eq8Mm7dhjZ1yffbgN6lS18LIuOMb2Q2M+DSm17yqQRr5ofiIs/IzDPFJ\nw1nyRRqGdlhng6tl02xahCbdlBKkeTxvGwupGdDq5vpcPDgQdYaR+G+dBmXGejtE\nirGbZkg0T77Cj9eMOisD/WUFeKCAej8I4IbGrkWQu3IsMqCn6mHAaDc6a6+WhRDr\nOuMns+LNpzrPxQ8GIWsD6R/xTqRzCIMu1nu9wWtl2bW4mFWiUHmTqseaQNwS2tWc\nh5IrrnN49yG25+dv/X0kq452mYmxMAJHMgG+T0N9Qsdd1xKmEoMHXcE5bMBpj4u/\n5LtCHsSeYco0IUV3MzZ6bIE4hSSbIsDNH8cNmGOBt1l9G63Dkjr4mfuIN/a7Z10q\ngVpzDW2hazOqWnunyLvOUpEuGwYgLdxG2DQt6dNSVY2g7IHgGCxfL/arBs+IIMka\ny3ZIHmrZC2Ym0+77srhrCLsCAwEAAQ==\n-----END PUBLIC KEY-----\n",
			kid:         "rsa4096",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096,
			expectedErr: nil,
			description: "RSA4096 Key and Alg match",
			name:        "rsa4096",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkrbxePKjeQccK2dVr6BO\nKpqolI6w6pi2l6M++za6e1YCvgv8vM2T4qh6OjoWawAE5K4CkOOdOhVme39GbglL\neSF1i09oHYJIj94IdNgzWj8GL9NGrZZgQ8qNcW7mtyGRz62/j//dblu4RF4/qTOe\nrDtr5lL7+IfvVvbhzoPRRDfmqnlnSpbfddSsCoeZy9FS+J/hyVueF4dTWuILb/NF\nhawqAK33Eq8Mm7dhjZ1yffbgN6lS18LIuOMb2Q2M+DSm17yqQRr5ofiIs/IzDPFJ\nw1nyRRqGdlhng6tl02xahCbdlBKkeTxvGwupGdDq5vpcPDgQdYaR+G+dBmXGejtE\nirGbZkg0T77Cj9eMOisD/WUFeKCAej8I4IbGrkWQu3IsMqCn6mHAaDc6a6+WhRDr\nOuMns+LNpzrPxQ8GIWsD6R/xTqRzCIMu1nu9wWtl2bW4mFWiUHmTqseaQNwS2tWc\nh5IrrnN49yG25+dv/X0kq452mYmxMAJHMgG+T0N9Qsdd1xKmEoMHXcE5bMBpj4u/\n5LtCHsSeYco0IUV3MzZ6bIE4hSSbIsDNH8cNmGOBt1l9G63Dkjr4mfuIN/a7Z10q\ngVpzDW2hazOqWnunyLvOUpEuGwYgLdxG2DQt6dNSVY2g7IHgGCxfL/arBs+IIMka\ny3ZIHmrZC2Ym0+77srhrCLsCAwEAAQ==\n-----END PUBLIC KEY-----\n",
			kid:         "rsa4096-bad",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
			expectedErr: ErrInvalidRSAKeySize,
			description: "RSA4096 Key and Alg mismatch",
			name:        "bad rsa4096",
		},
		{
			key:         "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkrbxePKjeQccK2dVr6BO\nKpqolI6w6pi2l6M++za6e1YCvgv8vM2T4qh6OjoWawAE5K4CkOOdOhVme39GbglL\neSF1i09oHYJIj94IdNgzWj8GL9NGrZZgQ8qNcW7mtyGRz62/j//dblu4RF4/qTOe\nrDtr5lL7+IfvVvbhzoPRRDfmqnlnSpbfddSsCoeZy9FS+J/hyVueF4dTWuILb/NF\nhawqAK33Eq8Mm7dhjZ1yffbgN6lS18LIuOMb2Q2M+DSm17yqQRr5ofiIs/IzDPFJ\nw1nyRRqGdlhng6tl02xahCbdlBKkeTxvGwupGdDq5vpcPDgQdYaR+G+dBmXGejtE\nirGbZkg0T77Cj9eMOisD/WUFeKCAej8I4IbGrkWQu3IsMqCn6mHAaDc6a6+WhRDr\nOuMns+LNpzrPxQ8GIWsD6R/xTqRzCIMu1nu9wWtl2bW4mFWiUHmTqseaQNwS2tWc\nh5IrrnN49yG25+dv/X0kq452mYmxMAJHMgG+T0N9Qsdd1xKmEoMHXcE5bMBpj4u/\n5LtCHsSeYco0IUV3MzZ6bIE4hSSbIsDNH8cNmGOBt1l9G63Dkjr4mfuIN/a7Z10q\ngVpzDW2hazOqWnunyLvOUpEuGwYgLdxG2DQt6dNSVY2g7IHgGCxfL/arBs+IIMka\ny3ZIHmrZC2Ym0+77srhrCLsCAwEAAQ==\n-----END PUBLIC KEY-----\n",
			kid:         "rsa4096-bad-ec",
			alg:         policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1,
			expectedErr: ErrKeyAlgMismatch,
			description: "RSA4096 Key Submitted as EC",
			name:        "bad rsa4096 ec",
		},
	}
	for _, key := range keys {
		err := verifyKeyAlg(key.key, key.alg)
		require.Equal(t, key.expectedErr, err, key.description)
	}
}

func Test_ListPublicKey_Validation(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.ListPublicKeysRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:        "Valid ListPublicKeyRequest",
			req:         &kasregistry.ListPublicKeysRequest{},
			expectError: false,
		},
		{
			name: "Invalid KasId filter (empty string)",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasId{
					KasId: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KasId filter (invalid UUID)",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasId{
					KasId: "invalid-uuid",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid KasId filter",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasId{
					KasId: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Invalid KasUri filter (empty string)",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasUri{
					KasUri: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Invalid KasUri filter (invalid URI)",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasUri{
					KasUri: "invalid-uri",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Valid KasUri filter",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasUri{
					KasUri: fakeURI,
				},
			},
			expectError: false,
		},
		{
			name: "Invalid KasName filter (empty string)",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasName{
					KasName: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageMinLen,
		},
		{
			name: "Valid KasName filter",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasName{
					KasName: "kas-name",
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_ListPublicKeyMappings_Validation(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.ListPublicKeyMappingRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:        "Valid ListPublicKeyMappingsRequest",
			req:         &kasregistry.ListPublicKeyMappingRequest{},
			expectError: false,
		},
		{
			name: "Invalid KasId filter (empty string)",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasId{
					KasId: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KasId filter (invalid UUID)",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasId{
					KasId: "invalid-uuid",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid KasId filter",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasId{
					KasId: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Invalid KasUri filter (empty string)",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasUri{
					KasUri: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Invalid KasUri filter (invalid URI)",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasUri{
					KasUri: "invalid-uri",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Valid KasUri filter",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasUri{
					KasUri: fakeURI,
				},
			},
			expectError: false,
		},
		{
			name: "Invalid KasName filter (empty string)",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasName{
					KasName: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageMinLen,
		},
		{
			name: "Valid KasName filter",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasName{
					KasName: "kas-name",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid KeyId filter (invalid UUID)",
			req: &kasregistry.ListPublicKeyMappingRequest{
				PublicKeyId: "invalid-uuid",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid KeyId filter",
			req: &kasregistry.ListPublicKeyMappingRequest{
				PublicKeyId: validUUID,
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_GetPublicKey_Validation(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.GetPublicKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:        "Valid GetPublicKeyRequest",
			req:         &kasregistry.GetPublicKeyRequest{},
			expectError: false,
		},
		{
			name: "Invalid KeyId (empty string)",
			req: &kasregistry.GetPublicKeyRequest{
				Identifier: &kasregistry.GetPublicKeyRequest_Id{
					Id: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KeyId (invalid UUID)",
			req: &kasregistry.GetPublicKeyRequest{
				Identifier: &kasregistry.GetPublicKeyRequest_Id{
					Id: "invalid-uuid",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid KeyId",
			req: &kasregistry.GetPublicKeyRequest{
				Identifier: &kasregistry.GetPublicKeyRequest_Id{
					Id: validUUID,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_CreatePublicKey_Validation(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.CreatePublicKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid CreatePublicKeyRequest (empty)",
			req:          &kasregistry.CreatePublicKeyRequest{},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KasId (empty string)",
			req: &kasregistry.CreatePublicKeyRequest{
				KasId: "",
				Key:   &policy.KasPublicKey{},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KasId (invalid UUID)",
			req: &kasregistry.CreatePublicKeyRequest{
				KasId: "invalid-uuid",
				Key:   &policy.KasPublicKey{},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid PublicKey (empty)",
			req: &kasregistry.CreatePublicKeyRequest{
				KasId: validUUID,
				Key:   nil,
			},
			expectError:  true,
			errorMessage: errMessageRequired,
		},
		{
			name: "Valid PublicKey",
			req: &kasregistry.CreatePublicKeyRequest{
				KasId: validUUID,
				Key: &policy.KasPublicKey{
					Pem: "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAGvC9aOQpUifTgBQ+aSFm1fn2m5Fb\nOv5Xc+qrT1LcHlX2vYPVfKVsqkjb0dg6LrrKWB6+UuS44y0GDAMln1KPfnkBb2+b\n6gLkYlAUpLV7RtyzBSktmLOkViGauYlR+9gKT2B5+hiL8lsLeh7khj6XEL+CVVgS\nswYGVPb345XuIdrvhBs=\n-----END PUBLIC KEY-----\n",
					Kid: "ec384",
					Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_UpdatePublicKey_Validation(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.UpdatePublicKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid UpdatePublicKeyRequest (empty)",
			req:          &kasregistry.UpdatePublicKeyRequest{},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KeyId (empty string)",
			req: &kasregistry.UpdatePublicKeyRequest{
				Id: "",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KeyId (invalid UUID)",
			req: &kasregistry.UpdatePublicKeyRequest{
				Id: "invalid-uuid",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid KeyId",
			req: &kasregistry.UpdatePublicKeyRequest{
				Id: validUUID,
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_DeactivePublicKey_Validation(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.DeactivatePublicKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid DeactivatePublicKeyRequest (empty)",
			req:          &kasregistry.DeactivatePublicKeyRequest{},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KeyId (empty string)",
			req: &kasregistry.DeactivatePublicKeyRequest{
				Id: "",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KeyId (invalid UUID)",
			req: &kasregistry.DeactivatePublicKeyRequest{
				Id: "invalid-uuid",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid KeyId",
			req: &kasregistry.DeactivatePublicKeyRequest{
				Id: validUUID,
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func Test_ActivatePublicKey_Validation(t *testing.T) {
	testCases := []struct {
		name         string
		req          *kasregistry.ActivatePublicKeyRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid ActivatePublicKeyRequest (empty)",
			req:          &kasregistry.ActivatePublicKeyRequest{},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KeyId (empty string)",
			req: &kasregistry.ActivatePublicKeyRequest{
				Id: "",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid KeyId (invalid UUID)",
			req: &kasregistry.ActivatePublicKeyRequest{
				Id: "invalid-uuid",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid KeyId",
			req: &kasregistry.ActivatePublicKeyRequest{
				Id: validUUID,
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			if tc.expectError {
				require.Error(t, err, "Expected error for test case: %s", tc.name)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Expected error message to contain '%s' for test case: %s", tc.errorMessage, tc.name)
				}
			} else {
				require.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}
