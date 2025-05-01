package kasregistry

import (
	"strings"
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/stretchr/testify/require"
)

func getValidator() protovalidate.Validator {
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
	invalidSourceType  = -1
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
		uri        string
		key        *policy.PublicKey
		name       string
		scenario   string
		sourceType policy.SourceType
	}{
		{
			fakeURI,
			fakeCachedKey,
			"",
			"no optional KAS name & cached key",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas_name",
			"included KAS name & cached key",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name",
			"hyphenated KAS name",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name123",
			"numeric KAS name",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			"KASnameIsMiXeDCaSe",
			"mixed case KAS name",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			remotePubKey,
			"",
			"no optional KAS name & remote key",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			remotePubKey,
			"",
			"no optional KAS name & remote key",
			policy.SourceType_SOURCE_TYPE_INTERNAL,
		},
	}

	for _, test := range good {
		createReq := &kasregistry.CreateKeyAccessServerRequest{
			Uri:        test.uri,
			PublicKey:  test.key,
			Name:       test.name,
			SourceType: test.sourceType,
		}

		err := getValidator().Validate(createReq)
		require.NoError(t, err, test.scenario+" should be valid")
	}
}

func Test_CreateKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		uri        string
		key        *policy.PublicKey
		name       string
		scenario   string
		sourceType policy.SourceType
	}{
		{
			"",
			fakeCachedKey,
			"",
			"no uri",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas name",
			"kas name has spaces",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas_name_",
			"kas name ends in underscore",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			"_kas_name",
			"kas name starts with underscore",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name-",
			"kas name ends in hyphen",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			"-kas-name",
			"kas name starts with hyphen",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			fakeCachedKey,
			strings.Repeat("a", 254),
			"name too long",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
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
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			fakeURI,
			remotePubKey,
			"",
			"no optional KAS name & remote key",
			invalidSourceType,
		},
	}

	for _, test := range bad {
		createReq := &kasregistry.CreateKeyAccessServerRequest{
			Uri:        test.uri,
			PublicKey:  test.key,
			Name:       test.name,
			SourceType: test.sourceType,
		}

		err := getValidator().Validate(createReq)
		require.Error(t, err, test.scenario+" should be invalid")
	}
}

func Test_UpdateKeyAccessServer_Succeeds(t *testing.T) {
	good := []struct {
		uri        string
		key        *policy.PublicKey
		name       string
		scenario   string
		sourceType policy.SourceType
	}{
		{
			fakeURI,
			fakeCachedKey,
			"",
			"no optional KAS name",
			policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
		},
		{
			fakeURI + "/somewhere-over-the-rainbow",
			nil,
			"",
			"only URI",
			policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
		},
		{
			"",
			fakeCachedKey,
			"",
			"only cached key",
			policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
		},
		{
			"",
			remotePubKey,
			"",
			"only remote key",
			policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
		},
		{
			"",
			nil,
			"KASnameIsMiXeDCaSe",
			"mixed case KAS name",
			policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
		},
		{
			fakeURI,
			remotePubKey,
			"new-name1",
			"everything included",
			policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name",
			"hyphenated KAS name",
			policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name123",
			"numeric KAS name",
			policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name123",
			"numeric KAS name",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
	}

	for _, test := range good {
		updateReq := &kasregistry.UpdateKeyAccessServerRequest{
			Id:         fakeID,
			Uri:        test.uri,
			PublicKey:  test.key,
			Name:       test.name,
			SourceType: test.sourceType,
		}

		err := getValidator().Validate(updateReq)
		require.NoError(t, err, test.scenario+" should be valid")
	}
}

func Test_UpdateKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		id         string
		uri        string
		key        *policy.PublicKey
		name       string
		scenario   string
		sourceType policy.SourceType
	}{
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas name",
			"kas name has spaces",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas_name_",
			"kas name ends in underscore",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"_kas_name",
			"kas name starts with underscore",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas-name-",
			"kas name ends in hyphen",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"-kas-name",
			"kas name starts with hyphen",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			strings.Repeat("a", 254),
			"name too long",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
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
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			"bad-id",
			fakeURI,
			fakeCachedKey,
			"",
			"invalid id",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			"",
			fakeURI,
			fakeCachedKey,
			"",
			"no id",
			policy.SourceType_SOURCE_TYPE_EXTERNAL,
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas-name123",
			"numeric KAS name",
			invalidSourceType,
		},
	}

	for _, test := range bad {
		updateReq := &kasregistry.UpdateKeyAccessServerRequest{
			Id:         test.id,
			Uri:        test.uri,
			PublicKey:  test.key,
			Name:       test.name,
			SourceType: test.sourceType,
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
