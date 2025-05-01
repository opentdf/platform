package namespaces

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/stretchr/testify/require"
)

const (
	validName              = "namespace.org"
	validUUID              = "390e0058-7ae8-48f6-821c-9db07c831276"
	errMessageUUID         = "string.uuid"
	errMessageMinLen       = "string.min_len"
	errMessageURI          = "string.uri"
	errRequiredField       = "required_fields"
	errExclusiveFields     = "exclusive_fields"
	errMessageNamespaceKey = "namespace_key"
	errMessageNamespaceID  = "namespace_id"
	errMessageKeyID        = "key_id"
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func TestCreateNamespace_Valid_Succeeds(t *testing.T) {
	names := []string{
		"example.org",
		"hello.com",
		"goodbye.net",
		"spanish.mx",
		"english.uk",
		"GERMAN.de",
		"chinese.CN",
		"japanese.yen.jp",
		"numbers1234.com",
		"numbers1234andletters.com",
		"hyphens-1234.com",
	}

	for _, name := range names {
		req := &namespaces.CreateNamespaceRequest{
			Name: name,
		}

		v := getValidator()
		err := v.Validate(req)

		require.NoError(t, err)
	}
}

func TestCreateNamespace_WithMetadata_Valid_Succeeds(t *testing.T) {
	req := &namespaces.CreateNamespaceRequest{
		Name: validName,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"key1": "value1",
			},
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateNamespace_WithSpace_Fails(t *testing.T) {
	req := &namespaces.CreateNamespaceRequest{
		Name: "name with space.org",
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "[namespace_format]")
}

func TestCreateNamespace_WithInvalidCharacter_Fails(t *testing.T) {
	// test a couple of the likely most common invalid characters, but knowing the set is much larger
	names := []string{
		"hello@name.com",
		"name/123.io",
		"name?123.net",
		"name*123.org",
		"name:123.uk",
		// preceeding and trailing hyphens
		"-name.org",
		"name.org-",
	}
	for _, name := range names {
		req := &namespaces.CreateNamespaceRequest{
			Name: name,
		}

		v := getValidator()
		err := v.Validate(req)

		require.Error(t, err)
		require.Contains(t, err.Error(), "[namespace_format]")
	}
}

func TestCreateNamespace_NameMissing_Fails(t *testing.T) {
	req := &namespaces.CreateNamespaceRequest{}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "name")
	require.Contains(t, err.Error(), "[required]")
}

func Test_GetNamespaceRequest(t *testing.T) {
	testCases := []struct {
		name         string
		req          *namespaces.GetNamespaceRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name: "Invalid NamespaceId in Identifier (empty string)",
			req: &namespaces.GetNamespaceRequest{
				Identifier: &namespaces.GetNamespaceRequest_NamespaceId{
					NamespaceId: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid NamespaceId in Identifier (invalid UUID)",
			req: &namespaces.GetNamespaceRequest{
				Identifier: &namespaces.GetNamespaceRequest_NamespaceId{
					NamespaceId: "invalid-uuid",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid NamespaceId in Identifier",
			req: &namespaces.GetNamespaceRequest{
				Identifier: &namespaces.GetNamespaceRequest_NamespaceId{
					NamespaceId: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Valid Deprecated Id",
			req: &namespaces.GetNamespaceRequest{
				Id: validUUID,
			},
			expectError: false,
		},
		{
			name: "Invalid Deprecated Id (empty string)",
			req: &namespaces.GetNamespaceRequest{
				Id: "",
			},
			expectError:  true,
			errorMessage: errRequiredField,
		},
		{
			name: "Invalid Deprecated Id (invalid UUID)",
			req: &namespaces.GetNamespaceRequest{
				Id: "invalid-uuid",
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid Namespace Identifier URI",
			req: &namespaces.GetNamespaceRequest{
				Identifier: &namespaces.GetNamespaceRequest_Fqn{
					Fqn: "invalid-fqn",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Invalid Namespace Identifier URI (empty string)",
			req: &namespaces.GetNamespaceRequest{
				Identifier: &namespaces.GetNamespaceRequest_Fqn{
					Fqn: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageMinLen,
		},
		{
			name: "Invalid Namespace Identifier URI (missing scheme)",
			req: &namespaces.GetNamespaceRequest{
				Identifier: &namespaces.GetNamespaceRequest_Fqn{
					Fqn: "namespace.org",
				},
			},
			expectError:  true,
			errorMessage: errMessageURI,
		},
		{
			name: "Valid Namespace Identifier URI",
			req: &namespaces.GetNamespaceRequest{
				Identifier: &namespaces.GetNamespaceRequest_Fqn{
					Fqn: "https://namespace.org",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid can't have both Id and Identifier",
			req: &namespaces.GetNamespaceRequest{
				Id: validUUID,
				Identifier: &namespaces.GetNamespaceRequest_Fqn{
					Fqn: "https://namespace.org",
				},
			},
			expectError:  true,
			errorMessage: errExclusiveFields,
		},
		{
			name:         "Invalid no Id or Identifier",
			req:          &namespaces.GetNamespaceRequest{},
			expectError:  true,
			errorMessage: errRequiredField,
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

func Test_UpdateNamespaceRequest_Succeeds(t *testing.T) {
	req := &namespaces.UpdateNamespaceRequest{}
	v := getValidator()

	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req.Id = validUUID
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_DeactivateNamespaceRequest_Succeeds(t *testing.T) {
	req := &namespaces.DeactivateNamespaceRequest{}
	v := getValidator()

	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req.Id = validUUID
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_NamespaceKeyAccessServer_Succeeds(t *testing.T) {
	validNamespaceKas := &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       validUUID,
		KeyAccessServerId: validUUID,
	}

	err := getValidator().Validate(validNamespaceKas)
	require.NoError(t, err)
}

func Test_NamespaceKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		nsID  string
		kasID string
	}{
		{
			"",
			validUUID,
		},
		{
			validUUID,
			"",
		},
		{
			"",
			"",
		},
		{},
	}

	for _, test := range bad {
		invalidNamespaceKAS := &namespaces.NamespaceKeyAccessServer{
			NamespaceId:       test.nsID,
			KeyAccessServerId: test.kasID,
		}
		err := getValidator().Validate(invalidNamespaceKAS)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMessageUUID)
	}
}

func Test_AssignPublicKeyToNamespace(t *testing.T) {
	testCases := []struct {
		name         string
		req          *namespaces.AssignPublicKeyToNamespaceRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name:         "Invalid Namespace Key (empty)",
			req:          &namespaces.AssignPublicKeyToNamespaceRequest{},
			expectError:  true,
			errorMessage: errMessageNamespaceKey,
		},
		{
			name: "Invalid Namespace Key (empty value id)",
			req: &namespaces.AssignPublicKeyToNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					KeyId: validUUID,
				}},
			expectError:  true,
			errorMessage: errMessageNamespaceID,
		},
		{
			name: "Invalid Namespace Key (empty value id)",
			req: &namespaces.AssignPublicKeyToNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					NamespaceId: validUUID,
				}},
			expectError:  true,
			errorMessage: errMessageKeyID,
		},
		{
			name: "Valid AssignPublicKeyToNamespaceRequest",
			req: &namespaces.AssignPublicKeyToNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					NamespaceId: validUUID,
					KeyId:       validUUID,
				}},
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

func Test_RemovePublicKeyFromNamespace(t *testing.T) {
	testCases := []struct {
		name         string
		req          *namespaces.RemovePublicKeyFromNamespaceRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name:         "Invalid Namespace Key (empty)",
			req:          &namespaces.RemovePublicKeyFromNamespaceRequest{},
			expectError:  true,
			errorMessage: errMessageNamespaceKey,
		},
		{
			name: "Invalid Namespace Key (empty value id)",
			req: &namespaces.RemovePublicKeyFromNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					KeyId: validUUID,
				}},
			expectError:  true,
			errorMessage: errMessageNamespaceID,
		},
		{
			name: "Invalid Namespace Key (empty value id)",
			req: &namespaces.RemovePublicKeyFromNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					NamespaceId: validUUID,
				}},
			expectError:  true,
			errorMessage: errMessageKeyID,
		},
		{
			name: "Valid RemovePublicKeyFromNamespaceRequest",
			req: &namespaces.RemovePublicKeyFromNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					NamespaceId: validUUID,
					KeyId:       validUUID,
				}},
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
