package namespaces

import (
	"testing"

	"buf.build/go/protovalidate"
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
				},
			},
			expectError:  true,
			errorMessage: errMessageNamespaceID,
		},
		{
			name: "Invalid Namespace Key (empty value id)",
			req: &namespaces.AssignPublicKeyToNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					NamespaceId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyID,
		},
		{
			name: "Valid AssignPublicKeyToNamespaceRequest",
			req: &namespaces.AssignPublicKeyToNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					NamespaceId: validUUID,
					KeyId:       validUUID,
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
				},
			},
			expectError:  true,
			errorMessage: errMessageNamespaceID,
		},
		{
			name: "Invalid Namespace Key (empty value id)",
			req: &namespaces.RemovePublicKeyFromNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					NamespaceId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errMessageKeyID,
		},
		{
			name: "Valid RemovePublicKeyFromNamespaceRequest",
			req: &namespaces.RemovePublicKeyFromNamespaceRequest{
				NamespaceKey: &namespaces.NamespaceKey{
					NamespaceId: validUUID,
					KeyId:       validUUID,
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

func Test_AssignCertificateToNamespace(t *testing.T) {
	const (
		// Valid x5c certificate (base64-encoded DER)
		validX5C = "MIICjTCCAhSgAwIBAgIIdebfy8FoW6gwCgYIKoZIzj0EAwIwfDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRkwFwYDVQQKDBBvcGVudGRmLm9yZyBJbmMxDTALBgNVBAsMBFRlc3QxHjAcBgNVBAMMFW9wZW50ZGYub3JnIFRlc3QgQ0EwHhcNMjMwMTA0MTcwMDAwWhcNMzMwMTA0MTcwMDAwWjB8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xGTAXBgNVBAoMEG9wZW50ZGYub3JnIEluYzENMAsGA1UECwwEVGVzdDEeMBwGA1UEAwwVb3BlbnRkZi5vcmcgVGVzdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJxnFtjHhP+oVPXm/hj/mZzzsKfKlF0vCL0eMR0K+Pp4OqEWVe0KN6FZPDGz7zKcrmqU5TXnNJ9YI9U6d0hJDyCjUzBRMB0GA1UdDgQWBBQVFzPXe9XHOD+UGpnL8N6m7w7fYDAfBgNVHSMEGDAWgBQVFzPXe9XHOD+UGpnL8N6m7w7fYDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIFBEa8VPY9xJfMPNDGR8g7mFPHvxNKCNUZk8ooLjkVsVAiBZONcH5dDCr+fRGUnXjqWN0v+ZCVEoQr8vMrZBPf3KOQ=="
	)

	testCases := []struct {
		name         string
		req          *namespaces.AssignCertificateToNamespaceRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid - Empty Request",
			req:          &namespaces.AssignCertificateToNamespaceRequest{},
			expectError:  true,
			errorMessage: "namespace",
		},
		{
			name: "Invalid - Missing x5c",
			req: &namespaces.AssignCertificateToNamespaceRequest{
				Namespace: &common.IdFqnIdentifier{Id: validUUID},
			},
			expectError:  true,
			errorMessage: "x5c",
		},
		{
			name: "Invalid - Missing namespace ID",
			req: &namespaces.AssignCertificateToNamespaceRequest{
				X5C: validX5C,
			},
			expectError:  true,
			errorMessage: "namespace",
		},
		{
			name: "Invalid - Bad namespace UUID",
			req: &namespaces.AssignCertificateToNamespaceRequest{
				Namespace: &common.IdFqnIdentifier{Id: "not-a-uuid"},
				X5C:       validX5C,
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid - All fields present",
			req: &namespaces.AssignCertificateToNamespaceRequest{
				Namespace: &common.IdFqnIdentifier{Id: validUUID},
				X5C:       validX5C,
			},
			expectError: false,
		},
		{
			name: "Valid - With metadata",
			req: &namespaces.AssignCertificateToNamespaceRequest{
				Namespace: &common.IdFqnIdentifier{Id: validUUID},
				X5C:       validX5C,
				Metadata: &common.MetadataMutable{
					Labels: map[string]string{"source": "test"},
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

func Test_RemoveCertificateFromNamespace(t *testing.T) {
	const (
		errMessageNamespaceCert = "namespace_certificate"
		errMessageCertID        = "certificate_id"
	)

	testCases := []struct {
		name         string
		req          *namespaces.RemoveCertificateFromNamespaceRequest
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Invalid - Empty Request",
			req:          &namespaces.RemoveCertificateFromNamespaceRequest{},
			expectError:  true,
			errorMessage: errMessageNamespaceCert,
		},
		{
			name: "Invalid - Empty NamespaceCertificate",
			req: &namespaces.RemoveCertificateFromNamespaceRequest{
				NamespaceCertificate: &namespaces.NamespaceCertificate{},
			},
			expectError:  true,
			errorMessage: "namespace",
		},
		{
			name: "Invalid - Missing certificate ID",
			req: &namespaces.RemoveCertificateFromNamespaceRequest{
				NamespaceCertificate: &namespaces.NamespaceCertificate{
					Namespace: &common.IdFqnIdentifier{Id: validUUID},
				},
			},
			expectError:  true,
			errorMessage: errMessageCertID,
		},
		{
			name: "Invalid - Missing namespace ID",
			req: &namespaces.RemoveCertificateFromNamespaceRequest{
				NamespaceCertificate: &namespaces.NamespaceCertificate{
					CertificateId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: "namespace",
		},
		{
			name: "Invalid - Bad namespace UUID",
			req: &namespaces.RemoveCertificateFromNamespaceRequest{
				NamespaceCertificate: &namespaces.NamespaceCertificate{
					Namespace:     &common.IdFqnIdentifier{Id: "not-a-uuid"},
					CertificateId: validUUID,
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid - Bad certificate UUID",
			req: &namespaces.RemoveCertificateFromNamespaceRequest{
				NamespaceCertificate: &namespaces.NamespaceCertificate{
					Namespace:     &common.IdFqnIdentifier{Id: validUUID},
					CertificateId: "not-a-uuid",
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid - All fields present",
			req: &namespaces.RemoveCertificateFromNamespaceRequest{
				NamespaceCertificate: &namespaces.NamespaceCertificate{
					Namespace:     &common.IdFqnIdentifier{Id: validUUID},
					CertificateId: validUUID,
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
