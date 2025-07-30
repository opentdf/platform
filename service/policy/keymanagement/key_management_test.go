package keymanagement

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/stretchr/testify/require"
)

const (
	errMessageName       = "name"
	errMessageManager    = "manager"
	errMessageConfig     = "config_json"
	errMessageIdentifier = "identifier"
	errMessageUUID       = "uuid"
)

var (
	validConfig  = []byte(`{"key": "value"}`)
	invalidUUID  = "invalid-uuid"
	validUUID    = "123e4567-e89b-12d3-a456-426614174000"
	validName    = "TestConfig"
	validManager = "local"
)

func getValidator() *protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return &v
}

func Test_CreateProviderConfigRequest(t *testing.T) {
	testCases := []struct {
		name         string
		req          *keymanagement.CreateProviderConfigRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name: "Invalid Name (empty)",
			req: &keymanagement.CreateProviderConfigRequest{
				Manager:    validManager,
				ConfigJson: validConfig,
			},
			expectError:  true,
			errorMessage: errMessageName,
		},
		{
			name: "Invalid Manager (empty)",
			req: &keymanagement.CreateProviderConfigRequest{
				Name:       validName,
				ConfigJson: validConfig,
			},
			expectError:  true,
			errorMessage: errMessageManager,
		},
		{
			name: "Invalid config (empty)",
			req: &keymanagement.CreateProviderConfigRequest{
				Name:    validName,
				Manager: validManager,
			},
			expectError:  true,
			errorMessage: errMessageConfig,
		},
		{
			name: "Valid config",
			req: &keymanagement.CreateProviderConfigRequest{
				Name:       validName,
				Manager:    validManager,
				ConfigJson: validConfig,
			},
			expectError: false,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := (*v).Validate(tc.req)
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

func Test_GetProviderConfigRequest(t *testing.T) {
	testCases := []struct {
		name         string
		req          *keymanagement.GetProviderConfigRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name:         "Invalid Request (empty identifier)",
			req:          &keymanagement.GetProviderConfigRequest{},
			expectError:  true,
			errorMessage: errMessageIdentifier,
		},
		{
			name: "Invalid ConfigId (invalid UUID)",
			req: &keymanagement.GetProviderConfigRequest{
				Identifier: &keymanagement.GetProviderConfigRequest_Id{
					Id: invalidUUID,
				},
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid ConfigId (invalid UUID)",
			req: &keymanagement.GetProviderConfigRequest{
				Identifier: &keymanagement.GetProviderConfigRequest_Name{
					Name: "",
				},
			},
			expectError:  true,
			errorMessage: errMessageName,
		},
		{
			name: "Valid ConfigId",
			req: &keymanagement.GetProviderConfigRequest{
				Identifier: &keymanagement.GetProviderConfigRequest_Id{
					Id: validUUID,
				},
			},
			expectError: false,
		},
		{
			name: "Valid Name",
			req: &keymanagement.GetProviderConfigRequest{
				Identifier: &keymanagement.GetProviderConfigRequest_Name{
					Name: validName,
				},
			},
			expectError: false,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := (*v).Validate(tc.req)
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

func Test_UpdateProviderConfigRequest(t *testing.T) {
	testCases := []struct {
		name         string
		req          *keymanagement.UpdateProviderConfigRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name:         "Invalid Request (empty uuid)",
			req:          &keymanagement.UpdateProviderConfigRequest{},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid Request (invalid uuid)",
			req: &keymanagement.UpdateProviderConfigRequest{
				Id: invalidUUID,
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid config",
			req: &keymanagement.UpdateProviderConfigRequest{
				Id:         validUUID,
				ConfigJson: validConfig,
			},
			expectError: false,
		},
		{
			name: "Valid name",
			req: &keymanagement.UpdateProviderConfigRequest{
				Id:   validUUID,
				Name: validName,
			},
			expectError: false,
		},
		{
			name: "Valid manager",
			req: &keymanagement.UpdateProviderConfigRequest{
				Id:      validUUID,
				Manager: validManager,
			},
			expectError: false,
		},
		{
			name: "Valid metadata",
			req: &keymanagement.UpdateProviderConfigRequest{
				Id: validUUID,
				Metadata: &common.MetadataMutable{
					Labels: map[string]string{},
				},
				MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
			},
			expectError: false,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := (*v).Validate(tc.req)
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

func Test_DeleteProviderConfigRequest(t *testing.T) {
	testCases := []struct {
		name         string
		req          *keymanagement.DeleteProviderConfigRequest
		expectError  bool
		errorMessage string // Optional: expected error message substring
	}{
		{
			name:         "Invalid Request (empty uuid)",
			req:          &keymanagement.DeleteProviderConfigRequest{},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Invalid Request (invalid uuid)",
			req: &keymanagement.DeleteProviderConfigRequest{
				Id: invalidUUID,
			},
			expectError:  true,
			errorMessage: errMessageUUID,
		},
		{
			name: "Valid Delete request",
			req: &keymanagement.DeleteProviderConfigRequest{
				Id: validUUID,
			},
			expectError: false,
		},
	}

	v := getValidator() // Get the validator instance (assuming this is defined elsewhere)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := (*v).Validate(tc.req)
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
