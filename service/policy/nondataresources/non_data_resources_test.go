package nondataresources

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy/nondataresources"
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
	validName  = "name"
	validValue = "value"
	validUUID  = "00000000-0000-0000-0000-000000000000"
	validURI   = "https://ndr-uri"

	invalidUUID = "not-uuid"
	invalidURI  = "not-uri"

	errMsgRequired      = "required"
	errMsgOneOfRequired = "oneof [required]"
	errMsgUUID          = "string.uuid"
	errMsgURI           = "string.uri"
	errMsgNameFormat    = "ndr_name_format"
	errMsgStringPattern = "string.pattern"
)

///
/// Non Data Resource Group
///

// Create

func TestCreateNonDataResourceGroup_Valid_Succeeds(t *testing.T) {
	testCases := []struct {
		name string
		req  *nondataresources.CreateNonDataResourceGroupRequest
	}{
		{
			name: "Valid Name",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: validName,
			},
		},
		{
			name: "Valid Name with Values",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: validName,
				Values: []string{
					validValue,
				},
			},
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)

			require.NoError(t, err)
		})
	}
}

func TestCreateNonDataResourceGroup_Invalid_Fails(t *testing.T) {
	testCases := []struct {
		name   string
		req    *nondataresources.CreateNonDataResourceGroupRequest
		errMsg string
	}{
		{
			name:   "Missing Name",
			req:    &nondataresources.CreateNonDataResourceGroupRequest{},
			errMsg: errMsgRequired,
		},
		{
			name: "Invalid Name (space)",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: " ",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (text with spaces)",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: "invalid name",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (text with special chars)",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: "invalid@name",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (leading underscore)",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: "_invalid_name",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (trailing underscore)",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: "invalid_name_",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (leading hyphen)",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: "-invalid-name",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (trailing hyphen)",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: "invalid-name-",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (invalid values)",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: validName,
				Values: []string{
					"invalid value",
				},
			},
			errMsg: errMsgStringPattern,
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)

			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

// Get

func TestGetNonDataResourceGroup_Valid_Succeeds(t *testing.T) {
	testCases := []struct {
		name string
		req  *nondataresources.GetNonDataResourceGroupRequest
	}{
		{
			name: "Valid Identifier (UUID)",
			req: &nondataresources.GetNonDataResourceGroupRequest{
				Identifier: &nondataresources.GetNonDataResourceGroupRequest_GroupId{
					GroupId: validUUID,
				},
			},
		},
		{
			name: "Valid Identifier (FQN)",
			req: &nondataresources.GetNonDataResourceGroupRequest{
				Identifier: &nondataresources.GetNonDataResourceGroupRequest_Fqn{
					Fqn: validURI,
				},
			},
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)

			require.NoError(t, err)
		})
	}
}

func TestGetNonDataResourceGroup_Invalid_Fails(t *testing.T) {
	testCases := []struct {
		name   string
		req    *nondataresources.GetNonDataResourceGroupRequest
		errMsg string
	}{
		{
			name:   "Missing Identifier",
			req:    &nondataresources.GetNonDataResourceGroupRequest{},
			errMsg: errMsgOneOfRequired,
		},
		{
			name: "Invalid UUID",
			req: &nondataresources.GetNonDataResourceGroupRequest{
				Identifier: &nondataresources.GetNonDataResourceGroupRequest_GroupId{
					GroupId: invalidUUID,
				},
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid FQN",
			req: &nondataresources.GetNonDataResourceGroupRequest{
				Identifier: &nondataresources.GetNonDataResourceGroupRequest_Fqn{
					Fqn: invalidURI,
				},
			},
			errMsg: errMsgURI,
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)

			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

// Update

// todo....

// Delete

func TestDeleteNonDataResourceGroup_Valid_Succeeds(t *testing.T) {
	req := &nondataresources.DeleteNonDataResourceGroupRequest{
		Id: validUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestDeleteNonDataResourceGroup_Invalid_Fails(t *testing.T) {
	testCases := []struct {
		name string
		req  *nondataresources.DeleteNonDataResourceGroupRequest
	}{
		{
			name: "Missing UUID",
			req:  &nondataresources.DeleteNonDataResourceGroupRequest{},
		},
		{
			name: "Invalid UUID",
			req: &nondataresources.DeleteNonDataResourceGroupRequest{
				Id: invalidUUID,
			},
		},
	}

	v := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.req)

			require.Error(t, err)
			require.Contains(t, err.Error(), errMsgUUID)
		})
	}
}
