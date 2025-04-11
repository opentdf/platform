package nondataresources

import (
	"strings"
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
	errMsgValueFormat   = "ndr_value_format"
	errMsgStringPattern = "string.pattern"
	errMsgStringMaxLen  = "string.max_len"
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
			name: "Name Only",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: validName,
			},
		},
		{
			name: "Name with Values",
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
			name: "Invalid Name (too long)",
			req: &nondataresources.CreateNonDataResourceGroupRequest{
				Name: strings.Repeat("a", 254),
			},
			errMsg: errMsgStringMaxLen,
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
			name: "Identifier (UUID)",
			req: &nondataresources.GetNonDataResourceGroupRequest{
				Identifier: &nondataresources.GetNonDataResourceGroupRequest_GroupId{
					GroupId: validUUID,
				},
			},
		},
		{
			name: "Identifier (FQN)",
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

func TestUpdateNonDataResourceGroup_Valid_Succeeds(t *testing.T) {
	// id provided
	// valid value provided
	testCases := []struct {
		name string
		req  *nondataresources.UpdateNonDataResourceGroupRequest
	}{
		{
			name: "ID only",
			req: &nondataresources.UpdateNonDataResourceGroupRequest{
				Id: validUUID,
			},
		},
		{
			name: "ID with Name",
			req: &nondataresources.UpdateNonDataResourceGroupRequest{
				Id:   validUUID,
				Name: validName,
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

func TestUpdateNonDataResourceGroup_Invalid_Fails(t *testing.T) {
	testCases := []struct {
		name   string
		req    *nondataresources.UpdateNonDataResourceGroupRequest
		errMsg string
	}{
		{
			name:   "Missing ID",
			req:    &nondataresources.UpdateNonDataResourceGroupRequest{},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid ID",
			req: &nondataresources.UpdateNonDataResourceGroupRequest{
				Id: invalidUUID,
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid Name (space)",
			req: &nondataresources.UpdateNonDataResourceGroupRequest{
				Id:   validUUID,
				Name: " ",
			},
			errMsg: errMsgNameFormat,
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

///
/// Non Data Resource Value
///

// Create

func TestCreateNonDataResourceValue_Valid_Succeeds(t *testing.T) {
	req := &nondataresources.CreateNonDataResourceValueRequest{
		GroupId: validUUID,
		Value:   validValue,
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateNonDataResourceValue_Invalid_Succeeds(t *testing.T) {
	testCases := []struct {
		name   string
		req    *nondataresources.CreateNonDataResourceValueRequest
		errMsg string
	}{
		{
			name: "Missing Group ID",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				Value: validValue,
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid Group ID",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: invalidUUID,
				Value:   validValue,
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Missing Value",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: validUUID,
			},
			errMsg: errMsgRequired,
		},
		{
			name: "Invalid Value (space)",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: validUUID,
				Value:   " ",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (too long)",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: validUUID,
				Value:   strings.Repeat("a", 254),
			},
			errMsg: errMsgStringMaxLen,
		},
		{
			name: "Invalid Value (text with spaces)",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: validUUID,
				Value:   "invalid value",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (text with special chars)",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: validUUID,
				Value:   "invalid@value",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (leading underscore)",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: validUUID,
				Value:   "_invalid_value",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (trailing underscore)",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: validUUID,
				Value:   "invalid_value_",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (leading hyphen)",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: validUUID,
				Value:   "-invalid-value",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (trailing hyphen)",
			req: &nondataresources.CreateNonDataResourceValueRequest{
				GroupId: validUUID,
				Value:   "invalid-value-",
			},
			errMsg: errMsgValueFormat,
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

func TestGetNonDataResourceValue_Valid_Succeeds(t *testing.T) {
	testCases := []struct {
		name string
		req  *nondataresources.GetNonDataResourceValueRequest
	}{
		{
			name: "Identifier (UUID)",
			req: &nondataresources.GetNonDataResourceValueRequest{
				Identifier: &nondataresources.GetNonDataResourceValueRequest_ValueId{
					ValueId: validUUID,
				},
			},
		},
		{
			name: "Identifier (FQN)",
			req: &nondataresources.GetNonDataResourceValueRequest{
				Identifier: &nondataresources.GetNonDataResourceValueRequest_Fqn{
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

func TestGetNonDataResourceValue_Invalid_Fails(t *testing.T) {
	testCases := []struct {
		name   string
		req    *nondataresources.GetNonDataResourceValueRequest
		errMsg string
	}{
		{
			name:   "Missing Identifier",
			req:    &nondataresources.GetNonDataResourceValueRequest{},
			errMsg: errMsgOneOfRequired,
		},
		{
			name: "Invalid UUID",
			req: &nondataresources.GetNonDataResourceValueRequest{
				Identifier: &nondataresources.GetNonDataResourceValueRequest_ValueId{
					ValueId: invalidUUID,
				},
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid FQN",
			req: &nondataresources.GetNonDataResourceValueRequest{
				Identifier: &nondataresources.GetNonDataResourceValueRequest_Fqn{
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

// List

func TestListNonDataResourceValue_Valid_Succeeds(t *testing.T) {
	groupID := string(validUUID)

	testCases := []struct {
		name string
		req  *nondataresources.ListNonDataResourceValueRequest
	}{
		{
			name: "Missing Group ID",
			req:  &nondataresources.ListNonDataResourceValueRequest{},
		},
		{
			name: "Group ID",
			req: &nondataresources.ListNonDataResourceValueRequest{
				GroupId: &groupID,
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

func TestListNonDataResourceValue_Invalid_Succeeds(t *testing.T) {
	groupID := string(invalidUUID)
	req := &nondataresources.ListNonDataResourceValueRequest{
		GroupId: &groupID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.ErrorContains(t, err, errMsgUUID)
}

// Update

func TestUpdateNonDataResourceValue_Valid_Succeeds(t *testing.T) {
	// id provided
	// valid value provided
	testCases := []struct {
		name string
		req  *nondataresources.UpdateNonDataResourceValueRequest
	}{
		{
			name: "ID only",
			req: &nondataresources.UpdateNonDataResourceValueRequest{
				Id: validUUID,
			},
		},
		{
			name: "ID with Value",
			req: &nondataresources.UpdateNonDataResourceValueRequest{
				Id:    validUUID,
				Value: validValue,
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

func TestUpdateNonDataResourceValue_Invalid_Fails(t *testing.T) {
	testCases := []struct {
		name   string
		req    *nondataresources.UpdateNonDataResourceValueRequest
		errMsg string
	}{
		{
			name:   "Missing ID",
			req:    &nondataresources.UpdateNonDataResourceValueRequest{},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid ID",
			req: &nondataresources.UpdateNonDataResourceValueRequest{
				Id: invalidUUID,
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid Value (space)",
			req: &nondataresources.UpdateNonDataResourceValueRequest{
				Id:    validUUID,
				Value: " ",
			},
			errMsg: errMsgValueFormat,
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

// Delete

func TestDeleteNonDataResourceValue_Valid_Succeeds(t *testing.T) {
	req := &nondataresources.DeleteNonDataResourceValueRequest{
		Id: validUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestDeleteNonDataResourceValue_Invalid_Fails(t *testing.T) {
	testCases := []struct {
		name string
		req  *nondataresources.DeleteNonDataResourceValueRequest
	}{
		{
			name: "Missing UUID",
			req:  &nondataresources.DeleteNonDataResourceValueRequest{},
		},
		{
			name: "Invalid UUID",
			req: &nondataresources.DeleteNonDataResourceValueRequest{
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
