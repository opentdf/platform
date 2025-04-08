package nondataresources

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy/nondataresources"
	"github.com/stretchr/testify/require"
)

// todo: we should really move this code manually written in every single test file to a common package
// maybe policyservicetest.* or protovalidatetest.* ?

func getValidator() *protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

const (
	validUUID   = "00000000-0000-0000-0000-000000000000"
	invalidUUID = "not-uuid"
	validURI    = "https://ndr-uri"
	invalidURI  = "not-uri"

	errMsgRequired      = "required"
	errMsgOneOfRequired = "oneof [required]"
	errMsgUUID          = "string.uuid"
	errMsgURI           = "string.uri"
)

///
/// Non Data Resource Group
///

// Create Non Data Resource Group

func TestCreateNonDataResourceGroup_NameOnly_Succeeds(t *testing.T) {
	req := &nondataresources.CreateNonDataResourceGroupRequest{
		Name: "test",
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateNonDataResourceGroup_NameAndValues_Succeeds(t *testing.T) {
	req := &nondataresources.CreateNonDataResourceGroupRequest{
		Name: "test",
		Values: []string{
			"value1",
			"value2",
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateNonDataResourceGroup_NameEmpty_Fails(t *testing.T) {
	req := &nondataresources.CreateNonDataResourceGroupRequest{}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgRequired)
}

// Get Non Data Resource Group

func TestGetNonDataResourceGroup_GroupID_Succeeds(t *testing.T) {
	req := &nondataresources.GetNonDataResourceGroupRequest{
		Identifier: &nondataresources.GetNonDataResourceGroupRequest_GroupId{
			GroupId: validUUID,
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestGetNonDataResourceGroup_GroupID_InvalidUUID_Fails(t *testing.T) {
	req := &nondataresources.GetNonDataResourceGroupRequest{
		Identifier: &nondataresources.GetNonDataResourceGroupRequest_GroupId{
			GroupId: invalidUUID,
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgUUID)
}

func TestGetNonDataResourceGroup_FQN_Succeeds(t *testing.T) {
	req := &nondataresources.GetNonDataResourceGroupRequest{
		Identifier: &nondataresources.GetNonDataResourceGroupRequest_Fqn{
			Fqn: validURI,
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestGetNonDataResourceGroup_FQN_InvalidURI_Fails(t *testing.T) {
	req := &nondataresources.GetNonDataResourceGroupRequest{
		Identifier: &nondataresources.GetNonDataResourceGroupRequest_Fqn{
			Fqn: invalidURI,
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgURI)
}

func TestGetNonDataResourceGroup_MissingIdentifier_Fails(t *testing.T) {
	req := &nondataresources.GetNonDataResourceGroupRequest{}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgOneOfRequired)
}

// Update Non Data Resource Group

func TestUpdateNonDataResourceGroup_ID_Succeeds(t *testing.T) {
	req := &nondataresources.UpdateNonDataResourceGroupRequest{
		Id: validUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestUpdateNonDataResourceGroup_ID_InvalidUUID_Fails(t *testing.T) {
	req := &nondataresources.UpdateNonDataResourceGroupRequest{
		Id: invalidUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgUUID)
}

///
/// Non Data Resource Value
///

// Create Non Data Resource Value

func TestCreateNonDataResourceValue_Succeeds(t *testing.T) {
	req := &nondataresources.CreateNonDataResourceValueRequest{
		GroupId: validUUID,
		Value:   "test",
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateNonDataResourceValue_GroupID_InvalidUUID_Fails(t *testing.T) {
	req := &nondataresources.CreateNonDataResourceValueRequest{
		GroupId: invalidUUID,
		Value:   "test",
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgUUID)
}

func TestCreateNonDataResourceValue_ValueEmpty_Fails(t *testing.T) {
	req := &nondataresources.CreateNonDataResourceValueRequest{
		GroupId: validUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgRequired)
}

func TestCreateNonDataResourceValue_EmptyRequest_Fails(t *testing.T) {
	req := &nondataresources.CreateNonDataResourceValueRequest{}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgUUID)
	require.Contains(t, err.Error(), errMsgRequired)
}

// Get Non Data Resource Value

func TestGetNonDataResourceValue_ValueID_Succeeds(t *testing.T) {
	req := &nondataresources.GetNonDataResourceValueRequest{
		Identifier: &nondataresources.GetNonDataResourceValueRequest_ValueId{
			ValueId: validUUID,
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestGetNonDataResourceValue_ValueID_InvalidUUID_Fails(t *testing.T) {
	req := &nondataresources.GetNonDataResourceValueRequest{
		Identifier: &nondataresources.GetNonDataResourceValueRequest_ValueId{
			ValueId: invalidUUID,
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgUUID)
}

func TestGetNonDataResourceValue_FQN_Succeeds(t *testing.T) {
	req := &nondataresources.GetNonDataResourceValueRequest{
		Identifier: &nondataresources.GetNonDataResourceValueRequest_Fqn{
			Fqn: validURI,
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestGetNonDataResourceValue_FQN_InvalidURI_Fails(t *testing.T) {
	req := &nondataresources.GetNonDataResourceValueRequest{
		Identifier: &nondataresources.GetNonDataResourceValueRequest_Fqn{
			Fqn: invalidURI,
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgURI)
}

func TestGetNonDataResourceValue_MissingIdentifier_Fails(t *testing.T) {
	req := &nondataresources.GetNonDataResourceValueRequest{}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgOneOfRequired)
}

// Update Non Data Resource Value

func TestUpdateNonDataResourceValue_ID_Succeeds(t *testing.T) {
	req := &nondataresources.UpdateNonDataResourceGroupRequest{
		Id: validUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestUpdateNonDataResourceValue_ID_InvalidUUID_Fails(t *testing.T) {
	req := &nondataresources.UpdateNonDataResourceGroupRequest{
		Id: invalidUUID,
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), errMsgUUID)
}
