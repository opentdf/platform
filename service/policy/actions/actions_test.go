package actions

import (
	"strings"
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	validUUID                  = "00000000-0000-0000-0000-000000000000"
	errMessageUUID             = "string.uuid"
	errMessageActionNameFormat = "action_name_format"
	errMessageMinLen           = "string.min_len"
	errMessageMaxLen           = "string.max_len"
	errMessageURI              = "string.uri"
	errMessageRequired         = "required"
)

var (
	validNames = []string{"valid_Name", "valid_name", "NAME", "NAME-IS-VALID", "SOME_VALID_NAME", "valid-name", strings.Repeat("a", 253), strings.Repeat("a", 1)}

	invalidNameTests = []struct {
		name           string
		expectedErrMsg string
	}{
		{strings.Repeat("a", 254), errMessageMaxLen},
		{"!", errMessageActionNameFormat},
		{"name with space", errMessageActionNameFormat},
		{"slash/", errMessageActionNameFormat},
		{"slash\\", errMessageActionNameFormat},
		{"name:with:colon", errMessageActionNameFormat},
		{"name.dot.delimited", errMessageActionNameFormat},
		{"_cannot_start_with_underscore", errMessageActionNameFormat},
		{"cannot_end_with__underscore_", errMessageActionNameFormat},
		{"-cannot-start-with-hyphen", errMessageActionNameFormat},
		{"cannot-end-with-hyphen-", errMessageActionNameFormat},
	}
)

// Actions proto validation

type ActionSuite struct {
	suite.Suite
	v *protovalidate.Validator
}

// Set up the test environment
func (s *ActionSuite) SetupSuite() {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	s.v = v
}

func TestActionsServiceProtos(t *testing.T) {
	suite.Run(t, new(ActionSuite))
}

func (s *ActionSuite) Test_CreateActionRequest_Fails() {
	for _, test := range invalidNameTests {
		s.Run(test.name, func() {
			req := &actions.CreateActionRequest{
				Name: test.name,
			}
			err := s.v.Validate(req)
			require.Error(s.T(), err)
			require.Contains(s.T(), err.Error(), test.expectedErrMsg)
		})
	}

	// no name
	req := &actions.CreateActionRequest{
		Name: "",
	}
	err := s.v.Validate(req)
	require.Error(s.T(), err)
	require.Contains(s.T(), err.Error(), errMessageMinLen)
}

func (s *ActionSuite) Test_CreateActionRequest_Succeeds() {
	for _, name := range validNames {
		s.Run(name, func() {
			req := &actions.CreateActionRequest{
				Name: name,
			}
			err := s.v.Validate(req)
			require.NoError(s.T(), err)
		})
	}

	// with metadata
	req := &actions.CreateActionRequest{
		Name: "valid_name",
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"key": "value"},
		},
	}
	err := s.v.Validate(req)
	require.NoError(s.T(), err)
}

func (s *ActionSuite) Test_GetAction_Succeeds() {
	req := &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: validUUID,
		},
	}
	err := s.v.Validate(req)
	require.NoError(s.T(), err)

	for _, name := range validNames {
		s.Run(name, func() {
			req := &actions.GetActionRequest{
				Identifier: &actions.GetActionRequest_Name{
					Name: name,
				},
			}
			err := s.v.Validate(req)
			require.NoError(s.T(), err)
		})
	}
}

func (s *ActionSuite) Test_GetAction_Fails() {
	req := &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: "",
		},
	}
	err := s.v.Validate(req)
	require.Error(s.T(), err)
	require.Contains(s.T(), err.Error(), errMessageUUID)

	req = &actions.GetActionRequest{}
	err = s.v.Validate(req)
	require.Error(s.T(), err)
	require.Contains(s.T(), err.Error(), errMessageRequired)

	for _, test := range invalidNameTests {
		s.Run(test.name, func() {
			req := &actions.GetActionRequest{
				Identifier: &actions.GetActionRequest_Name{
					Name: test.name,
				},
			}
			err := s.v.Validate(req)
			require.Error(s.T(), err)
			require.Contains(s.T(), err.Error(), test.expectedErrMsg)
		})
	}

	// no name
	req = &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{
			Name: "",
		},
	}
	err = s.v.Validate(req)
	require.Error(s.T(), err)
	require.Contains(s.T(), err.Error(), errMessageMinLen)
}

func (s *ActionSuite) Test_ListActions_Succeeds() {
	reqPaginated := &actions.ListActionsRequest{
		Pagination: &policy.PageRequest{
			Limit: 1,
		},
	}
	err := s.v.Validate(reqPaginated)
	require.NoError(s.T(), err)

	reqPaginated.Pagination.Offset = 100
	err = s.v.Validate(reqPaginated)
	require.NoError(s.T(), err)

	reqNoPagination := &actions.ListActionsRequest{}
	err = s.v.Validate(reqNoPagination)
	require.NoError(s.T(), err)
}

func (s *ActionSuite) Test_UpdateActionRequest_Succeeds() {
	req := &actions.UpdateActionRequest{
		Id: validUUID,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"key": "value"},
		},
	}
	err := s.v.Validate(req)
	require.NoError(s.T(), err)

	for _, name := range validNames {
		s.Run(name, func() {
			req.Name = name
			err := s.v.Validate(req)
			require.NoError(s.T(), err)
		})
	}

	req = &actions.UpdateActionRequest{
		Id:   validUUID,
		Name: "no-metadata",
	}
	err = s.v.Validate(req)
	require.NoError(s.T(), err)
}

func (s *ActionSuite) Test_UpdateActionRequest_Fails() {
	req := &actions.UpdateActionRequest{
		Id: "",
	}
	err := s.v.Validate(req)
	require.Error(s.T(), err)
	require.Contains(s.T(), err.Error(), errMessageUUID)

	for _, test := range invalidNameTests {
		s.Run(test.name, func() {
			req := &actions.UpdateActionRequest{
				Id:   validUUID,
				Name: test.name,
			}
			err := s.v.Validate(req)
			require.Error(s.T(), err)
			require.Contains(s.T(), err.Error(), test.expectedErrMsg)
		})
	}
}

func (s *ActionSuite) Test_DeleteActionRequest_Succeeds() {
	req := &actions.DeleteActionRequest{
		Id: validUUID,
	}
	err := s.v.Validate(req)
	require.NoError(s.T(), err)
}

func (s *ActionSuite) Test_DeleteActionRequest_Fails() {
	req := &actions.DeleteActionRequest{
		Id: "",
	}
	err := s.v.Validate(req)
	require.Error(s.T(), err)
	require.Contains(s.T(), err.Error(), errMessageUUID)

	req = &actions.DeleteActionRequest{}
	err = s.v.Validate(req)
	require.Error(s.T(), err)
	require.Contains(s.T(), err.Error(), errMessageUUID)

	req = &actions.DeleteActionRequest{
		Id: "custom_action_name_used_as_id",
	}
	err = s.v.Validate(req)
	require.Error(s.T(), err)
	require.Contains(s.T(), err.Error(), errMessageUUID)
}
