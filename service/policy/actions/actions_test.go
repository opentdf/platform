package actions

import (
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/stretchr/testify/suite"
)

const (
	validUUID                  = "00000000-0000-0000-0000-000000000000"
	validNamespaceFQN          = "https://example.com"
	errMessageUUID             = "string.uuid"
	errMessageMaxLength        = "string.max_len"
	errMessageActionNameFormat = "action_name_format"
	errMessageURI              = "string.uri"
	errMessageRequired         = "required"
	errMessageOneof            = "message.oneof"
	errMessageNamespaceByName  = "namespace_required_for_name"
)

var (
	validNames = []string{"valid_Name", "valid_name", "NAME", "NAME-IS-VALID", "SOME_VALID_NAME", "valid-name", strings.Repeat("a", 253), strings.Repeat("a", 1)}

	actionNamesInvalidFormat = []string{
		"!",
		"name with space",
		"slash/",
		"slash\\",
		"name:with:colon",
		"name.dot.delimited",
		"_cannot_start_with_underscore",
		"cannot_end_with__underscore_",
		"-cannot-start-with-hyphen",
		"cannot-end-with-hyphen-",
	}
)

// Actions proto validation

type ActionSuite struct {
	suite.Suite
	v protovalidate.Validator
}

// Set up the test environment
func (s *ActionSuite) SetupSuite() {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	s.v = v
}

func TestActionServiceProtos(t *testing.T) {
	suite.Run(t, new(ActionSuite))
}

func (s *ActionSuite) Test_CreateActionRequest_Fails() {
	for _, name := range actionNamesInvalidFormat {
		s.Run(name, func() {
			req := &actions.CreateActionRequest{
				Name:        name,
				NamespaceId: validUUID,
			}
			err := s.v.Validate(req)
			s.Require().Error(err)
			s.Require().Contains(err.Error(), errMessageActionNameFormat)
		})
	}

	// no name
	req := &actions.CreateActionRequest{
		Name:        "",
		NamespaceId: validUUID,
	}
	err := s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageRequired)

	// too long
	req = &actions.CreateActionRequest{
		Name:        strings.Repeat("a", 254),
		NamespaceId: validUUID,
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageMaxLength)

	// namespace required
	req = &actions.CreateActionRequest{
		Name: "valid_name",
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageOneof)

	// invalid namespace id
	req = &actions.CreateActionRequest{
		Name:        "valid_name",
		NamespaceId: "invalid-uuid",
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageUUID)

	// invalid namespace fqn
	req = &actions.CreateActionRequest{
		Name:         "valid_name",
		NamespaceFqn: "not-a-uri",
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageURI)
}

func (s *ActionSuite) Test_CreateActionRequest_Succeeds() {
	for _, name := range validNames {
		s.Run(name, func() {
			req := &actions.CreateActionRequest{
				Name:         name,
				NamespaceFqn: validNamespaceFQN,
			}
			err := s.v.Validate(req)
			s.Require().NoError(err)
		})
	}

	// with metadata
	req := &actions.CreateActionRequest{
		Name:        "valid_name",
		NamespaceId: validUUID,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"key": "value"},
		},
	}
	err := s.v.Validate(req)
	s.Require().NoError(err)
}

func (s *ActionSuite) Test_GetAction_Succeeds() {
	req := &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: validUUID,
		},
	}
	err := s.v.Validate(req)
	s.Require().NoError(err)

	for _, name := range validNames {
		s.Run(name, func() {
			req = &actions.GetActionRequest{
				Identifier: &actions.GetActionRequest_Name{
					Name: name,
				},
				NamespaceFqn: validNamespaceFQN,
			}
			err := s.v.Validate(req)
			s.Require().NoError(err)
		})
	}
}

func (s *ActionSuite) Test_GetAction_Fails() {
	req := &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: "",
		},
		NamespaceId: validUUID,
	}
	err := s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageUUID)

	req = &actions.GetActionRequest{}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageRequired)

	// missing namespace
	req = &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{
			Name: "valid_name",
		},
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageNamespaceByName)

	for _, name := range actionNamesInvalidFormat {
		s.Run(name, func() {
			req = &actions.GetActionRequest{
				Identifier: &actions.GetActionRequest_Name{
					Name: name,
				},
				NamespaceFqn: validNamespaceFQN,
			}
			err := s.v.Validate(req)
			s.Require().Error(err)
			s.Require().Contains(err.Error(), errMessageActionNameFormat)
		})
	}

	// too long
	req = &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{
			Name: strings.Repeat("a", 254),
		},
		NamespaceId: validUUID,
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageMaxLength)

	// invalid namespace id
	req = &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{
			Name: "valid_name",
		},
		NamespaceId: "invalid-uuid",
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageUUID)

	// invalid namespace fqn
	req = &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{
			Name: "valid_name",
		},
		NamespaceFqn: "not-a-uri",
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageURI)
}

func (s *ActionSuite) Test_ListActions_Succeeds() {
	reqPaginated := &actions.ListActionsRequest{
		NamespaceId: validUUID,
		Pagination: &policy.PageRequest{
			Limit: 1,
		},
	}
	err := s.v.Validate(reqPaginated)
	s.Require().NoError(err)

	reqPaginated.Pagination.Offset = 100
	err = s.v.Validate(reqPaginated)
	s.Require().NoError(err)

	reqNoPagination := &actions.ListActionsRequest{NamespaceFqn: validNamespaceFQN}
	err = s.v.Validate(reqNoPagination)
	s.Require().NoError(err)
}

func (s *ActionSuite) Test_ListActions_Fails() {
	// missing namespace
	req := &actions.ListActionsRequest{}
	err := s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageOneof)

	// invalid namespace id
	req = &actions.ListActionsRequest{NamespaceId: "invalid-uuid"}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageUUID)

	// invalid namespace fqn
	req = &actions.ListActionsRequest{NamespaceFqn: "not-a-uri"}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageURI)
}

func (s *ActionSuite) Test_UpdateActionRequest_Succeeds() {
	req := &actions.UpdateActionRequest{
		Id: validUUID,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"key": "value"},
		},
	}
	err := s.v.Validate(req)
	s.Require().NoError(err)

	for _, name := range validNames {
		s.Run(name, func() {
			req.Name = name
			err := s.v.Validate(req)
			s.Require().NoError(err)
		})
	}

	req = &actions.UpdateActionRequest{
		Id:   validUUID,
		Name: "no-metadata",
	}
	err = s.v.Validate(req)
	s.Require().NoError(err)
}

func (s *ActionSuite) Test_UpdateActionRequest_Fails() {
	req := &actions.UpdateActionRequest{
		Id: "",
	}
	err := s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageUUID)

	for _, name := range actionNamesInvalidFormat {
		s.Run(name, func() {
			req = &actions.UpdateActionRequest{
				Id:   validUUID,
				Name: name,
			}
			err := s.v.Validate(req)
			s.Require().Error(err)
			s.Require().Contains(err.Error(), errMessageActionNameFormat)
		})
	}

	req = &actions.UpdateActionRequest{
		Name: strings.Repeat("a", 254),
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageMaxLength)
}

func (s *ActionSuite) Test_DeleteActionRequest_Succeeds() {
	req := &actions.DeleteActionRequest{
		Id: validUUID,
	}
	err := s.v.Validate(req)
	s.Require().NoError(err)
}

func (s *ActionSuite) Test_DeleteActionRequest_Fails() {
	req := &actions.DeleteActionRequest{
		Id: "",
	}
	err := s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageUUID)

	req = &actions.DeleteActionRequest{}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageUUID)

	req = &actions.DeleteActionRequest{
		Id: "custom_action_name_used_as_id",
	}
	err = s.v.Validate(req)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), errMessageUUID)
}
