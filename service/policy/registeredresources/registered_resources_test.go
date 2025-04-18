package registeredresources

import (
	"strings"
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/stretchr/testify/suite"
)

type RegisteredResourcesSuite struct {
	suite.Suite
	v protovalidate.Validator
}

func (s *RegisteredResourcesSuite) SetupSuite() {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	s.v = v
}

func TestRegisteredResourcesServiceProtos(t *testing.T) {
	suite.Run(t, new(RegisteredResourcesSuite))
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
	errMsgOptionalUUID  = "optional_uuid_format"
	errMsgURI           = "string.uri"
	errMsgNameFormat    = "rr_name_format"
	errMsgValueFormat   = "rr_value_format"
	errMsgStringPattern = "string.pattern"
	errMsgStringMaxLen  = "string.max_len"
)

///
/// Registered Resources
///

// Create

func (s *RegisteredResourcesSuite) TestCreateRegisteredResource_Valid_Succeeds() {
	testCases := []struct {
		name string
		req  *registeredresources.CreateRegisteredResourceRequest
	}{
		{
			name: "Name Only",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: validName,
			},
		},
		{
			name: "Name with Values",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: validName,
				Values: []string{
					validValue,
				},
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().NoError(err)
		})
	}
}

func (s *RegisteredResourcesSuite) TestCreateRegisteredResource_Invalid_Fails() {
	testCases := []struct {
		name   string
		req    *registeredresources.CreateRegisteredResourceRequest
		errMsg string
	}{
		{
			name:   "Missing Name",
			req:    &registeredresources.CreateRegisteredResourceRequest{},
			errMsg: errMsgRequired,
		},
		{
			name: "Invalid Name (space)",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: " ",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (too long)",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: strings.Repeat("a", 254),
			},
			errMsg: errMsgStringMaxLen,
		},
		{
			name: "Invalid Name (text with spaces)",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: "invalid name",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (text with special chars)",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: "invalid@name",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (leading underscore)",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: "_invalid_name",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (trailing underscore)",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: "invalid_name_",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (leading hyphen)",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: "-invalid-name",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (trailing hyphen)",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: "invalid-name-",
			},
			errMsg: errMsgNameFormat,
		},
		{
			name: "Invalid Name (invalid values)",
			req: &registeredresources.CreateRegisteredResourceRequest{
				Name: validName,
				Values: []string{
					"invalid value",
				},
			},
			errMsg: errMsgStringPattern,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().Error(err)
			s.Require().Contains(err.Error(), tc.errMsg)
		})
	}
}

// Get

func (s *RegisteredResourcesSuite) TestGetRegisteredResource_Valid_Succeeds() {
	testCases := []struct {
		name string
		req  *registeredresources.GetRegisteredResourceRequest
	}{
		{
			name: "Identifier (UUID)",
			req: &registeredresources.GetRegisteredResourceRequest{
				Identifier: &registeredresources.GetRegisteredResourceRequest_ResourceId{
					ResourceId: validUUID,
				},
			},
		},
		{
			name: "Identifier (FQN)",
			req: &registeredresources.GetRegisteredResourceRequest{
				Identifier: &registeredresources.GetRegisteredResourceRequest_Fqn{
					Fqn: validURI,
				},
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().NoError(err)
		})
	}
}

func (s *RegisteredResourcesSuite) TestGetRegisteredResource_Invalid_Fails() {
	testCases := []struct {
		name   string
		req    *registeredresources.GetRegisteredResourceRequest
		errMsg string
	}{
		{
			name:   "Missing Identifier",
			req:    &registeredresources.GetRegisteredResourceRequest{},
			errMsg: errMsgOneOfRequired,
		},
		{
			name: "Invalid UUID",
			req: &registeredresources.GetRegisteredResourceRequest{
				Identifier: &registeredresources.GetRegisteredResourceRequest_ResourceId{
					ResourceId: invalidUUID,
				},
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid FQN",
			req: &registeredresources.GetRegisteredResourceRequest{
				Identifier: &registeredresources.GetRegisteredResourceRequest_Fqn{
					Fqn: invalidURI,
				},
			},
			errMsg: errMsgURI,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().Error(err)
			s.Require().Contains(err.Error(), tc.errMsg)
		})
	}
}

// Update

func (s *RegisteredResourcesSuite) TestUpdateRegisteredResource_Valid_Succeeds() {
	// id provided
	// valid value provided
	testCases := []struct {
		name string
		req  *registeredresources.UpdateRegisteredResourceRequest
	}{
		{
			name: "ID only",
			req: &registeredresources.UpdateRegisteredResourceRequest{
				Id: validUUID,
			},
		},
		{
			name: "ID with Name",
			req: &registeredresources.UpdateRegisteredResourceRequest{
				Id:   validUUID,
				Name: validName,
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().NoError(err)
		})
	}
}

func (s *RegisteredResourcesSuite) TestUpdateRegisteredResource_Invalid_Fails() {
	testCases := []struct {
		name   string
		req    *registeredresources.UpdateRegisteredResourceRequest
		errMsg string
	}{
		{
			name:   "Missing ID",
			req:    &registeredresources.UpdateRegisteredResourceRequest{},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid ID",
			req: &registeredresources.UpdateRegisteredResourceRequest{
				Id: invalidUUID,
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid Name (space)",
			req: &registeredresources.UpdateRegisteredResourceRequest{
				Id:   validUUID,
				Name: " ",
			},
			errMsg: errMsgNameFormat,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().Error(err)
			s.Require().Contains(err.Error(), tc.errMsg)
		})
	}
}

// Delete

func (s *RegisteredResourcesSuite) TestDeleteRegisteredResource_Valid_Succeeds() {
	req := &registeredresources.DeleteRegisteredResourceRequest{
		Id: validUUID,
	}

	err := s.v.Validate(req)

	s.Require().NoError(err)
}

func (s *RegisteredResourcesSuite) TestDeleteRegisteredResource_Invalid_Fails() {
	testCases := []struct {
		name string
		req  *registeredresources.DeleteRegisteredResourceRequest
	}{
		{
			name: "Missing UUID",
			req:  &registeredresources.DeleteRegisteredResourceRequest{},
		},
		{
			name: "Invalid UUID",
			req: &registeredresources.DeleteRegisteredResourceRequest{
				Id: invalidUUID,
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().Error(err)
			s.Require().Contains(err.Error(), errMsgUUID)
		})
	}
}

///
/// Registered Resource Values
///

// Create

func (s *RegisteredResourcesSuite) TestCreateRegisteredResourceValue_Valid_Succeeds() {
	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: validUUID,
		Value:      validValue,
	}

	err := s.v.Validate(req)

	s.Require().NoError(err)
}

func (s *RegisteredResourcesSuite) TestCreateRegisteredResourceValue_Invalid_Succeeds() {
	testCases := []struct {
		name   string
		req    *registeredresources.CreateRegisteredResourceValueRequest
		errMsg string
	}{
		{
			name: "Missing Group ID",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				Value: validValue,
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid Group ID",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: invalidUUID,
				Value:      validValue,
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Missing Value",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: validUUID,
			},
			errMsg: errMsgRequired,
		},
		{
			name: "Invalid Value (space)",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: validUUID,
				Value:      " ",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (too long)",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: validUUID,
				Value:      strings.Repeat("a", 254),
			},
			errMsg: errMsgStringMaxLen,
		},
		{
			name: "Invalid Value (text with spaces)",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: validUUID,
				Value:      "invalid value",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (text with special chars)",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: validUUID,
				Value:      "invalid@value",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (leading underscore)",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: validUUID,
				Value:      "_invalid_value",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (trailing underscore)",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: validUUID,
				Value:      "invalid_value_",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (leading hyphen)",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: validUUID,
				Value:      "-invalid-value",
			},
			errMsg: errMsgValueFormat,
		},
		{
			name: "Invalid Value (trailing hyphen)",
			req: &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId: validUUID,
				Value:      "invalid-value-",
			},
			errMsg: errMsgValueFormat,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().Error(err)
			s.Require().Contains(err.Error(), tc.errMsg)
		})
	}
}

// Get

func (s *RegisteredResourcesSuite) TestGetRegisteredResourceValue_Valid_Succeeds() {
	testCases := []struct {
		name string
		req  *registeredresources.GetRegisteredResourceValueRequest
	}{
		{
			name: "Identifier (UUID)",
			req: &registeredresources.GetRegisteredResourceValueRequest{
				Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
					ValueId: validUUID,
				},
			},
		},
		{
			name: "Identifier (FQN)",
			req: &registeredresources.GetRegisteredResourceValueRequest{
				Identifier: &registeredresources.GetRegisteredResourceValueRequest_Fqn{
					Fqn: validURI,
				},
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().NoError(err)
		})
	}
}

func (s *RegisteredResourcesSuite) TestGetRegisteredResourceValue_Invalid_Fails() {
	testCases := []struct {
		name   string
		req    *registeredresources.GetRegisteredResourceValueRequest
		errMsg string
	}{
		{
			name:   "Missing Identifier",
			req:    &registeredresources.GetRegisteredResourceValueRequest{},
			errMsg: errMsgOneOfRequired,
		},
		{
			name: "Invalid UUID",
			req: &registeredresources.GetRegisteredResourceValueRequest{
				Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
					ValueId: invalidUUID,
				},
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid FQN",
			req: &registeredresources.GetRegisteredResourceValueRequest{
				Identifier: &registeredresources.GetRegisteredResourceValueRequest_Fqn{
					Fqn: invalidURI,
				},
			},
			errMsg: errMsgURI,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().Error(err)
			s.Require().Contains(err.Error(), tc.errMsg)
		})
	}
}

// List

func (s *RegisteredResourcesSuite) TestListRegisteredResourceValues_Valid_Succeeds() {
	testCases := []struct {
		name string
		req  *registeredresources.ListRegisteredResourceValuesRequest
	}{
		{
			name: "Missing Group ID",
			req:  &registeredresources.ListRegisteredResourceValuesRequest{},
		},
		{
			name: "Group ID",
			req: &registeredresources.ListRegisteredResourceValuesRequest{
				ResourceId: validUUID,
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().NoError(err)
		})
	}
}

func (s *RegisteredResourcesSuite) TestListRegisteredResourceValues_Invalid_Succeeds() {
	req := &registeredresources.ListRegisteredResourceValuesRequest{
		ResourceId: invalidUUID,
	}

	err := s.v.Validate(req)

	s.Require().Error(err)
	s.Require().ErrorContains(err, errMsgOptionalUUID)
}

// Update

func (s *RegisteredResourcesSuite) TestUpdateRegisteredResourceValue_Valid_Succeeds() {
	// id provided
	// valid value provided
	testCases := []struct {
		name string
		req  *registeredresources.UpdateRegisteredResourceValueRequest
	}{
		{
			name: "ID only",
			req: &registeredresources.UpdateRegisteredResourceValueRequest{
				Id: validUUID,
			},
		},
		{
			name: "ID with Value",
			req: &registeredresources.UpdateRegisteredResourceValueRequest{
				Id:    validUUID,
				Value: validValue,
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().NoError(err)
		})
	}
}

func (s *RegisteredResourcesSuite) TestUpdateRegisteredResourceValue_Invalid_Fails() {
	testCases := []struct {
		name   string
		req    *registeredresources.UpdateRegisteredResourceValueRequest
		errMsg string
	}{
		{
			name:   "Missing ID",
			req:    &registeredresources.UpdateRegisteredResourceValueRequest{},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid ID",
			req: &registeredresources.UpdateRegisteredResourceValueRequest{
				Id: invalidUUID,
			},
			errMsg: errMsgUUID,
		},
		{
			name: "Invalid Value (space)",
			req: &registeredresources.UpdateRegisteredResourceValueRequest{
				Id:    validUUID,
				Value: " ",
			},
			errMsg: errMsgValueFormat,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().Error(err)
			s.Require().Contains(err.Error(), tc.errMsg)
		})
	}
}

// Delete

func (s *RegisteredResourcesSuite) TestDeleteRegisteredResourceValue_Valid_Succeeds() {
	req := &registeredresources.DeleteRegisteredResourceValueRequest{
		Id: validUUID,
	}

	err := s.v.Validate(req)

	s.Require().NoError(err)
}

func (s *RegisteredResourcesSuite) TestDeleteRegisteredResourceValue_Invalid_Fails() {
	testCases := []struct {
		name string
		req  *registeredresources.DeleteRegisteredResourceValueRequest
	}{
		{
			name: "Missing UUID",
			req:  &registeredresources.DeleteRegisteredResourceValueRequest{},
		},
		{
			name: "Invalid UUID",
			req: &registeredresources.DeleteRegisteredResourceValueRequest{
				Id: invalidUUID,
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := s.v.Validate(tc.req)

			s.Require().Error(err)
			s.Require().Contains(err.Error(), errMsgUUID)
		})
	}
}
