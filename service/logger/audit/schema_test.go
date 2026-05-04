package audit

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateClaimDestinationPath(t *testing.T) {
	t.Run("allows writable leaf paths", func(t *testing.T) {
		require.NoError(t, validateClaimDestinationPath("object.id"))
		require.NoError(t, validateClaimDestinationPath("actor.attributes"))
	})

	t.Run("allows nested paths below extensible maps", func(t *testing.T) {
		require.NoError(t, validateClaimDestinationPath("eventMetaData.requester.sub"))
		require.NoError(t, validateClaimDestinationPath("original.request.headers.user"))
	})

	t.Run("allows top level additions", func(t *testing.T) {
		require.NoError(t, validateClaimDestinationPath("banana"))
		require.NoError(t, validateClaimDestinationPath("banana.requester.sub"))
	})

	t.Run("rejects reserved paths", func(t *testing.T) {
		err := validateClaimDestinationPath("requestID")
		require.ErrorIs(t, err, ErrReservedAuditPath)

		err = validateClaimDestinationPath("action.result")
		require.ErrorIs(t, err, ErrReservedAuditPath)

		err = validateClaimDestinationPath("clientInfo.userAgent")
		require.ErrorIs(t, err, ErrReservedAuditPath)

		err = validateClaimDestinationPath("clientInfo.requestIP")
		require.ErrorIs(t, err, ErrReservedAuditPath)
	})

	t.Run("rejects container paths", func(t *testing.T) {
		err := validateClaimDestinationPath("eventMetaData")
		require.ErrorIs(t, err, ErrAuditContainerPath)

		err = validateClaimDestinationPath("object")
		require.ErrorIs(t, err, ErrAuditContainerPath)

		err = validateClaimDestinationPath("object.attributes")
		require.ErrorIs(t, err, ErrAuditContainerPath)
	})

	t.Run("rejects unknown nested paths below closed containers", func(t *testing.T) {
		err := validateClaimDestinationPath("object.extra.foo")
		require.ErrorIs(t, err, ErrUnknownAuditPath)
	})

	t.Run("rejects leading dot paths", func(t *testing.T) {
		err := validateClaimDestinationPath(".banana")
		require.ErrorIs(t, err, ErrUnknownAuditPath)
	})
}

func TestBuildAuditPathSchemaRejectsUnknownTags(t *testing.T) {
	type badStruct struct {
		Field string `json:"field" audit:"resreved"`
	}
	_, err := buildAuditPathSchema(reflect.TypeOf(badStruct{}))
	require.Error(t, err)
	require.ErrorContains(t, err, "unknown audit tag")
}
