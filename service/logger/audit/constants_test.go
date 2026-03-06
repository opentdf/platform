package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetAuditTypeRegistrationState(t *testing.T) {
	t.Helper()

	auditTypeRegistryMu.Lock()
	typeRegistrationSealed = false
	auditTypeRegistryMu.Unlock()
}

func TestRegisterObjectType(t *testing.T) {
	resetAuditTypeRegistrationState(t)

	const customObjectType ObjectType = 10001
	const customName = "custom_object_type"

	err := RegisterObjectType(customObjectType, customName)
	require.NoError(t, err)
	assert.Equal(t, customName, customObjectType.String())
}

func TestRegisterActionType(t *testing.T) {
	resetAuditTypeRegistrationState(t)

	const customActionType ActionType = 10002
	const customName = "custom_action_type"

	err := RegisterActionType(customActionType, customName)
	require.NoError(t, err)
	assert.Equal(t, customName, customActionType.String())
}

func TestRegisterActionResult(t *testing.T) {
	resetAuditTypeRegistrationState(t)

	const customActionResult ActionResult = 10003
	const customName = "custom_action_result"

	err := RegisterActionResult(customActionResult, customName)
	require.NoError(t, err)
	assert.Equal(t, customName, customActionResult.String())
}

func TestApplyTypeRegistrations(t *testing.T) {
	resetAuditTypeRegistrationState(t)

	const (
		customObjectType   ObjectType   = 10004
		customActionType   ActionType   = 10005
		customActionResult ActionResult = 10006
	)

	objectTypes := make(map[ObjectType]string)
	objectTypes[customObjectType] = "object_type_custom"

	actionTypes := make(map[ActionType]string)
	actionTypes[customActionType] = "action_type_custom"

	actionResults := make(map[ActionResult]string)
	actionResults[customActionResult] = "action_result_custom"

	err := ApplyTypeRegistrations(TypeRegistrations{
		ObjectTypes:   objectTypes,
		ActionTypes:   actionTypes,
		ActionResults: actionResults,
	})
	require.NoError(t, err)

	assert.Equal(t, "object_type_custom", customObjectType.String())
	assert.Equal(t, "action_type_custom", customActionType.String())
	assert.Equal(t, "action_result_custom", customActionResult.String())
}

func TestRegisterTypeBlockedAfterSeal(t *testing.T) {
	resetAuditTypeRegistrationState(t)

	SealTypeRegistrations()

	errObject := RegisterObjectType(ObjectType(10010), "blocked_object")
	errAction := RegisterActionType(ActionType(10011), "blocked_action")
	errResult := RegisterActionResult(ActionResult(10012), "blocked_result")

	require.ErrorIs(t, errObject, ErrAuditTypeRegistrationSealed)
	require.ErrorIs(t, errAction, ErrAuditTypeRegistrationSealed)
	require.ErrorIs(t, errResult, ErrAuditTypeRegistrationSealed)
}

func TestApplyTypeRegistrationsBlockedAfterSeal(t *testing.T) {
	resetAuditTypeRegistrationState(t)

	SealTypeRegistrations()

	blockedObjectTypes := make(map[ObjectType]string)
	blockedObjectTypes[ObjectType(10013)] = "blocked_object"

	err := ApplyTypeRegistrations(TypeRegistrations{
		ObjectTypes: blockedObjectTypes,
	})
	require.ErrorIs(t, err, ErrAuditTypeRegistrationSealed)
}
