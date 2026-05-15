package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetAuditTypeRegistrationState(t *testing.T) {
	t.Helper()

	auditTypeRegistryMu.Lock()
	// Remove any previously registered test types.
	for k := range objectTypeNames {
		if k >= testRegistrationBase {
			delete(objectTypeNames, k)
		}
	}
	for k := range actionTypeNames {
		if k >= testRegistrationBase {
			delete(actionTypeNames, k)
		}
	}
	for k := range actionResultNames {
		if k >= testRegistrationBase {
			delete(actionResultNames, k)
		}
	}
	typeRegistrationSealed = false
	auditTypeRegistryMu.Unlock()
}

const testRegistrationBase = 10000

func TestRegisterObjectType(t *testing.T) {
	resetAuditTypeRegistrationState(t)
	t.Cleanup(func() { resetAuditTypeRegistrationState(t) })

	const customObjectType ObjectType = testRegistrationBase + 1
	const customName = "custom_object_type"

	err := RegisterObjectType(customObjectType, customName)
	require.NoError(t, err)
	assert.Equal(t, customName, customObjectType.String())
}

func TestRegisterActionType(t *testing.T) {
	resetAuditTypeRegistrationState(t)
	t.Cleanup(func() { resetAuditTypeRegistrationState(t) })

	const customActionType ActionType = testRegistrationBase + 2
	const customName = "custom_action_type"

	err := RegisterActionType(customActionType, customName)
	require.NoError(t, err)
	assert.Equal(t, customName, customActionType.String())
}

func TestRegisterActionResult(t *testing.T) {
	resetAuditTypeRegistrationState(t)
	t.Cleanup(func() { resetAuditTypeRegistrationState(t) })

	const customActionResult ActionResult = testRegistrationBase + 3
	const customName = "custom_action_result"

	err := RegisterActionResult(customActionResult, customName)
	require.NoError(t, err)
	assert.Equal(t, customName, customActionResult.String())
}

func TestRegisterTypeRejectsEmptyName(t *testing.T) {
	resetAuditTypeRegistrationState(t)
	t.Cleanup(func() { resetAuditTypeRegistrationState(t) })

	errObject := RegisterObjectType(ObjectType(testRegistrationBase+20), "")
	errAction := RegisterActionType(ActionType(testRegistrationBase+21), "")
	errResult := RegisterActionResult(ActionResult(testRegistrationBase+22), "")

	require.ErrorIs(t, errObject, ErrInvalidAuditTypeName)
	require.ErrorIs(t, errAction, ErrInvalidAuditTypeName)
	require.ErrorIs(t, errResult, ErrInvalidAuditTypeName)
}

func TestApplyTypeRegistrations(t *testing.T) {
	resetAuditTypeRegistrationState(t)
	t.Cleanup(func() { resetAuditTypeRegistrationState(t) })

	const (
		customObjectType   ObjectType   = testRegistrationBase + 4
		customActionType   ActionType   = testRegistrationBase + 5
		customActionResult ActionResult = testRegistrationBase + 6
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
	t.Cleanup(func() { resetAuditTypeRegistrationState(t) })

	SealTypeRegistrations()

	errObject := RegisterObjectType(ObjectType(testRegistrationBase+10), "blocked_object")
	errAction := RegisterActionType(ActionType(testRegistrationBase+11), "blocked_action")
	errResult := RegisterActionResult(ActionResult(testRegistrationBase+12), "blocked_result")

	require.ErrorIs(t, errObject, ErrAuditTypeRegistrationSealed)
	require.ErrorIs(t, errAction, ErrAuditTypeRegistrationSealed)
	require.ErrorIs(t, errResult, ErrAuditTypeRegistrationSealed)
}

func TestApplyTypeRegistrationsBlockedAfterSeal(t *testing.T) {
	resetAuditTypeRegistrationState(t)
	t.Cleanup(func() { resetAuditTypeRegistrationState(t) })

	SealTypeRegistrations()

	blockedObjectTypes := make(map[ObjectType]string)
	blockedObjectTypes[ObjectType(testRegistrationBase+13)] = "blocked_object"

	err := ApplyTypeRegistrations(TypeRegistrations{
		ObjectTypes: blockedObjectTypes,
	})
	require.ErrorIs(t, err, ErrAuditTypeRegistrationSealed)
}
