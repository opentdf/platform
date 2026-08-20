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
	dropTestRegistrations(objectTypeNames)
	dropTestRegistrations(actionTypeNames)
	dropTestRegistrations(actionResultNames)
	typeRegistrationSealed = false
	auditTypeRegistryMu.Unlock()
}

// dropTestRegistrations removes registrations made by tests, leaving the
// built-in names intact. Callers must hold auditTypeRegistryMu.
func dropTestRegistrations[T ~int](registry *typeNameRegistry[T]) {
	remaining := make(map[T]string)
	for key, name := range *registry.names.Load() {
		if key < testRegistrationBase {
			remaining[key] = name
		}
	}
	registry.names.Store(&remaining)
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

func TestRegisterTypeRejectsRenamingExistingType(t *testing.T) {
	resetAuditTypeRegistrationState(t)
	t.Cleanup(func() { resetAuditTypeRegistrationState(t) })

	const customObjectType ObjectType = testRegistrationBase + 30
	require.NoError(t, RegisterObjectType(customObjectType, "custom_object_type"))

	// Re-registering the same name is a no-op.
	require.NoError(t, RegisterObjectType(customObjectType, "custom_object_type"))

	// Renaming an existing registration is rejected.
	require.ErrorIs(t, RegisterObjectType(customObjectType, "renamed"), ErrAuditTypeAlreadyRegistered)
	assert.Equal(t, "custom_object_type", customObjectType.String())

	// Built-in types cannot be renamed either.
	require.ErrorIs(t, RegisterObjectType(ObjectTypeNamespace, "renamed_namespace"), ErrAuditTypeAlreadyRegistered)
	require.ErrorIs(t, RegisterActionType(ActionTypeRead, "renamed_read"), ErrAuditTypeAlreadyRegistered)
	require.ErrorIs(t, RegisterActionResult(ActionResultSuccess, "renamed_success"), ErrAuditTypeAlreadyRegistered)

	assert.Equal(t, "namespace", ObjectTypeNamespace.String())
	assert.Equal(t, "read", ActionTypeRead.String())
	assert.Equal(t, "success", ActionResultSuccess.String())
}

func TestUnregisteredTypesFallBackToNumericNames(t *testing.T) {
	resetAuditTypeRegistrationState(t)
	t.Cleanup(func() { resetAuditTypeRegistrationState(t) })

	assert.Equal(t, "object_type_10040", ObjectType(testRegistrationBase+40).String())
	assert.Equal(t, "action_type_10041", ActionType(testRegistrationBase+41).String())
	assert.Equal(t, "action_result_10042", ActionResult(testRegistrationBase+42).String())
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
