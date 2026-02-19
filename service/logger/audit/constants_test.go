package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegisterObjectType(t *testing.T) {
	const customObjectType ObjectType = 10001
	const customName = "custom_object_type"

	RegisterObjectType(customObjectType, customName)

	assert.Equal(t, customName, customObjectType.String())
}

func TestRegisterActionType(t *testing.T) {
	const customActionType ActionType = 10002
	const customName = "custom_action_type"

	RegisterActionType(customActionType, customName)

	assert.Equal(t, customName, customActionType.String())
}

func TestRegisterActionResult(t *testing.T) {
	const customActionResult ActionResult = 10003
	const customName = "custom_action_result"

	RegisterActionResult(customActionResult, customName)

	assert.Equal(t, customName, customActionResult.String())
}
