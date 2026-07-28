package handlers

import (
	"testing"

	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithHook_RegistersInOrder(t *testing.T) {
	var invoked []string

	hookA := PreSDKHook(func(PreSDKHookContext) []sdk.Option {
		invoked = append(invoked, "a")
		return nil
	})
	hookB := PreSDKHook(func(PreSDKHookContext) []sdk.Option {
		invoked = append(invoked, "b")
		return nil
	})

	var o handlerOpts
	o = WithHook(hookA)(o)
	o = WithHook(hookB)(o)

	require.Len(t, o.hooks, 2, "expected both hooks registered")

	applyHooks(o)
	assert.Equal(t, []string{"a", "b"}, invoked, "hooks should execute in registration order")
}

func TestWithHook_VariadicRegistersAllInOrder(t *testing.T) {
	var invoked []string

	hookA := PreSDKHook(func(PreSDKHookContext) []sdk.Option {
		invoked = append(invoked, "a")
		return nil
	})
	hookB := PreSDKHook(func(PreSDKHookContext) []sdk.Option {
		invoked = append(invoked, "b")
		return nil
	})

	var o handlerOpts
	o = WithHook(hookA, hookB)(o)

	require.Len(t, o.hooks, 2, "expected both hooks registered")

	applyHooks(o)
	assert.Equal(t, []string{"a", "b"}, invoked)
}

func TestApplyHooks_PreSDKHookReceivesResolvedContext(t *testing.T) {
	var captured PreSDKHookContext

	o := handlerOpts{
		endpoint:    "https://platform.example.test",
		TLSNoVerify: true,
	}
	o = WithHook(PreSDKHook(func(ctx PreSDKHookContext) []sdk.Option {
		captured = ctx
		return nil
	}))(o)

	_ = applyHooks(o)

	assert.Equal(t, "https://platform.example.test", captured.Endpoint)
	assert.True(t, captured.TLSNoVerify)
	assert.Nil(t, captured.Profile, "no profile was set on the handlerOpts")
}

func TestApplyHooks_AppendsReturnedOptionsInOrder(t *testing.T) {
	optA := sdk.WithConnectionValidation()
	optB := sdk.WithInsecurePlaintextConn()

	var o handlerOpts
	o = WithHook(PreSDKHook(func(PreSDKHookContext) []sdk.Option { return []sdk.Option{optA} }))(o)
	o = WithHook(PreSDKHook(func(PreSDKHookContext) []sdk.Option { return []sdk.Option{optB} }))(o)

	o = applyHooks(o)

	require.Len(t, o.sdkOpts, 2, "expected one option per hook")
}

func TestApplyHooks_NoopWhenNoHooks(t *testing.T) {
	baseline := sdk.WithConnectionValidation()
	o := handlerOpts{sdkOpts: []sdk.Option{baseline}}

	o = applyHooks(o)

	assert.Len(t, o.sdkOpts, 1, "applyHooks must not mutate sdkOpts when no hooks are registered")
}

// TestWithHook_NilHookIsSkipped guards against a nil Hook slipping into the
// registered list and panicking when applyHooks invokes it.
func TestWithHook_NilHookIsSkipped(t *testing.T) {
	var o handlerOpts
	o = WithHook(nil)(o)

	assert.Empty(t, o.hooks, "nil hook must not be registered")
}

// TestWithHook_NilAmongVariadicHooksIsSkipped confirms the nil guard applies
// per element when WithHook is called with a mixed variadic list.
func TestWithHook_NilAmongVariadicHooksIsSkipped(t *testing.T) {
	realHook := PreSDKHook(func(PreSDKHookContext) []sdk.Option { return nil })

	var o handlerOpts
	o = WithHook(nil, realHook, nil)(o)

	require.Len(t, o.hooks, 1, "only the non-nil hook should be registered")
}

// TestWithProfile_NilProfileIsSkipped guards against a nil profile
// dereferencing on the immediately following GetEndpoint / GetTLSNoVerify
// calls.
func TestWithProfile_NilProfileIsSkipped(t *testing.T) {
	var o handlerOpts

	assert.NotPanics(t, func() {
		o = WithProfile(nil)(o)
	})

	assert.Nil(t, o.profile, "nil profile must not be stored")
	assert.Empty(t, o.endpoint, "endpoint must remain unset when profile is nil")
}

// TestApplyHooks_TypedNilPreSDKHookIsDropped guards against the interface
// footgun where a typed-nil function value wrapped in the Hook interface
// passes the untyped-nil check in WithHook and would otherwise panic on
// invocation. The dispatch switch drops it per-variant.
func TestApplyHooks_TypedNilPreSDKHookIsDropped(t *testing.T) {
	var typedNil PreSDKHook

	var o handlerOpts
	o = WithHook(typedNil)(o)

	require.Len(t, o.hooks, 1, "typed-nil interface value bypasses the untyped-nil filter, so it lands in the hooks slice")

	assert.NotPanics(t, func() {
		o = applyHooks(o)
	})
	assert.Empty(t, o.sdkOpts, "typed-nil PreSDKHook must not contribute SDK options")
}

// unknownHook is a Hook variant applyHooks does not recognize. It exists to
// make sure the dispatch switch drops unknown variants instead of panicking,
// which is what lets future hook points land in later PRs without breaking
// existing binaries.
type unknownHook struct{}

func (unknownHook) isHandlerHook() {}

func TestApplyHooks_UnknownHookVariantIsDropped(t *testing.T) {
	var o handlerOpts
	o.hooks = append(o.hooks, unknownHook{})

	assert.NotPanics(t, func() {
		o = applyHooks(o)
	})
	assert.Empty(t, o.sdkOpts, "unknown hook variants must not contribute SDK options")
}
