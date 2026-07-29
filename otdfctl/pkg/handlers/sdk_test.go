package handlers

import (
	"testing"

	"github.com/opentdf/platform/otdfctl/pkg/profiles"
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

func TestResolveSDKFactory_FallsBackToDefault(t *testing.T) {
	var o handlerOpts
	assert.NotNil(t, o.resolveSDKFactory(), "unset factory must fall back to the default")
}

func TestResolveSDKFactory_PerHandlerOverridesDefault(t *testing.T) {
	sentinel := &sdk.SDK{}
	o := WithSDKFactory(func(string, ...sdk.Option) (*sdk.SDK, error) {
		return sentinel, nil
	})(handlerOpts{})

	got, err := o.resolveSDKFactory()("https://platform.example.test")
	require.NoError(t, err)
	assert.Same(t, sentinel, got, "per-handler factory must take precedence over the default")
}

func TestSetDefaultSDKFactory_OverridesAndResets(t *testing.T) {
	t.Cleanup(func() { SetDefaultSDKFactory(nil) }) // restore sdk.New

	sentinel := &sdk.SDK{}
	SetDefaultSDKFactory(func(string, ...sdk.Option) (*sdk.SDK, error) {
		return sentinel, nil
	})

	got, err := handlerOpts{}.resolveSDKFactory()("https://platform.example.test")
	require.NoError(t, err)
	assert.Same(t, sentinel, got, "SetDefaultSDKFactory must install the process-wide factory")

	SetDefaultSDKFactory(nil)
	assert.NotNil(t, handlerOpts{}.resolveSDKFactory(), "nil must reset to a usable default")
}

// newInMemoryProfile builds a client-credentials profile in memory so New can
// resolve auth options without touching the network.
func newInMemoryProfile(t *testing.T, endpoint string, tlsNoVerify bool) *profiles.OtdfctlProfileStore {
	t.Helper()
	store, err := profiles.NewOtdfctlProfileStore(
		profiles.ProfileDriverMemory,
		&profiles.ProfileConfig{Name: "test", Endpoint: endpoint, TLSNoVerify: tlsNoVerify},
		true,
	)
	require.NoError(t, err)
	require.NoError(t, store.SetAuthCredentials(profiles.AuthCredentials{
		AuthType:     profiles.AuthTypeClientCredentials,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}))
	return store
}

// captureFactoryArgs runs New with a factory that records what it received
// instead of building a real SDK.
func captureFactoryArgs(t *testing.T, opts ...HandlerOption) (string, []sdk.Option) {
	t.Helper()
	var (
		gotEndpoint string
		gotOpts     []sdk.Option
	)
	capture := WithSDKFactory(func(endpoint string, sdkOpts ...sdk.Option) (*sdk.SDK, error) {
		gotEndpoint = endpoint
		gotOpts = sdkOpts
		return &sdk.SDK{}, nil
	})
	_, err := New(append([]HandlerOption{capture}, opts...)...)
	require.NoError(t, err)
	return gotEndpoint, gotOpts
}

// TestNew_PassesNormalizedEndpointToFactory confirms the factory receives the
// normalized endpoint, not the raw profile value.
func TestNew_PassesNormalizedEndpointToFactory(t *testing.T) {
	p := newInMemoryProfile(t, "https://platform.example.test", false)

	endpoint, _ := captureFactoryArgs(t, WithProfile(p))

	assert.Equal(t, "https://platform.example.test:443", endpoint,
		"factory must receive the normalized endpoint New computed")
}

// TestNew_TLSNoVerifyReachesFactory proves --tls-no-verify adds an SDK option
// reaching the factory. It asserts the delta because sdk.Option is opaque.
func TestNew_TLSNoVerifyReachesFactory(t *testing.T) {
	off := newInMemoryProfile(t, "https://platform.example.test", false)
	on := newInMemoryProfile(t, "https://platform.example.test", true)

	_, optsOff := captureFactoryArgs(t, WithProfile(off))
	_, optsOn := captureFactoryArgs(t, WithProfile(on))

	assert.Len(t, optsOn, len(optsOff)+1,
		"--tls-no-verify must add exactly one SDK option (WithInsecureSkipVerifyConn) reaching the factory")
}

// TestNew_HTTPEndpointReachesFactoryAsPlaintext proves an http endpoint adds
// the plaintext-connection option reaching the factory.
func TestNew_HTTPEndpointReachesFactoryAsPlaintext(t *testing.T) {
	secure := newInMemoryProfile(t, "https://platform.example.test", false)
	plaintext := newInMemoryProfile(t, "http://platform.example.test", false)

	_, optsSecure := captureFactoryArgs(t, WithProfile(secure))
	_, optsPlaintext := captureFactoryArgs(t, WithProfile(plaintext))

	assert.Len(t, optsPlaintext, len(optsSecure)+1,
		"an http endpoint must add WithInsecurePlaintextConn reaching the factory")
}
