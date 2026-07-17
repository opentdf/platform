package handlers

import (
	"errors"
	"log/slog"

	"github.com/opentdf/platform/otdfctl/pkg/auth"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/otdfctl/pkg/utils"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/sdk"
)

var (
	SDK *sdk.SDK

	ErrUnauthenticated = errors.New("unauthenticated")
)

type Handler struct {
	sdk              *sdk.SDK
	platformEndpoint string
}

type handlerOpts struct {
	endpoint    string
	TLSNoVerify bool

	profile *profiles.OtdfctlProfileStore

	sdkOpts []sdk.Option

	hooks []Hook
}

// HandlerOption configures a Handler during construction. Callers compose
// options by passing them to New; extension points that want to defer their
// SDK-option contribution until profile resolution is complete should use
// WithHook rather than WithSDKOpts.
type HandlerOption func(handlerOpts) handlerOpts

// Hook is the umbrella type for handler-construction hooks. Concrete hook
// variants (PreSDKHook, and any future point-specific hooks added later)
// implement Hook so callers can pass them uniformly through WithHook and
// common.NewHandler. New hook points are added by declaring a new named
// callback type, giving it an isHandlerHook receiver, and extending the
// applyHooks dispatch switch — no new exported registration function is
// needed.
type Hook interface {
	isHandlerHook()
}

// PreSDKHookContext exposes the resolved handler configuration to a
// PreSDKHook callback so it can decide which SDK options to contribute
// (for example, an interceptor that only attaches for a specific endpoint
// or profile).
type PreSDKHookContext struct {
	Endpoint    string
	TLSNoVerify bool
	Profile     *profiles.OtdfctlProfileStore
}

// PreSDKHook runs after every HandlerOption has been applied and before
// sdk.New is called. It returns additional SDK options that get appended to
// the final options list. Multiple PreSDKHooks compose in registration
// order and each sees the same fully-resolved PreSDKHookContext.
type PreSDKHook func(PreSDKHookContext) []sdk.Option

func (PreSDKHook) isHandlerHook() {}

func WithEndpoint(endpoint string, tlsNoVerify bool) HandlerOption {
	return func(c handlerOpts) handlerOpts {
		c.endpoint = endpoint
		c.TLSNoVerify = tlsNoVerify
		return c
	}
}

func WithProfile(profile *profiles.OtdfctlProfileStore) HandlerOption {
	return func(c handlerOpts) handlerOpts {
		if profile == nil {
			return c
		}
		c.profile = profile
		c.endpoint = profile.GetEndpoint()
		c.TLSNoVerify = profile.GetTLSNoVerify()

		// get sdk opts
		opts, err := auth.GetSDKAuthOptionFromProfile(profile)
		if err != nil {
			return c
		}
		c.sdkOpts = append(c.sdkOpts, opts)

		return c
	}
}

func WithSDKOpts(opts ...sdk.Option) HandlerOption {
	return func(c handlerOpts) handlerOpts {
		c.sdkOpts = opts
		return c
	}
}

// WithHook registers one or more Hooks that run during handler construction
// after every HandlerOption has been applied and before the SDK is built.
// Nil entries are ignored so a caller cannot accidentally register a hook
// that would panic on execution.
func WithHook(hooks ...Hook) HandlerOption {
	return func(c handlerOpts) handlerOpts {
		for _, h := range hooks {
			if h == nil {
				continue
			}
			c.hooks = append(c.hooks, h)
		}
		return c
	}
}

// applyHooks dispatches every registered Hook to the callback attached to
// its concrete variant. Each variant gets its own context type derived from
// the resolved handler configuration, and any SDK options the hook returns
// are appended to o.sdkOpts. Broken out of New so the extension point is
// directly testable without touching the network. Unknown Hook variants
// are dropped so future variants added upstream do not panic older code
// paths that have not yet been updated to dispatch them.
func applyHooks(o handlerOpts) handlerOpts {
	if len(o.hooks) == 0 {
		return o
	}
	for _, h := range o.hooks {
		// Switch anticipates future Hook variants (see Hook doc) even though
		// only PreSDKHook exists today, so gocritic's single-case suggestion
		// would force a rewrite the moment a second variant lands.
		//nolint:gocritic // extensible dispatch, keep switch
		switch v := h.(type) {
		case PreSDKHook:
			// A typed-nil function value stored in the Hook interface
			// passes the untyped-nil filter inside WithHook, so guard
			// per-variant here before invoking the callback.
			if v == nil {
				continue
			}
			ctx := PreSDKHookContext{
				Endpoint:    o.endpoint,
				TLSNoVerify: o.TLSNoVerify,
				Profile:     o.profile,
			}
			o.sdkOpts = append(o.sdkOpts, v(ctx)...)
		}
	}
	return o
}

// Creates a new handler wrapping the SDK, which is authenticated through the cached client-credentials flow tokens
func New(opts ...HandlerOption) (Handler, error) {
	var o handlerOpts
	for _, f := range opts {
		o = f(o)
	}

	o = applyHooks(o)

	u, err := utils.NormalizeEndpoint(o.endpoint)
	if err != nil {
		return Handler{}, err
	}

	// get auth
	authSDKOpt, err := auth.GetSDKAuthOptionFromProfile(o.profile)
	if err != nil {
		return Handler{}, err
	}

	defaultSDKOpts := []sdk.Option{
		authSDKOpt,
		sdk.WithConnectionValidation(),
		sdk.WithLogger(slog.Default()),
	}
	if o.TLSNoVerify {
		defaultSDKOpts = append(defaultSDKOpts, sdk.WithInsecureSkipVerifyConn())
	}

	if u.Scheme == "http" {
		defaultSDKOpts = append(defaultSDKOpts, sdk.WithInsecurePlaintextConn())
	}
	o.sdkOpts = append(defaultSDKOpts, o.sdkOpts...)

	s, err := sdk.New(u.String(), o.sdkOpts...)
	if err != nil {
		return Handler{}, err
	}

	return Handler{
		sdk:              s,
		platformEndpoint: o.endpoint,
	}, nil
}

func (h Handler) Close() error {
	return h.sdk.Close()
}

func (h Handler) Direct() *sdk.SDK {
	return h.sdk
}

// Replace all labels in the metadata
func (h Handler) WithReplaceLabelsMetadata(metadata *common.MetadataMutable, labels map[string]string) func(*common.MetadataMutable) *common.MetadataMutable {
	return func(*common.MetadataMutable) *common.MetadataMutable {
		nextMetadata := &common.MetadataMutable{
			Labels: labels,
		}
		return nextMetadata
	}
}

// Append a label to the metadata
func (h Handler) WithLabelMetadata(metadata *common.MetadataMutable, key, value string) func(*common.MetadataMutable) *common.MetadataMutable {
	return func(*common.MetadataMutable) *common.MetadataMutable {
		labels := metadata.GetLabels()
		labels[key] = value
		nextMetadata := &common.MetadataMutable{
			Labels: labels,
		}
		return nextMetadata
	}
}

// func buildMetadata(metadata *common.MetadataMutable, fns ...func(*common.MetadataMutable) *common.MetadataMutable) *common.MetadataMutable {
// 	if metadata == nil {
// 		metadata = &common.MetadataMutable{}
// 	}
// 	if len(fns) == 0 {
// 		return metadata
// 	}
// 	for _, fn := range fns {
// 		metadata = fn(metadata)
// 	}
// 	return metadata
// }
