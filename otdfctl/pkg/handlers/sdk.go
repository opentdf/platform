package handlers

import (
	"errors"
	"log/slog"

	"github.com/opentdf/otdfctl/pkg/auth"
	"github.com/opentdf/otdfctl/pkg/profiles"
	"github.com/opentdf/otdfctl/pkg/utils"
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
}

type handlerOptsFunc func(handlerOpts) handlerOpts

func WithEndpoint(endpoint string, tlsNoVerify bool) handlerOptsFunc {
	return func(c handlerOpts) handlerOpts {
		c.endpoint = endpoint
		c.TLSNoVerify = tlsNoVerify
		return c
	}
}

func WithProfile(profile *profiles.OtdfctlProfileStore) handlerOptsFunc {
	return func(c handlerOpts) handlerOpts {
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

func WithSDKOpts(opts ...sdk.Option) handlerOptsFunc {
	return func(c handlerOpts) handlerOpts {
		c.sdkOpts = opts
		return c
	}
}

// Creates a new handler wrapping the SDK, which is authenticated through the cached client-credentials flow tokens
func New(opts ...handlerOptsFunc) (Handler, error) {
	var o handlerOpts
	for _, f := range opts {
		o = f(o)
	}

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
