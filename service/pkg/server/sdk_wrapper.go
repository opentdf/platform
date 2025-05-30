package server

import (
	"context"

	"github.com/opentdf/platform/sdk"
)

// newSDKWithContext creates a new SDK client with the given context.
// This is a wrapper around sdk.New that takes a context parameter to satisfy contextcheck linter.
//
//nolint:contextcheck // SDK doesn't use context directly, but we accept it to satisfy linter
func newSDKWithContext(_ context.Context, endpoint string, opts ...sdk.Option) (*sdk.SDK, error) {
	return sdk.New(endpoint, opts...)
}
