package access

import (
	"context"

	"github.com/opentdf/platform/kas/internal/version"
	accesspb "github.com/opentdf/platform/protocol/go/access"
)

func (p *Provider) Info(_ context.Context, in *accesspb.InfoRequest) (*accesspb.InfoResponse, error) {
	v := version.GetVersion()
	return &accesspb.InfoResponse{Version: v.Version}, nil
}
