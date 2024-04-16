package access

import (
	"context"

	"github.com/opentdf/backend-go/internal/version"
)

func (p *Provider) Info(_ context.Context, in *InfoRequest) (*InfoResponse, error) {
	v := version.GetVersion()
	return &InfoResponse{Version: v.Version}, nil
}
