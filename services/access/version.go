package access

import (
	"context"

	accesspb "github.com/opentdf/platform/protocol/go/access"
)

const (
	Version = "0.1.0"
)

// TODO
type Stat struct {
	Version     string `json:"version"`
	VersionLong string `json:"versionLong"`
	BuildTime   string `json:"buildTime"`
}

func (p *Provider) Info(_ context.Context, in *accesspb.InfoRequest) (*accesspb.InfoResponse, error) {
	return &accesspb.InfoResponse{Version: Version}, nil
}
