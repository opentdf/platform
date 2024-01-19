package db

import (
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// Postgres specific statement builder
func newStatementBuilder() sq.StatementBuilderType {
	return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
}

func removeProtobufEnumPrefix(s string) string {
	// find the first instance of ENUM_
	if strings.Contains(s, "ENUM_") {
		// remove everything left of it
		return s[strings.Index(s, "ENUM_")+5:]
	}
	return s
}

func marshalPolicyMetadata(metadata *common.PolicyMetadataMutable) ([]byte, error) {
	if m, err := protojson.Marshal(metadata); err != nil {
		return nil, status.Error(codes.Internal, services.ErrCreatingResource)
	} else {
		return m, nil
	}
}
