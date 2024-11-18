package config

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/opentdf/platform/protocol/go/config"
	"github.com/opentdf/platform/service/config/db"
	"github.com/opentdf/platform/service/config/db/migrations"
	otdfDb "github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var Migrations *embed.FS

func init() {
	Migrations = &migrations.FS
}

type ConfigService struct {
	queries *db.Queries
}

func New(dbClient *otdfDb.Client) *ConfigService {
	return &ConfigService{
		queries: db.New(dbClient.Pgx),
	}
}

func (s *ConfigService) LoadConfig(ctx context.Context, svcNamespace string, pb protoreflect.ProtoMessage) error {
	err := s.loadFromDB(ctx, svcNamespace, pb)
	if err == nil {
		return nil
	}

	slog.Info("failed to load config from database, loading from defaults")

	return s.loadFromDefaults(ctx, svcNamespace, pb)
}

func (s *ConfigService) loadFromDefaults(ctx context.Context, svcNamespace string, pb protoreflect.ProtoMessage) error {
	for i := 0; i < pb.ProtoReflect().Descriptor().Fields().Len(); i++ {
		field := pb.ProtoReflect().Descriptor().Fields().Get(i)
		meta := proto.GetExtension(field.Options(), config.E_Meta).(*config.FieldMetadata)

		switch fieldType := field.Message().Name(); fieldType {
		case "StringField":
			value := config.StringField{Value: meta.Default}
			pb.ProtoReflect().Set(field, protoreflect.ValueOfMessage(value.ProtoReflect()))
		case "BoolField":
			boolValue, err := strconv.ParseBool(meta.Default)
			value := config.BoolField{Value: boolValue}
			if err != nil {
				return fmt.Errorf("parse bool value failed, field: %s, value: %s", field.FullName(), meta.Default)
			}
			pb.ProtoReflect().Set(field, protoreflect.ValueOfMessage(value.ProtoReflect()))
		case "IntField":
			intValue, err := strconv.Atoi(meta.Default)
			value := config.IntField{Value: int32(intValue)}
			if err != nil {
				return fmt.Errorf("parse int value failed, field: %s, value: %s", field.FullName(), meta.Default)
			}
			pb.ProtoReflect().Set(field, protoreflect.ValueOfMessage(value.ProtoReflect()))
		default:
			return fmt.Errorf("unsupported field type: %s", fieldType)
		}
	}

	pbBytes, err := protojson.Marshal(pb)
	if err != nil {
		return fmt.Errorf("failed to marshal config to json: %w", err)
	}

	err = s.queries.CreateConfig(ctx, db.CreateConfigParams{
		Service: svcNamespace,
		Version: "v1",
		Value:   pbBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to create config in db for service [%s]: %w", svcNamespace, err)
	}

	return nil
}

func (s *ConfigService) loadFromDB(ctx context.Context, svcNamespace string, pb protoreflect.ProtoMessage) error {
	cfg, err := s.queries.GetConfig(ctx, svcNamespace)
	if err != nil {
		return fmt.Errorf("failed to get config from db for service [%s]: %w", svcNamespace, err)
	}

	if err = protojson.Unmarshal(cfg.Value, pb); err != nil {
		return fmt.Errorf("failed to unmarshal config from db for service [%s]: %w", svcNamespace, err)
	}

	return nil
}
