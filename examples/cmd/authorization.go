package cmd

import (
	"context"
	"log/slog"

	authorizationv2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

var AuthorizationExampleCmd = &cobra.Command{
	Use:   "authorization",
	Short: "Example usage for authorization service",
	RunE: func(_ *cobra.Command, _ []string) error {
		return authorizationExamples()
	},
}

func authorizationExamples() error {
	s, err := sdk.New(platformEndpoint, sdk.WithInsecurePlaintextConn())
	if err != nil {
		slog.Error("could not connect", slog.Any("error", err))
		return err
	}
	defer s.Close()

	entityChains := []*entity.EntityChain{
		{
			EphemeralId: "ec1",
			Entities: []*entity.Entity{
				{
					EphemeralId: "bob",
					EntityType:  &entity.Entity_EmailAddress{EmailAddress: "bob@example.org"},
					Category:    entity.Entity_CATEGORY_SUBJECT,
				},
			},
		},
		{
			EphemeralId: "ec2",
			Entities: []*entity.Entity{
				{
					EphemeralId: "alice",
					EntityType:  &entity.Entity_UserName{UserName: "alice@example.org"},
					Category:    entity.Entity_CATEGORY_SUBJECT,
				},
			},
		},
	}

	tradeSecretAttributeValueFQN := "https://namespace.com/attr/attr_name/value/replaceme" //nolint:gosec // example attribute, not a credential
	openAttributeValueFQN := "https://open.io/attr/attr_name/value/open"
	resource := &authorizationv2.Resource{
		EphemeralId: "resource-1",
		Resource: &authorizationv2.Resource_AttributeValues_{
			AttributeValues: &authorizationv2.Resource_AttributeValues{
				Fqns: []string{tradeSecretAttributeValueFQN, openAttributeValueFQN},
			},
		},
	}

	requests := make([]*authorizationv2.GetDecisionMultiResourceRequest, 0, len(entityChains))
	for _, entityChain := range entityChains {
		requests = append(requests, &authorizationv2.GetDecisionMultiResourceRequest{
			EntityIdentifier: &authorizationv2.EntityIdentifier{
				Identifier: &authorizationv2.EntityIdentifier_EntityChain{EntityChain: entityChain},
			},
			Action:    &policy.Action{Name: "read"},
			Resources: []*authorizationv2.Resource{resource},
		})
	}

	decisionRequest := &authorizationv2.GetDecisionBulkRequest{DecisionRequests: requests}
	//nolint:sloglint // safe to log request in example code
	slog.Info("submitting decision", slog.String("request", protojson.Format(decisionRequest)))
	decisionResponse, err := s.AuthorizationV2.GetDecisionBulk(context.Background(), decisionRequest)
	if err != nil {
		return err
	}
	slog.Info("received decision response", slog.String("response", protojson.Format(decisionResponse)))
	return nil
}

func init() {
	ExamplesCmd.AddCommand(AuthorizationExampleCmd)
}
