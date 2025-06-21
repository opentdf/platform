package cmd

import (
	"context"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/authorization"
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

	// request decision on "read" Action
	actions := []*policy.Action{{
		Name: "read",
	}}

	// model two groups of entities; user bob and user alice
	entityChains := []*authorization.EntityChain{{
		Id: "ec1", // ec1 is an arbitrary tracking id to match results to request
		Entities: []*authorization.Entity{{
			EntityType: &authorization.Entity_EmailAddress{EmailAddress: "bob@example.org"},
			Category:   authorization.Entity_CATEGORY_SUBJECT,
		}},
	}, {
		Id: "ec2", // ec2 is an arbitrary tracking id to match results to request
		Entities: []*authorization.Entity{{
			EntityType: &authorization.Entity_UserName{UserName: "alice@example.org"},
			Category:   authorization.Entity_CATEGORY_SUBJECT,
		}},
	}}

	tradeSecretAttributeValueFqn := "https://namespace.com/attr/attr_name/value/replaceme" //nolint: gosec // TODO Get attribute value ids
	openAttributeValueFqn := "https://open.io/attr/attr_name/value/open"

	slog.Info("Getting decision for bob and alice for transmit action on resource set with trade secret and resource" +
		" set with trade secret + open attribute values")
	//
	drs := make([]*authorization.DecisionRequest, 0)
	drs = append(drs, &authorization.DecisionRequest{
		Actions:      actions,
		EntityChains: entityChains,
		ResourceAttributes: []*authorization.ResourceAttribute{
			{AttributeValueFqns: []string{tradeSecretAttributeValueFqn, openAttributeValueFqn}},
		},
	})

	decisionRequest := &authorization.GetDecisionsRequest{DecisionRequests: drs}
	//nolint:sloglint // safe to log request in example code
	slog.Info("submitting decision", slog.String("request", protojson.Format(decisionRequest)))
	decisionResponse, err := s.Authorization.GetDecisions(context.Background(), decisionRequest)
	if err != nil {
		return err
	}
	slog.Info("received decision response", slog.String("response", protojson.Format(decisionResponse)))

	// map response back to entity chain id
	decisionsByEntityChain := make(map[string]*authorization.DecisionResponse)
	for _, dr := range decisionResponse.GetDecisionResponses() {
		decisionsByEntityChain[dr.GetEntityChainId()] = dr
	}

	slog.Info("decision for bob", slog.String("decision", protojson.Format(decisionsByEntityChain["ec1"])))
	slog.Info("decision for alice", slog.String("decision", protojson.Format(decisionsByEntityChain["ec2"])))
	return nil
}

func init() {
	ExamplesCmd.AddCommand(AuthorizationExampleCmd)
}
