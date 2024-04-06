package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/arkavo-org/opentdf-platform/protocol/go/authorization"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy"
	"github.com/arkavo-org/opentdf-platform/sdk"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

var AuthorizationExampleCmd = &cobra.Command{
	Use:   "authorization",
	Short: "Example usage for authorization service",
	RunE: func(cmd *cobra.Command, args []string) error {
		examplesConfig := *(cmd.Context().Value(RootConfigKey).(*ExampleConfig))
		return authorizationExamples(&examplesConfig)
	},
}

func authorizationExamples(examplesConfig *ExampleConfig) error {
	s, err := sdk.New(examplesConfig.PlatformEndpoint, sdk.WithInsecureConn())
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		return err
	}
	defer s.Close()

	// request decision on "TRANSMIT" Action
	actions := []*policy.Action{{
		Value: &policy.Action_Standard{Standard: policy.Action_STANDARD_ACTION_TRANSMIT},
	}}

	// model two groups of entities; user bob and user alice
	entityChains := []*authorization.EntityChain{{
		Id:       "ec1", // ec1 is an arbitrary tracking id to match results to request
		Entities: []*authorization.Entity{{EntityType: &authorization.Entity_EmailAddress{EmailAddress: "bob@example.org"}}},
	}, {
		Id:       "ec2", // ec2 is an arbitrary tracking id to match results to request
		Entities: []*authorization.Entity{{EntityType: &authorization.Entity_UserName{UserName: "alice@example.org"}}},
	}}

	// TODO Get attribute value ids
	tradeSecretAttributeValueFqn := "https://namespace.com/attr/attr_name/value/replaceme"
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
	slog.Info(fmt.Sprintf("Submitting decision request: %s", protojson.Format(decisionRequest)))
	decisionResponse, err := s.Authorization.GetDecisions(context.Background(), decisionRequest)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("Received decision response: %s", protojson.Format(decisionResponse)))

	// map response back to entity chain id
	decisionsByEntityChain := make(map[string]*authorization.DecisionResponse)
	for _, dr := range decisionResponse.DecisionResponses {
		decisionsByEntityChain[dr.EntityChainId] = dr
	}

	slog.Info(fmt.Sprintf("decision for bob: %s", protojson.Format(decisionsByEntityChain["ec1"])))
	slog.Info(fmt.Sprintf("decision for alice: %s", protojson.Format(decisionsByEntityChain["ec2"])))
	return nil
}

func init() {
	ExamplesCmd.AddCommand(AuthorizationExampleCmd)
}
