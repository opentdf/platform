package cmd

import (
	"context"
	"fmt"
	"github.com/opentdf/opentdf-v2-poc/sdk"
	"github.com/opentdf/opentdf-v2-poc/sdk/authorization"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"log/slog"
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

	//TODO - no SDK method for authorization service yet...so directly conn and create a new auth service client.
	conn, err := grpc.Dial(examplesConfig.PlatformEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	authServiceClient := authorization.NewAuthorizationServiceClient(conn)

	// request decision on "TRANSMIT" Action
	actions := []*authorization.Action{{
		Value: &authorization.Action_Standard{Standard: authorization.Action_STANDARD_ACTION_TRANSMIT},
	}}

	// model two groups of entities; user bob and user alice
	entityChains := []*authorization.EntityChain{{
		Id:       "ec1", //ec1 is an arbitrary tracking id to match results to request
		Entities: []*authorization.Entity{{EntityType: &authorization.Entity_EmailAddress{EmailAddress: "bob@example.org"}}},
	}, {
		Id:       "ec2", //ec2 is an arbitrary tracking id to match results to request
		Entities: []*authorization.Entity{{EntityType: &authorization.Entity_UserName{UserName: "alice@example.org"}}},
	}}

	// TODO Get attribute value ids
	tradeSecretAttributeValueId := "replaceme"
	openAttributeValueId := "Open"

	slog.Info("Getting decision for bob and alice for transmit action on resource set with trade secret and resource" +
		" set with trade secret + open attribute values")
	//
	drs := make([]*authorization.DecisionRequest, 0)
	drs = append(drs, &authorization.DecisionRequest{
		Actions:      actions,
		EntityChains: entityChains,
		ResourceAttributes: []*authorization.ResourceAttributes{
			{Id: "request-set-1", AttributeId: []string{tradeSecretAttributeValueId}},                        // request-set-1 is arbitrary tracking id
			{Id: "request-set-2", AttributeId: []string{tradeSecretAttributeValueId, openAttributeValueId}}}, // request-set-2 is arbitrary tracking id
	})

	decisionRequest := &authorization.GetDecisionsRequest{DecisionRequests: drs}
	slog.Info(fmt.Sprintf("Submitting decision request: %s", protojson.Format(decisionRequest)))
	decisionResponse, err := authServiceClient.GetDecisions(context.Background(), decisionRequest)
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
