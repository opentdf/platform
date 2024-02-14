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
		Id:       "ec1",
		Entities: []*authorization.Entity{{EntityType: &authorization.Entity_EmailAddress{EmailAddress: "bob@example.org"}}},
	}, {
		Id:       "ec2",
		Entities: []*authorization.Entity{{EntityType: &authorization.Entity_UserName{UserName: "alice@example.org"}}},
	}}

	// Get attribute ids

	drs := make([]*authorization.DecisionRequest, 0)
	drs = append(drs, &authorization.DecisionRequest{
		Actions:      actions,
		EntityChains: entityChains,
		ResourceAttributes: []*authorization.ResourceAttributes{{Id: "request-set-1", AttributeId: []string{"http://www.example.org/attr/foo/value/bar"}},
			{Id: "request-set-2", AttributeId: []string{"http://www.example.org/attr/foo/value/bar", "http://www.example.org/attr/color/value/red"}}},
	})

	decisionRequest := &authorization.GetDecisionsRequest{DecisionRequests: drs}
	slog.Info(fmt.Sprintf("Submitting decision request: %s", protojson.Format(decisionRequest)))
	decisionResponse, err := authServiceClient.GetDecisions(context.Background(), decisionRequest)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("Received decision response: %s", protojson.Format(decisionResponse)))
	return nil
}

func init() {
	ExamplesCmd.AddCommand(AuthorizationExampleCmd)
}
