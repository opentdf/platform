package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/arkavo-org/opentdf-platform/protocol/go/policy"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/attributes"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/namespaces"
	"github.com/arkavo-org/opentdf-platform/sdk"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var AttributesExampleCmd = &cobra.Command{
	Use:   "attributes",
	Short: "Example usage for attributes service",
	RunE: func(cmd *cobra.Command, args []string) error {
		examplesConfig := *(cmd.Context().Value(RootConfigKey).(*ExampleConfig))
		return attributesExample(&examplesConfig)
	},
}

func init() {
	ExamplesCmd.AddCommand(AttributesExampleCmd)
}

func attributesExample(examplesConfig *ExampleConfig) error {
	s, err := sdk.New(examplesConfig.PlatformEndpoint, sdk.WithInsecureConn())
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		return err
	}
	defer s.Close()

	var exampleNamespace *policy.Namespace
	slog.Info("listing namespaces")
	listResp, err := s.Namespaces.ListNamespaces(context.Background(), &namespaces.ListNamespacesRequest{})
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("found %d namespaces", len(listResp.Namespaces)))
	for _, ns := range listResp.GetNamespaces() {
		slog.Info(fmt.Sprintf("existing namespace; name: %s, id: %s", ns.Name, ns.Id))
		if ns.Name == "example" {
			exampleNamespace = ns
		}
	}

	if exampleNamespace == nil {
		slog.Info("creating new namespace")
		resp, err := s.Namespaces.CreateNamespace(context.Background(), &namespaces.CreateNamespaceRequest{
			Name: "example",
		})
		if err != nil {
			return err
		}
		exampleNamespace = resp.Namespace
	}

	slog.Info("creating new attribute with hierarchy rule")
	_, err = s.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Name:        "IntellectualProperty",
		NamespaceId: exampleNamespace.Id,
		Rule:        *policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY.Enum(),
		// Values: []*attributes.ValueCreateUpdate{
		// 	{Value: "TradeSecret"},
		// 	{Value: "Proprietary"},
		// 	{Value: "BusinessSensitive"},
		// 	{Value: "Open"},
		// },
	})
	if err != nil {
		if returnStatus, ok := status.FromError(err); ok && returnStatus.Code() == codes.AlreadyExists {
			slog.Info("attribute already exists")
		} else {
			slog.Error("could not create attribute", slog.String("error", err.Error()))
			return err
		}
	} else {
		slog.Info("attribute created")
	}

	allAttr, err := s.Attributes.ListAttributes(context.Background(), &attributes.ListAttributesRequest{})
	if err != nil {
		slog.Error("could not list attributes", slog.String("error", err.Error()))
		return err
	}
	slog.Info(fmt.Sprintf("list attributes response: %s", protojson.Format(allAttr)))
	return nil
}
