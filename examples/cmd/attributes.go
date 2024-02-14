package cmd

import (
	"context"
	"github.com/opentdf/opentdf-v2-poc/sdk/namespaces"
	"github.com/spf13/cobra"
	"log/slog"
	"strconv"

	"github.com/opentdf/opentdf-v2-poc/sdk"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
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

	resp, err := s.Namespaces.CreateNamespace(context.Background(), &namespaces.CreateNamespaceRequest{
		Name: "example",
	})

	if err != nil {
		return err
	}

	namespaceId := resp.GetNamespace().Id

	_, err = s.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Attribute: &attributes.AttributeCreateUpdate{
			Name:        "relto",
			NamespaceId: namespaceId,
			Rule:        *attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF.Enum(),
		},
	})
	if err != nil {
		slog.Error("could not create attribute", slog.String("error", err.Error()))
		return err
	}

	slog.Info("attribute created")

	allAttr, err := s.Attributes.ListAttributes(context.Background(), &attributes.ListAttributesRequest{})
	if err != nil {
		slog.Error("could not list attributes", slog.String("error", err.Error()))
		return err
	}
	for _, attr := range allAttr.Attributes {
		slog.Info("attribute", slog.String("id", attr.Id))
		slog.Info("attribute", slog.String("name", attr.Name))
		slog.Info("attribute", slog.String("rule", attr.Rule.String()))
		slog.Info("attribute", slog.Any("metadata", attr.Metadata))
		for i, val := range attr.Values {
			slog.Info("attribute: "+strconv.Itoa(i), slog.String("id", val.Id))
			slog.Info("attribute: "+strconv.Itoa(i), slog.String("value", val.Value))
			slog.Info("attribute: "+strconv.Itoa(i), slog.Any("members", val.Members))
			slog.Info("attribute: "+strconv.Itoa(i), slog.Any("metadata", val.Metadata))
		}
	}
	return nil
}
