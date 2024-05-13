package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var DataCmd = &cobra.Command{
	Use:   "create-data",
	Short: "Create test data",
	RunE: func(cmd *cobra.Command, args []string) error {
		testConfig := *(cmd.Context().Value(RootConfigKey).(*TestConfig))
		return createTestData(&testConfig)
	},
}

func init() {
	E2ECmd.AddCommand(DataCmd)
}

var attributesToMap = []string{
	"https://example.com/attr/language/value/english",
	"https://example.com/attr/color/value/red",
	"https://example.com/attr/cards/value/queen"}

func createTestData(testConfig *TestConfig) error {
	s, err := sdk.New(testConfig.PlatformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials(testConfig.ClientID,
			testConfig.ClientSecret, nil),
		sdk.WithTokenEndpoint(testConfig.TokenEndpoint))
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		return err
	}
	defer s.Close()

	// create namespace example.com
	var exampleNamespace *policy.Namespace
	slog.Info("listing namespaces")
	listResp, err := s.Namespaces.ListNamespaces(context.Background(), &namespaces.ListNamespacesRequest{})
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("found %d namespaces", len(listResp.Namespaces)))
	for _, ns := range listResp.GetNamespaces() {
		slog.Info(fmt.Sprintf("existing namespace; name: %s, id: %s", ns.Name, ns.Id))
		if ns.Name == "example.com" {
			exampleNamespace = ns
		}
	}

	if exampleNamespace == nil {
		slog.Info("creating new namespace")
		resp, err := s.Namespaces.CreateNamespace(context.Background(), &namespaces.CreateNamespaceRequest{
			Name: "example.com",
		})
		if err != nil {
			return err
		}
		exampleNamespace = resp.Namespace
	}

	slog.Info("##################################\n#######################################")

	// Create the attributes
	slog.Info("creating attribute language with allOf rule")
	_, err = s.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Name:        "language",
		NamespaceId: exampleNamespace.Id,
		Rule:        *policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF.Enum(),
		Values: []string{
			"english",
			"french",
			"spanish",
		},
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

	slog.Info("creating attribute color with anyOf rule")
	_, err = s.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Name:        "color",
		NamespaceId: exampleNamespace.Id,
		Rule:        *policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF.Enum(),
		Values: []string{
			"red",
			"green",
			"blue",
		},
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

	slog.Info("creating attribute cards with hierarchy rule")
	_, err = s.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Name:        "cards",
		NamespaceId: exampleNamespace.Id,
		Rule:        *policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY.Enum(),
		Values: []string{
			"king",
			"queen",
			"jack",
		},
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

	slog.Info("##################################\n#######################################")

	allAttr, err := s.Attributes.ListAttributes(context.Background(), &attributes.ListAttributesRequest{})
	if err != nil {
		slog.Error("could not list attributes", slog.String("error", err.Error()))
		return err
	}
	slog.Info(fmt.Sprintf("list attributes response: %s", protojson.Format(allAttr)))

	slog.Info("##################################\n#######################################")

	// get the attribute ids for the values were mapping to the client
	var attributeValueIDs []string
	fqnResp, err := s.Attributes.GetAttributeValuesByFqns(context.Background(), &attributes.GetAttributeValuesByFqnsRequest{
		Fqns:      attributesToMap,
		WithValue: &policy.AttributeValueSelector{},
	})
	if err != nil {
		slog.Error("get attribute values by fqn ", slog.String("error", err.Error()))
		return err
	}
	for _, attribute := range attributesToMap {
		attributeValueIDs = append(attributeValueIDs, fqnResp.GetFqnAttributeValues()[attribute].GetValue().GetId())
	}

	// create subject mappings
	slog.Info("creating subject mappings for client " + testConfig.ClientID)
	for _, attribute_id := range attributeValueIDs {
		_, err = s.SubjectMapping.CreateSubjectMapping(context.Background(), &subjectmapping.CreateSubjectMappingRequest{
			AttributeValueId: attribute_id,
			Actions: []*policy.Action{{Value: &policy.Action_Standard{
				Standard: policy.Action_StandardAction(policy.Action_STANDARD_ACTION_DECRYPT),
			}},
				{Value: &policy.Action_Standard{
					Standard: policy.Action_StandardAction(policy.Action_STANDARD_ACTION_TRANSMIT),
				}},
			},
			NewSubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{
				SubjectSets: []*policy.SubjectSet{
					{ConditionGroups: []*policy.ConditionGroup{
						{Conditions: []*policy.Condition{{
							SubjectExternalSelectorValue: ".clientId",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues:        []string{testConfig.ClientID},
						}},
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						},
					}},
				},
			},
		})
		if err != nil {
			if returnStatus, ok := status.FromError(err); ok && returnStatus.Code() == codes.AlreadyExists {
				slog.Info("subject mapping already exists")
			} else {
				slog.Error("could not create subject mapping ", slog.String("error", err.Error()))
				return err
			}
		} else {
			slog.Info("subject mapping created")
		}
	}

	allSubMaps, err := s.SubjectMapping.ListSubjectMappings(context.Background(), &subjectmapping.ListSubjectMappingsRequest{})
	if err != nil {
		slog.Error("could not list subject mappings", slog.String("error", err.Error()))
		return err
	}
	slog.Info(fmt.Sprintf("list subject mappings response: %s", protojson.Format(allSubMaps)))

	return nil
}
