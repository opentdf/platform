package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v2"
)

// create the config struct types

type PolicyConfigData struct {
	PlatformEndpoint     string            `yaml:"platformEndpoint" json:"platformEndpoint"`
	Namespaces           []NamespaceConfig `yaml:"namespaces" json:"namespaces"`
	SubjectConditionSets []SCSConfig       `yaml:"subject_condition_sets"  json:"subject_condition_sets"`
}

type NamespaceConfig struct {
	Name       string `yaml:"name" json:"name"`
	Id         string
	Attributes []AttributeConfig `yaml:"attributes" json:"attributes"`
}

type AttributeConfig struct {
	Name     string `yaml:"name" json:"name"`
	Rule     string `yaml:"rule" json:"rule"`
	Id       string
	Values   []string `yaml:"values" json:"values"`
	ValueIds map[string]string
}

type SCSConfig struct {
	SubjectSets     []SubjectSetConfig `yaml:"subject_sets" json:"subject_sets"`
	Id              string
	SubjectMappings []SubjectMappingConfig `yaml:"subject_mappings" json:"subject_mappings"`
}

type SubjectSetConfig struct {
	ConditionGroups []ConditionGroupConfig `yaml:"condition_groups" json:"condition_groups"`
}

type ConditionGroupConfig struct {
	Operator   string            `yaml:"operator" json:"operator"`
	Conditions []ConditionConfig `yaml:"conditions" json:"conditions"`
}

type ConditionConfig struct {
	Operator              string   `yaml:"operator" json:"operator"`
	SubjectExternalField  string   `yaml:"subject_external_field" json:"subject_external_field"`
	SubjectExternalValues []string `yaml:"subject_external_values"  json:"subject_external_values"`
}

type SubjectMappingConfig struct {
	Actions        []ActionConfig       `yaml:"actions" json:"actions"`
	AttributeValue AttributeValueConfig `yaml:"attribute_value" json:"attribute_value"`
}

type ActionConfig struct {
	Standard string `yaml:"standard" json:"standard"`
}

type AttributeValueConfig struct {
	Namespace string `yaml:"namespace" json:"namespace"`
	Attribute string `yaml:"attribute" json:"attribute"`
	Value     string `yaml:"value" json:"value"`
}

// ability to load config from yaml

var (
	provDataFilename = "./cmd/simple_policy_data.yaml"
	policyConfigData PolicyConfigData
)

var provisionDataFromConfigCmd = &cobra.Command{
	Use:   "custom-policy-data",
	Short: "Provision custom policy data",
	RunE: func(cmd *cobra.Command, args []string) error {
		dataFilename, _ := cmd.Flags().GetString(provDataFilename)

		LoadConfigData(dataFilename)
		ctx := context.Background()

		// do the work

		// initialize sdk
		s, err := sdk.New(policyConfigData.PlatformEndpoint, sdk.WithInsecureConn())
		if err != nil {
			slog.Error("could not connect", slog.String("error", err.Error()))
			return err
		}
		defer s.Close()

		// create the namespaces, store the ids
		for ni, nsConfig := range policyConfigData.Namespaces {
			// create the namespace
			id, err := createNamespace(s, ctx, nsConfig.Name)
			if err != nil {
				return err
			}
			policyConfigData.Namespaces[ni].Id = id

			for ai, attrConfig := range policyConfigData.Namespaces[ni].Attributes {
				// create the attribute definitions
				id, err = createAttribute(s, ctx, policyConfigData.Namespaces[ni].Id, attrConfig)
				if err != nil {
					return err
				}
				policyConfigData.Namespaces[ni].Attributes[ai].Id = id
				for _, value := range policyConfigData.Namespaces[ni].Attributes[ai].Values {
					// create the value
					id, err = createAttributeValue(s, ctx, policyConfigData.Namespaces[ni].Attributes[ai].Id, value)
					if err != nil {
						return err
					}
					policyConfigData.Namespaces[ni].Attributes[ai].ValueIds = make(map[string]string)
					policyConfigData.Namespaces[ni].Attributes[ai].ValueIds[value] = id
				}
			}

		}

		//create the subject condition sets
		for sci, scsConfig := range policyConfigData.SubjectConditionSets {
			id, err := createSubjectConditionSet(s, ctx, scsConfig)
			if err != nil {
				return err
			}
			policyConfigData.SubjectConditionSets[sci].Id = id

			// create the mapping
			for _, smConfig := range policyConfigData.SubjectConditionSets[sci].SubjectMappings {
				_, err := createSubjectMapping(s, ctx, policyConfigData.SubjectConditionSets[sci].Id, smConfig)
				if err != nil {
					return err
				}
			}
		}

		return nil
	},
}

func createSubjectMapping(s *sdk.SDK, ctx context.Context, scsId string, smConfig SubjectMappingConfig) (string, error) {
	slog.Info("creating subject mapping")
	// lookup attribute value
	var attrId string
	for _, ns := range policyConfigData.Namespaces {
		if ns.Name == smConfig.AttributeValue.Namespace {
			for _, attr := range ns.Attributes {
				if attr.Name == smConfig.AttributeValue.Attribute {
					val, ok := attr.ValueIds[smConfig.AttributeValue.Value]
					if ok {
						attrId = val
					}
				}
			}
		}
	}
	if attrId == "" {
		return "", errors.New("could not find attribute id")
	}

	req := &subjectmapping.CreateSubjectMappingRequest{
		ExistingSubjectConditionSetId: scsId,
		AttributeValueId:              attrId,
		Actions:                       []*policy.Action{},
	}
	for _, act := range smConfig.Actions {
		req.Actions = append(req.Actions, &policy.Action{
			Value: &policy.Action_Standard{Standard: policy.Action_StandardAction(policy.Action_StandardAction_value[act.Standard])},
		})
	}

	res, err := s.SubjectMapping.CreateSubjectMapping(ctx, req)

	var smId string
	if err != nil {
		if returnStatus, ok := status.FromError(err); ok && returnStatus.Code() == codes.AlreadyExists {
			slog.Info("Subject mapping set already exists")
			// list by name
			allSms, err := s.SubjectMapping.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{})
			if err != nil {
				slog.Error("could not list subject mapping consition sets", slog.String("error", err.Error()))
				return "", err
			}
			for _, sm := range allSms.GetSubjectMappings() {
				if (sm.SubjectConditionSet.Id == req.ExistingSubjectConditionSetId) &&
					(sm.AttributeValue.Id == req.AttributeValueId) &&
					(reflect.DeepEqual(sm.Actions, req.Actions)) {
					smId = sm.Id
					break
				}
			}
			if smId == "" {
				slog.Error("Already exists code returned on subject mapping creation but could not find subject mapping in list")
				return "", errors.New("already exists code returned on subject mapping creation but could not find subject mapping in list")
			}
		} else {
			slog.Error("could not create subject mapping", slog.String("error", err.Error()))
			return "", err
		}
	} else {
		slog.Info("subject mapping created")
		smId = res.SubjectMapping.Id
	}
	return smId, nil
}

func createSubjectConditionSet(s *sdk.SDK, ctx context.Context, scsConfig SCSConfig) (string, error) {
	slog.Info("creating subject condition set")
	req := &subjectmapping.CreateSubjectConditionSetRequest{SubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{SubjectSets: []*policy.SubjectSet{}}}
	for _, subset := range scsConfig.SubjectSets {
		ss := policy.SubjectSet{
			ConditionGroups: []*policy.ConditionGroup{},
		}
		for _, condgr := range subset.ConditionGroups {
			rule := policy.ConditionBooleanTypeEnum(policy.ConditionBooleanTypeEnum_value[condgr.Operator])
			cg := policy.ConditionGroup{
				Conditions:      []*policy.Condition{},
				BooleanOperator: rule,
			}
			for _, cond := range condgr.Conditions {
				rule := policy.SubjectMappingOperatorEnum(policy.SubjectMappingOperatorEnum_value[cond.Operator])
				c := policy.Condition{
					SubjectExternalField:  cond.SubjectExternalField,
					SubjectExternalValues: cond.SubjectExternalValues,
					Operator:              rule,
				}
				cg.Conditions = append(cg.Conditions, &c)
			}
			ss.ConditionGroups = append(ss.ConditionGroups, &cg)
		}
		req.SubjectConditionSet.SubjectSets = append(req.SubjectConditionSet.SubjectSets, &ss)
	}
	// iterate through to create request
	res, err := s.SubjectMapping.CreateSubjectConditionSet(ctx, req)

	var scsId string
	if err != nil {
		if returnStatus, ok := status.FromError(err); ok && returnStatus.Code() == codes.AlreadyExists {
			slog.Info("Subject condition set already exists")
			// list by name
			allScs, err := s.SubjectMapping.ListSubjectConditionSets(ctx, &subjectmapping.ListSubjectConditionSetsRequest{})
			if err != nil {
				slog.Error("could not list subject mapping consition sets", slog.String("error", err.Error()))
				return "", err
			}
			for _, scs := range allScs.GetSubjectConditionSets() {
				if reflect.DeepEqual(scs.SubjectSets, req.SubjectConditionSet.SubjectSets) {
					scsId = scs.Id
					break
				}
			}
			if scsId == "" {
				slog.Error("Already exists code returned on subject condition set creation but could not find subject condition set in list")
				return "", errors.New("already exists code returned on subject condition set creation but could not find subject condition set in list")
			}
		} else {
			slog.Error("could not create subject condition set", slog.String("error", err.Error()))
			return "", err
		}
	} else {
		slog.Info("subject condition set created")
		scsId = res.SubjectConditionSet.Id
	}
	return scsId, nil
}

func createNamespace(s *sdk.SDK, ctx context.Context, name string) (string, error) {
	var exampleNamespace *policy.Namespace
	slog.Info("listing namespaces")
	listResp, err := s.Namespaces.ListNamespaces(ctx, &namespaces.ListNamespacesRequest{})
	if err != nil {
		return "", err
	}
	slog.Info(fmt.Sprintf("found %d namespaces", len(listResp.Namespaces)))
	for _, ns := range listResp.GetNamespaces() {
		slog.Info(fmt.Sprintf("existing namespace; name: %s, id: %s", ns.Name, ns.Id))
		if ns.Name == name {
			exampleNamespace = ns
		}
	}

	if exampleNamespace == nil {
		slog.Info("creating new namespace")
		resp, err := s.Namespaces.CreateNamespace(ctx, &namespaces.CreateNamespaceRequest{
			Name: name,
		})
		if err != nil {
			return "", err
		}
		exampleNamespace = resp.Namespace
	}
	return exampleNamespace.Id, nil
}

func createAttribute(s *sdk.SDK, ctx context.Context, namespaceId string, attrConf AttributeConfig) (string, error) {
	slog.Info("creating new attribute rule")

	rule := policy.AttributeRuleTypeEnum(policy.AttributeRuleTypeEnum_value[attrConf.Rule])

	resp, err := s.Attributes.CreateAttribute(ctx, &attributes.CreateAttributeRequest{
		Name:        attrConf.Name,
		NamespaceId: namespaceId,
		Rule:        rule,
	})
	var attrId string
	if err != nil {
		if returnStatus, ok := status.FromError(err); ok && returnStatus.Code() == codes.AlreadyExists {
			slog.Info("attribute already exists")
			// list by name
			allAttr, err := s.Attributes.ListAttributes(ctx, &attributes.ListAttributesRequest{})
			if err != nil {
				slog.Error("could not list attributes", slog.String("error", err.Error()))
				return "", err
			}
			for _, attr := range allAttr.GetAttributes() {
				if attr.Name == attrConf.Name && attr.Namespace.Id == namespaceId {
					attrId = attr.Id
					break
				}
			}
			if attrId == "" {
				slog.Error("Already exists code returned on attribute creation but could not find attribute in list", slog.String("attribute", attrConf.Name))
				return "", errors.New("already exists code returned on attribute creation but could not find attribute in list")
			}
		} else {
			slog.Error("could not create attribute", slog.String("error", err.Error()))
			return "", err
		}
	} else {
		slog.Info("attribute created")
		attrId = resp.Attribute.Id
	}
	return attrId, nil
}

func createAttributeValue(s *sdk.SDK, ctx context.Context, attrId string, value string) (string, error) {
	slog.Info("creating new attribute value")

	resp, err := s.Attributes.CreateAttributeValue(ctx, &attributes.CreateAttributeValueRequest{
		AttributeId: attrId,
		Value:       value,
	})
	var valId string
	if err != nil {
		if returnStatus, ok := status.FromError(err); ok && returnStatus.Code() == codes.AlreadyExists {
			slog.Info("attribute value already exists")
			// list by name
			allAttrVals, err := s.Attributes.ListAttributeValues(ctx, &attributes.ListAttributeValuesRequest{
				AttributeId: attrId,
			})
			if err != nil {
				slog.Error("could not list attribute values", slog.String("error", err.Error()))
				return "", err
			}
			for _, val := range allAttrVals.GetValues() {
				if val.Value == value {
					valId = val.Id
					break
				}
			}
			if valId == "" {
				slog.Error("Already exists code returned on attribute value creation but could not find attribute value in list", slog.String("value", value))
				return "", errors.New("already exists code returned on attribute value creation but could not find attribute value in list")
			}
		} else {
			slog.Error("could not create attribute value", slog.String("error", err.Error()))
			return "", err
		}
	} else {
		slog.Info("attribute value created")
		valId = resp.Value.Id
	}
	return valId, nil
}

func init() {

	provisionDataFromConfigCmd.Flags().StringP(provDataFilename, "f", "./cmd/simple_policy_data.yaml", "config file to use")

	provisionCmd.AddCommand(provisionDataFromConfigCmd)

	rootCmd.AddCommand(provisionDataFromConfigCmd)

}

func LoadConfigData(filename string) error {
	c, err := os.ReadFile(filename)
	if err != nil {
		slog.Error("could not read "+filename, slog.String("error", err.Error()))
		panic(err)
	}

	if err := yaml.Unmarshal(c, &policyConfigData); err != nil {
		slog.Error("could not unmarshal "+filename, slog.String("error", err.Error()))
		panic(err)
	}
	slog.Info("Fully loaded policy config", slog.Any("policyConfigData", policyConfigData))
	return nil
}

// func attributesExample(examplesConfig *ExampleConfig) error {
// 	s, err := sdk.New(examplesConfig.PlatformEndpoint, sdk.WithInsecureConn())
// 	if err != nil {
// 		slog.Error("could not connect", slog.String("error", err.Error()))
// 		return err
// 	}
// 	defer s.Close()

// 	var exampleNamespace *policy.Namespace
// 	slog.Info("listing namespaces")
// 	listResp, err := s.Namespaces.ListNamespaces(context.Background(), &namespaces.ListNamespacesRequest{})
// 	if err != nil {
// 		return err
// 	}
// 	slog.Info(fmt.Sprintf("found %d namespaces", len(listResp.Namespaces)))
// 	for _, ns := range listResp.GetNamespaces() {
// 		slog.Info(fmt.Sprintf("existing namespace; name: %s, id: %s", ns.Name, ns.Id))
// 		if ns.Name == "example" {
// 			exampleNamespace = ns
// 		}
// 	}

// 	if exampleNamespace == nil {
// 		slog.Info("creating new namespace")
// 		resp, err := s.Namespaces.CreateNamespace(context.Background(), &namespaces.CreateNamespaceRequest{
// 			Name: "example",
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		exampleNamespace = resp.Namespace
// 	}

// 	slog.Info("creating new attribute with hierarchy rule")
// 	_, err = s.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
// 		Name:        "IntellectualProperty",
// 		NamespaceId: exampleNamespace.Id,
// 		Rule:        *policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY.Enum(),
// 		// Values: []*attributes.ValueCreateUpdate{
// 		// 	{Value: "TradeSecret"},
// 		// 	{Value: "Proprietary"},
// 		// 	{Value: "BusinessSensitive"},
// 		// 	{Value: "Open"},
// 		// },
// 	})
// 	if err != nil {
// 		if returnStatus, ok := status.FromError(err); ok && returnStatus.Code() == codes.AlreadyExists {
// 			slog.Info("attribute already exists")
// 		} else {
// 			slog.Error("could not create attribute", slog.String("error", err.Error()))
// 			return err
// 		}
// 	} else {
// 		slog.Info("attribute created")
// 	}

// 	allAttr, err := s.Attributes.ListAttributes(context.Background(), &attributes.ListAttributesRequest{})
// 	if err != nil {
// 		slog.Error("could not list attributes", slog.String("error", err.Error()))
// 		return err
// 	}
// 	slog.Info(fmt.Sprintf("list attributes response: %s", protojson.Format(allAttr)))
// 	return nil
// }
