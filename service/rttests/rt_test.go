package rttests

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// These roundtrip tests are to be run when the platform server is up and running
// and the keycloak provision has already been run. These tests use the client and
// endpoints provided in the config below. If the platform with a custom config
// then those will need to be updated.

type TestConfig struct {
	PlatformEndpoint string
	TokenEndpoint    string
	ClientID         string
	ClientSecret     string
}

var attributesToMap = []string{
	"https://example.com/attr/language/value/english",
	"https://example.com/attr/color/value/red",
	"https://example.com/attr/cards/value/queen"}

var successAttributeSets = [][]string{
	{},
	{"https://example.com/attr/language/value/english"},
	{"https://example.com/attr/color/value/red"},
	{"https://example.com/attr/color/value/red", "https://example.com/attr/color/value/green"},
	{"https://example.com/attr/cards/value/jack"},
	{"https://example.com/attr/cards/value/queen"},
	{"https://example.com/attr/language/value/english",
		"https://example.com/attr/color/value/red",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/jack",
		"https://example.com/attr/cards/value/queen"},
}

var failureAttributeSets = [][]string{
	{"https://example.com/attr/language/value/english", "https://example.com/attr/language/value/french"},
	{"https://example.com/attr/color/value/blue"},
	{"https://example.com/attr/color/value/blue", "https://example.com/attr/color/value/green"},
	{"https://example.com/attr/cards/value/king"},
	{"https://example.com/attr/language/value/english",
		"https://example.com/attr/language/value/french",
		"https://example.com/attr/color/value/red",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/queen"},
	{"https://example.com/attr/language/value/english",
		"https://example.com/attr/color/value/blue",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/queen"},
	{"https://example.com/attr/language/value/english",
		"https://example.com/attr/color/value/red",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/king"},
}

func newTestConfig() TestConfig {
	return TestConfig{
		PlatformEndpoint: "localhost:8080",
		TokenEndpoint:    "http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token",
		ClientID:         "opentdf",
		ClientSecret:     "secret",
	}
}

func Test_RoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping roundtrip tests, they require the server to be up and running")
	}
	suite.Run(t, new(RoundtripSuite))
}

type RoundtripSuite struct {
	suite.Suite
	TestConfig
}

func (s *RoundtripSuite) SetupSuite() {
	s.TestConfig = newTestConfig()
	slog.Info("Test config", "", s.TestConfig)

	err := s.CreateTestData()
	s.Require().NoError(err)
}

func (s *RoundtripSuite) Tests() {
	// success tests
	for i, attributes := range successAttributeSets {
		n := fmt.Sprintf("success roundtrip %d", i)
		s.Run(n, func() {
			filename := fmt.Sprintf("test-success-%d.tdf", i)
			plaintext := "Running a roundtrip test!"
			err := encrypt(&s.TestConfig, plaintext, attributes, filename)
			s.Require().NoError(err)
			err = decrypt(&s.TestConfig, filename, plaintext)
			s.NoError(err)
		})
	}

	// failure tests
	for i, attributes := range failureAttributeSets {
		n := fmt.Sprintf("failure roundtrip %d", i)
		s.Run(n, func() {
			filename := fmt.Sprintf("test-failure-%d.tdf", i)
			plaintext := "Running a roundtrip test!"
			err := encrypt(&s.TestConfig, plaintext, attributes, filename)
			s.Require().NoError(err)
			err = decrypt(&s.TestConfig, filename, plaintext)
			s.ErrorContains(err, "PermissionDenied")
		})
	}
}

func (s *RoundtripSuite) CreateTestData() error {
	sdk, err := sdk.New(s.TestConfig.PlatformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials(s.TestConfig.ClientID,
			s.TestConfig.ClientSecret, nil),
	)
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		return err
	}
	defer sdk.Close()

	// create namespace example.com
	var exampleNamespace *policy.Namespace
	slog.Info("listing namespaces")
	listResp, err := sdk.Namespaces.ListNamespaces(context.Background(), &namespaces.ListNamespacesRequest{})
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("found %d namespaces", len(listResp.GetNamespaces())))
	for _, ns := range listResp.GetNamespaces() {
		slog.Info(fmt.Sprintf("existing namespace; name: %s, id: %s", ns.GetName(), ns.GetId()))
		if ns.GetName() == "example.com" {
			exampleNamespace = ns
		}
	}

	if exampleNamespace == nil {
		slog.Info("creating new namespace")
		resp, err := sdk.Namespaces.CreateNamespace(context.Background(), &namespaces.CreateNamespaceRequest{
			Name: "example.com",
		})
		if err != nil {
			return err
		}
		exampleNamespace = resp.GetNamespace()
	}

	slog.Info("##################################\n#######################################")

	// Create the attributes
	slog.Info("creating attribute language with allOf rule")
	_, err = sdk.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Name:        "language",
		NamespaceId: exampleNamespace.GetId(),
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
	_, err = sdk.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Name:        "color",
		NamespaceId: exampleNamespace.GetId(),
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
	_, err = sdk.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Name:        "cards",
		NamespaceId: exampleNamespace.GetId(),
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

	allAttr, err := sdk.Attributes.ListAttributes(context.Background(), &attributes.ListAttributesRequest{})
	if err != nil {
		slog.Error("could not list attributes", slog.String("error", err.Error()))
		return err
	}
	slog.Info(fmt.Sprintf("list attributes response: %s", protojson.Format(allAttr)))

	slog.Info("##################################\n#######################################")

	// get the attribute ids for the values were mapping to the client
	var attributeValueIDs []string
	fqnResp, err := sdk.Attributes.GetAttributeValuesByFqns(context.Background(), &attributes.GetAttributeValuesByFqnsRequest{
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
	slog.Info("creating subject mappings for client " + s.TestConfig.ClientID)
	for _, attributeID := range attributeValueIDs {
		_, err = sdk.SubjectMapping.CreateSubjectMapping(context.Background(), &subjectmapping.CreateSubjectMappingRequest{
			AttributeValueId: attributeID,
			Actions: []*policy.Action{{Value: &policy.Action_Standard{
				Standard: policy.Action_STANDARD_ACTION_DECRYPT,
			}},
				{Value: &policy.Action_Standard{
					Standard: policy.Action_STANDARD_ACTION_TRANSMIT,
				}},
			},
			NewSubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{
				SubjectSets: []*policy.SubjectSet{
					{ConditionGroups: []*policy.ConditionGroup{
						{Conditions: []*policy.Condition{{
							SubjectExternalSelectorValue: ".clientId",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
							SubjectExternalValues:        []string{s.TestConfig.ClientID},
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

	allSubMaps, err := sdk.SubjectMapping.ListSubjectMappings(context.Background(), &subjectmapping.ListSubjectMappingsRequest{})
	if err != nil {
		slog.Error("could not list subject mappings", slog.String("error", err.Error()))
		return err
	}
	slog.Info(fmt.Sprintf("list subject mappings response: %s", protojson.Format(allSubMaps)))

	return nil
}

func encrypt(testConfig *TestConfig, plaintext string, attributes []string, filename string) error {
	strReader := strings.NewReader(plaintext)

	// Create new offline client
	client, err := sdk.New(testConfig.PlatformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials(testConfig.ClientID,
			testConfig.ClientSecret, nil),
		sdk.WithTokenEndpoint(testConfig.TokenEndpoint),
	)
	if err != nil {
		return err
	}

	tdfFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer tdfFile.Close()

	_, err = client.CreateTDF(tdfFile, strReader,
		sdk.WithDataAttributes(attributes...),
		sdk.WithKasInformation(
			sdk.KASInfo{
				// examples assume insecure http
				URL:       fmt.Sprintf("http://%s", testConfig.PlatformEndpoint),
				PublicKey: "",
			}))
	if err != nil {
		return err
	}

	return nil
}

func decrypt(testConfig *TestConfig, tdfFile string, plaintext string) error {
	// Create new client
	client, err := sdk.New(testConfig.PlatformEndpoint,
		sdk.WithInsecurePlaintextConn(),
		sdk.WithClientCredentials(testConfig.ClientID,
			testConfig.ClientSecret, nil),
		sdk.WithTokenEndpoint(testConfig.TokenEndpoint),
	)
	if err != nil {
		return err
	}
	file, err := os.Open(tdfFile)
	if err != nil {
		return err
	}

	defer file.Close()

	tdfreader, err := client.LoadTDF(file)
	if err != nil {
		return errors.New("failure on LoadTDF: " + err.Error())
	}

	buf := new(strings.Builder)
	_, err = io.Copy(buf, tdfreader)
	if err != nil && !(errors.Is(err, io.EOF)) {
		return err
	}

	if buf.String() != plaintext {
		return errors.New("decrypt result (" + buf.String() + ") does not match expected (" + plaintext + ")")
	}

	return nil
}
