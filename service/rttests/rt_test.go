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
	"github.com/opentdf/platform/service/policy/actions"
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
	PlatformEndpoint           string
	PlatformEndpointWithScheme string
	TokenEndpoint              string
	ClientID                   string
	ClientSecret               string
}

var attributesToMap = []string{
	"https://example.com/attr/language/value/english",
	"https://example.com/attr/color/value/red",
	"https://example.com/attr/cards/value/queen",
}

var successAttributeSets = [][]string{
	{},
	{"https://example.com/attr/language/value/english"},
	{"https://example.com/attr/color/value/red"},
	{"https://example.com/attr/color/value/red", "https://example.com/attr/color/value/green"},
	{"https://example.com/attr/cards/value/jack"},
	{"https://example.com/attr/cards/value/queen"},
	{
		"https://example.com/attr/language/value/english",
		"https://example.com/attr/color/value/red",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/jack",
		"https://example.com/attr/cards/value/queen",
	},
}

var failureAttributeSets = [][]string{
	{"https://example.com/attr/language/value/english", "https://example.com/attr/language/value/french"},
	{"https://example.com/attr/color/value/blue"},
	{"https://example.com/attr/color/value/blue", "https://example.com/attr/color/value/green"},
	{"https://example.com/attr/cards/value/king"},
	{
		"https://example.com/attr/language/value/english",
		"https://example.com/attr/language/value/french",
		"https://example.com/attr/color/value/red",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/queen",
	},
	{
		"https://example.com/attr/language/value/english",
		"https://example.com/attr/color/value/blue",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/queen",
	},
	{
		"https://example.com/attr/language/value/english",
		"https://example.com/attr/color/value/red",
		"https://example.com/attr/color/value/green",
		"https://example.com/attr/cards/value/king",
	},
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
	client *sdk.SDK
}

func (s *RoundtripSuite) SetupSuite() {
	s.TestConfig = newTestConfig()
	slog.Info("test config", slog.Any("config", s.TestConfig))

	opts := []sdk.Option{}
	if os.Getenv("TLS_ENABLED") == "" {
		opts = append(opts, sdk.WithInsecurePlaintextConn())
		s.TestConfig.PlatformEndpointWithScheme = "http://" + s.TestConfig.PlatformEndpoint
	} else {
		s.TestConfig.PlatformEndpointWithScheme = "https://" + s.TestConfig.PlatformEndpoint
	}

	opts = append(opts, sdk.WithClientCredentials(s.TestConfig.ClientID, s.TestConfig.ClientSecret, nil))

	sdk, err := sdk.New(s.TestConfig.PlatformEndpointWithScheme, opts...)
	s.Require().NoError(err)
	s.client = sdk

	err = s.CreateTestData()
	s.Require().NoError(err)
}

func (s *RoundtripSuite) Tests() {
	var passNames []string
	// success tests
	for i, attributes := range successAttributeSets {
		n := fmt.Sprintf("success roundtrip %d", i)
		s.Run(n, func() {
			filename := fmt.Sprintf("test-success-%d.tdf", i)
			passNames = append(passNames, filename)
			plaintext := "Running a roundtrip test!"
			err := encrypt(s.client, s.TestConfig, plaintext, attributes, filename)
			s.Require().NoError(err)
			err = decrypt(s.client, filename, plaintext)
			s.NoError(err)
		})
	}

	var failNames []string
	// failure tests
	for i, attributes := range failureAttributeSets {
		n := fmt.Sprintf("failure roundtrip %d", i)
		s.Run(n, func() {
			filename := fmt.Sprintf("test-failure-%d.tdf", i)
			failNames = append(failNames, filename)
			plaintext := "Running a roundtrip test!"
			err := encrypt(s.client, s.TestConfig, plaintext, attributes, filename)
			s.Require().NoError(err)
			err = decrypt(s.client, filename, plaintext)
			s.ErrorContains(err, "PermissionDenied")
		})
	}

	// bulk tests
	s.Run("bulk test", func() {
		s.Require().NoError(bulk(s.client, passNames, failNames, "Running a roundtrip test!"))
	})
}

func (s *RoundtripSuite) CreateTestData() error {
	client := s.client

	// create namespace example.com
	var exampleNamespace *policy.Namespace
	slog.Info("listing namespaces")
	listResp, err := client.Namespaces.ListNamespaces(context.Background(), &namespaces.ListNamespacesRequest{})
	if err != nil {
		return err
	}
	slog.Info("found namespaces", slog.Int("count", len(listResp.GetNamespaces())))
	for _, ns := range listResp.GetNamespaces() {
		slog.Info("existing namespace",
			slog.String("name", ns.GetName()),
			slog.String("id", ns.GetId()),
		)

		if ns.GetName() == "example.com" {
			exampleNamespace = ns
		}
	}

	if exampleNamespace == nil {
		slog.Info("creating new namespace")
		resp, err := client.Namespaces.CreateNamespace(context.Background(), &namespaces.CreateNamespaceRequest{
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
	_, err = client.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
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
	_, err = client.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
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
	_, err = client.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
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

	allAttr, err := client.Attributes.ListAttributes(context.Background(), &attributes.ListAttributesRequest{})
	if err != nil {
		slog.Error("could not list attributes", slog.String("error", err.Error()))
		return err
	}
	slog.Info("list attributes", slog.String("response", protojson.Format(allAttr)))

	slog.Info("##################################\n#######################################")

	// get the attribute ids for the values were mapping to the client
	var attributeValueIDs []string
	fqnResp, err := client.Attributes.GetAttributeValuesByFqns(context.Background(), &attributes.GetAttributeValuesByFqnsRequest{
		Fqns:      attributesToMap,
	})
	if err != nil {
		slog.Error("get attribute values by fqn ", slog.String("error", err.Error()))
		return err
	}
	for _, attribute := range attributesToMap {
		attributeValueIDs = append(attributeValueIDs, fqnResp.GetFqnAttributeValues()[attribute].GetValue().GetId())
	}

	// create subject mappings
	slog.Info("creating subject mappings", slog.String("client_id", s.TestConfig.ClientID))
	for _, attributeID := range attributeValueIDs {
		_, err = client.SubjectMapping.CreateSubjectMapping(context.Background(), &subjectmapping.CreateSubjectMappingRequest{
			AttributeValueId: attributeID,
			Actions: []*policy.Action{
				{Name: actions.ActionNameCreate},
				{Name: actions.ActionNameRead},
			},
			NewSubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{
				SubjectSets: []*policy.SubjectSet{
					{ConditionGroups: []*policy.ConditionGroup{
						{
							Conditions: []*policy.Condition{{
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

	// If quantity of attributes exceeds maximum list pagination, all are needed to determine entitlements
	var nextOffset int32
	smList := make([]*policy.SubjectMapping, 0)
	ctx := s.T().Context()

	for {
		listed, err := client.SubjectMapping.ListSubjectMappings(ctx, &subjectmapping.ListSubjectMappingsRequest{
			// defer to service default for limit pagination
			Pagination: &policy.PageRequest{
				Offset: nextOffset,
			},
		})
		if err != nil {
			slog.ErrorContext(ctx, "failed to list subject mappings", slog.String("error", err.Error()))
			return fmt.Errorf("failed to list subject mappings: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		smList = append(smList, listed.GetSubjectMappings()...)

		if nextOffset <= 0 {
			break
		}
	}
	resp := &subjectmapping.ListSubjectMappingsResponse{
		SubjectMappings: smList,
	}
	slog.InfoContext(ctx, "list all subject mappings", slog.String("subject_mappings", protojson.Format(resp)))

	return nil
}

func encrypt(client *sdk.SDK, testConfig TestConfig, plaintext string, attributes []string, filename string) error {
	strReader := strings.NewReader(plaintext)

	tdfFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer tdfFile.Close()

	_, err = client.CreateTDF(tdfFile, strReader,
		sdk.WithDataAttributes(attributes...),
		sdk.WithKasInformation(
			sdk.KASInfo{
				URL:       testConfig.PlatformEndpointWithScheme,
				PublicKey: "",
			}))
	if err != nil {
		return err
	}

	return nil
}

func decrypt(client *sdk.SDK, tdfFile string, plaintext string) error {
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

func bulk(client *sdk.SDK, tdfSuccess []string, tdfFail []string, plaintext string) error {
	var passTDF []*sdk.BulkTDF
	for _, fileName := range tdfSuccess {
		file, err := os.Open(fileName)
		if err != nil {
			return err
		}

		defer file.Close()

		buf := new(strings.Builder)
		passTDF = append(passTDF, &sdk.BulkTDF{Writer: buf, Reader: file})
	}

	var failTDF []*sdk.BulkTDF
	for _, fileName := range tdfFail {
		file, err := os.Open(fileName)
		if err != nil {
			return err
		}

		defer file.Close()

		buf := new(strings.Builder)
		failTDF = append(failTDF, &sdk.BulkTDF{Writer: buf, Reader: file})
	}

	_ = client.BulkDecrypt(context.Background(), sdk.WithTDFs(passTDF...), sdk.WithTDFs(failTDF...), sdk.WithTDFType(sdk.Standard))
	for _, tdf := range passTDF {
		builder, ok := tdf.Writer.(*strings.Builder)
		if !ok {
			return errors.New("bad writer")
		}

		if tdf.Error != nil {
			return tdf.Error
		}
		if builder.String() != plaintext {
			return errors.New("bulk did not equal plaintext")
		}
	}
	for _, tdf := range failTDF {
		if tdf.Error == nil {
			return errors.New("no expected err")
		}
	}

	_ = client.BulkDecrypt(
		context.Background(),
		sdk.WithTDFs(passTDF...),
		sdk.WithTDFType(sdk.Standard),
		sdk.WithBulkKasAllowlist([]string{"http://some-non-existant:8080"}),
	)
	for _, tdf := range passTDF {
		if tdf.Error == nil {
			return errors.New("no expected err")
		}
		slog.Error("pass tdf error", slog.Any("error", tdf.Error))
		if !strings.Contains(tdf.Error.Error(), "KasAllowlist") {
			return errors.New("did not receive kas allowlist error")
		}
	}

	return nil
}
