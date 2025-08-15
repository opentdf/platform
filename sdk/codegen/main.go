package main

import (
	"errors"
	"log"
	"path/filepath"
	"runtime"

	"github.com/opentdf/platform/sdk/codegen/runner"
)

var clientsToGenerateList = []runner.ClientsToGenerate{
	{
		GrpcClientInterface: "ActionServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/actions",
	},
	{
		GrpcClientInterface: "AttributesServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/attributes",
	},
	{
		GrpcClientInterface: "AuthorizationServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/authorization",
	},
	{
		GrpcClientInterface: "AuthorizationServiceClient",
		Suffix:              "V2",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/authorization/v2",
		PackageNameOverride: "authorizationv2",
	},
	{
		GrpcClientInterface: "EntityResolutionServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/entityresolution",
	},
	{
		GrpcClientInterface: "EntityResolutionServiceClient",
		Suffix:              "V2",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/entityresolution/v2",
		PackageNameOverride: "entityresolutionv2",
	},
	{
		GrpcClientInterface: "FeatureFlagServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/featureflag",
	},
	{
		GrpcClientInterface: "KeyAccessServerRegistryServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/kasregistry",
	},
	{
		GrpcClientInterface: "KeyManagementServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/keymanagement",
	},
	{
		GrpcClientInterface: "NamespaceServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/namespaces",
	},
	{
		GrpcClientInterface: "RegisteredResourcesServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/registeredresources",
	},
	{
		GrpcClientInterface: "ResourceMappingServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/resourcemapping",
	},
	{
		GrpcClientInterface: "SubjectMappingServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/subjectmapping",
	},
	{
		GrpcClientInterface: "UnsafeServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/unsafe",
	},
	{
		GrpcClientInterface: "WellKnownServiceClient",
		GrpcPackagePath:     "github.com/opentdf/platform/protocol/go/wellknownconfiguration",
	},
}

func getCurrentFileDir() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("could not get caller file (main.go) working directory")
	}
	return filepath.Dir(filename), nil
}

func main() {
	currentDir, err := getCurrentFileDir()
	if err != nil {
		log.Fatal("Error getting current file directory:", err)
	}
	outputDir := filepath.Join(currentDir, "..", "sdkconnect")
	if err := runner.Generate(clientsToGenerateList, outputDir); err != nil {
		log.Fatal(err)
	}
}
