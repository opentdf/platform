package runner

import (
	"errors"
	"fmt"
	"go/ast"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"golang.org/x/tools/go/packages"
)

type clientsToGenerate struct {
	grpcClientInterface string
	suffix              string
	packageNameOverride string
	grpcPackagePath     string
}

var clientsToGenerateList = []clientsToGenerate{
	{
		grpcClientInterface: "ActionServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/actions",
	},
	{
		grpcClientInterface: "AttributesServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/attributes",
	},
	{
		grpcClientInterface: "AuthorizationServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/authorization",
	},
	{
		grpcClientInterface: "AuthorizationServiceClient",
		suffix:              "V2",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/authorization/v2",
		packageNameOverride: "authorizationv2",
	},
	{
		grpcClientInterface: "EntityResolutionServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/entityresolution",
	},
	{
		grpcClientInterface: "EntityResolutionServiceClient",
		suffix:              "V2",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/entityresolution/v2",
		packageNameOverride: "entityresolutionv2",
	},
	{
		grpcClientInterface: "KeyAccessServerRegistryServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/kasregistry",
	},
	{
		grpcClientInterface: "KeyManagementServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/keymanagement",
	},
	{
		grpcClientInterface: "NamespaceServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/namespaces",
	},
	{
		grpcClientInterface: "RegisteredResourcesServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/registeredresources",
	},
	{
		grpcClientInterface: "ResourceMappingServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/resourcemapping",
	},
	{
		grpcClientInterface: "SubjectMappingServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/subjectmapping",
	},
	{
		grpcClientInterface: "UnsafeServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/policy/unsafe",
	},
	{
		grpcClientInterface: "WellKnownServiceClient",
		grpcPackagePath:     "github.com/opentdf/platform/protocol/go/wellknownconfiguration",
	},
}

func Generate() error {
	for _, client := range clientsToGenerateList {
		slog.Info("Generating wrapper for", "interface", client.grpcClientInterface, "package", client.grpcPackagePath)
		// Load the Go package using the import path
		cfg := &packages.Config{
			Mode: packages.NeedName |
				packages.NeedTypes |
				packages.NeedTypesInfo |
				packages.NeedSyntax |
				packages.NeedCompiledGoFiles,
		}
		pkgs, err := packages.Load(cfg, client.grpcPackagePath)
		if err != nil {
			return fmt.Errorf("failed to load package %s: %w", client.grpcPackagePath, err)
		}
		if packages.PrintErrors(pkgs) > 0 {
			return fmt.Errorf("errors loading package %s", client.grpcPackagePath)
		}
		found := false
		err = nil
		// Loop through the package and its files
		for _, p := range pkgs {
			for _, file := range p.Syntax {
				ast.Inspect(file, func(n ast.Node) bool {
					if found {
						return false // skip rest of traversal
					}
					ts, ok := n.(*ast.TypeSpec)
					if !ok {
						return true
					}
					iface, ok := ts.Type.(*ast.InterfaceType)
					if !ok {
						return true
					}
					if ts.Name.Name == client.grpcClientInterface {
						packageName := path.Base(client.grpcPackagePath)
						if client.packageNameOverride != "" {
							packageName = client.packageNameOverride
						}
						code := generateWrapper(ts.Name.Name, iface, client.grpcPackagePath, packageName, client.suffix)
						var currentDir string
						currentDir, err = getCurrentFileDir()
						outputPath := filepath.Join(currentDir, "..", "..", "..", "sdkconnect", packageName+".go")
						err = os.WriteFile(outputPath, []byte(code), 0o644) //nolint:gosec // ignore G306
						if err != nil {
							slog.Error("Error writing file", "file", outputPath, "error", err)
						}
						found = true
						return false // stop traversal
					}
					return true
				})
				if found {
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return fmt.Errorf("interface %q not found in package %s", client.grpcClientInterface, client.grpcPackagePath)
		}
		if err != nil {
			return fmt.Errorf("error writing file: %w", err)
		}
	}
	return nil
}

func getCurrentFileDir() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("could not get caller file (generate.go) working directory")
	}
	return filepath.Dir(filename), nil
}

// Helper function to get the method names of an interface
func getMethodNames(interfaceType *ast.InterfaceType) []string {
	methodNames := []string{}
	for _, method := range interfaceType.Methods.List {
		if len(method.Names) > 0 {
			methodNames = append(methodNames, method.Names[0].Name)
		}
	}
	return methodNames
}

// Generate wrapper code for the Connect RPC client interface
func generateWrapper(interfaceName string, interfaceType *ast.InterfaceType, packagePath string, packageName string, suffix string) string {
	// Get method names dynamically from the interface
	methods := getMethodNames(interfaceType)
	connectPackageName := packageName + "connect"

	// Start generating the wrapper code
	wrapperCode := fmt.Sprintf(`// Wrapper for %s (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"%s"
	"%s"
)

type %s%sConnectWrapper struct {
	%s.%s
}

func New%s%sConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *%s%sConnectWrapper {
	return &%s%sConnectWrapper{%s: %s.New%s(httpClient, baseURL, opts...)}
}
`,
		interfaceName,
		packagePath,
		packagePath+"/"+connectPackageName,
		interfaceName,
		suffix,
		connectPackageName,
		interfaceName,
		interfaceName,
		suffix,
		interfaceName,
		suffix,
		interfaceName,
		suffix,
		interfaceName,
		connectPackageName,
		interfaceName)

	// Generate the interface type definition
	wrapperCode += generateInterfaceType(interfaceName, methods, packageName, suffix)
	// Now generate a wrapper function for each method in the interface
	for _, method := range methods {
		wrapperCode += generateWrapperMethod(interfaceName, method, packageName, suffix)
	}

	// Output the generated wrapper code
	return wrapperCode
}

func generateInterfaceType(interfaceName string, methods []string, packageName string, suffix string) string {
	// Generate the interface type definition
	interfaceType := fmt.Sprintf(`
type %s%s interface {
`, interfaceName, suffix)
	for _, method := range methods {
		interfaceType += fmt.Sprintf(`	%s(ctx context.Context, req *%s.%sRequest) (*%s.%sResponse, error)
`, method, packageName, method, packageName, method)
	}
	interfaceType += "}\n"
	return interfaceType
}

// Generate the wrapper method for a specific method in the interface
func generateWrapperMethod(interfaceName, methodName, packageName string, suffix string) string {
	return fmt.Sprintf(`
func (w *%s%sConnectWrapper) %s(ctx context.Context, req *%s.%sRequest) (*%s.%sResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.%s.%s(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
`, interfaceName, suffix, methodName, packageName, methodName, packageName, methodName, interfaceName, methodName)
}
