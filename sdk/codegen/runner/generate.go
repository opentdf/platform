package runner

import (
	"fmt"
	"go/ast"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/tools/go/packages"
)

type ClientsToGenerate struct {
	GrpcClientInterface string
	Suffix              string
	PackageNameOverride string
	GrpcPackagePath     string
}

func Generate(clientsToGenerateList []ClientsToGenerate, outputDir string) error {
	for _, client := range clientsToGenerateList {
		slog.Info("generating wrapper for",
			slog.String("interface", client.GrpcClientInterface),
			slog.String("package", client.GrpcPackagePath),
		)
		// Load the Go package using the import path
		cfg := &packages.Config{
			Mode: packages.NeedName |
				packages.NeedTypes |
				packages.NeedTypesInfo |
				packages.NeedSyntax |
				packages.NeedCompiledGoFiles,
		}
		pkgs, err := packages.Load(cfg, client.GrpcPackagePath)
		if err != nil {
			return fmt.Errorf("failed to load package %s: %w", client.GrpcPackagePath, err)
		}
		if packages.PrintErrors(pkgs) > 0 {
			return fmt.Errorf("errors loading package %s", client.GrpcPackagePath)
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
					if ts.Name.Name == client.GrpcClientInterface {
						packageName := path.Base(client.GrpcPackagePath)
						if client.PackageNameOverride != "" {
							packageName = client.PackageNameOverride
						}
						// In order to counter package name fatigue (policy.attributes.AttributesService),
						// newer services are simply named "Service" (policy.obligations.Service).
						// This prefix logic is necessary for newer services.
						prefix := ""
						if ts.Name.Name == "ServiceClient" {
							prefix = cases.Title(language.English).String(packageName)
						}
						code := generateWrapper(ts.Name.Name, iface, client.GrpcPackagePath, packageName, prefix, client.Suffix)
						outputPath := filepath.Join(outputDir, packageName+".go")
						err = os.WriteFile(outputPath, []byte(code), 0o644) //nolint:gosec // ignore G306
						if err != nil {
							slog.Error("error writing file",
								slog.String("file", outputPath),
								slog.Any("error", err),
							)
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
			return fmt.Errorf("interface %q not found in package %s", client.GrpcClientInterface, client.GrpcPackagePath)
		}
		if err != nil {
			return fmt.Errorf("error writing file: %w", err)
		}
	}
	return nil
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
func generateWrapper(interfaceName string, interfaceType *ast.InterfaceType, packagePath, packageName, prefix, suffix string) string {
	// Get method names dynamically from the interface
	methods := getMethodNames(interfaceType)
	connectPackageName := packageName + "connect"

	// Start generating the wrapper code
	wrapperCode := fmt.Sprintf(`// Wrapper for %s%s (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"%s"
	"%s"
)

type %s%s%sConnectWrapper struct {
	%s.%s
}

func New%s%s%sConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *%s%s%sConnectWrapper {
	return &%s%s%sConnectWrapper{%s: %s.New%s(httpClient, baseURL, opts...)}
}
`,
		prefix,
		interfaceName,
		packagePath,
		packagePath+"/"+connectPackageName,
		prefix,
		interfaceName,
		suffix,
		connectPackageName,
		interfaceName,
		prefix,
		interfaceName,
		suffix,
		prefix,
		interfaceName,
		suffix,
		prefix,
		interfaceName,
		suffix,
		interfaceName,
		connectPackageName,
		interfaceName)

	// Generate the interface type definition
	var builder strings.Builder
	builder.WriteString(wrapperCode)
	builder.WriteString(generateInterfaceType(interfaceName, methods, packageName, prefix, suffix))
	// Now generate a wrapper function for each method in the interface
	for _, method := range methods {
		builder.WriteString(generateWrapperMethod(interfaceName, method, packageName, prefix, suffix))
	}

	// Output the generated wrapper code
	return builder.String()
}

func generateInterfaceType(interfaceName string, methods []string, packageName, prefix, suffix string) string {
	// Generate the interface type definition
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf(`
type %s%s%s interface {
`, prefix, interfaceName, suffix))
	for _, method := range methods {
		builder.WriteString(fmt.Sprintf(`	%s(ctx context.Context, req *%s.%sRequest) (*%s.%sResponse, error)
`, method, packageName, method, packageName, method))
	}
	builder.WriteString("}\n")
	return builder.String()
}

// Generate the wrapper method for a specific method in the interface
func generateWrapperMethod(interfaceName, methodName, packageName, prefix, suffix string) string {
	return fmt.Sprintf(`
func (w *%s%s%sConnectWrapper) %s(ctx context.Context, req *%s.%sRequest) (*%s.%sResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.%s.%s(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
`, prefix, interfaceName, suffix, methodName, packageName, methodName, packageName, methodName, interfaceName, methodName)
}
