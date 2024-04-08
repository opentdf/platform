package namespaces

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/stretchr/testify/require"
)

var validName = "namespace.org"

func getValidator() *protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func TestCreateNamespace_Valid_Succeeds(t *testing.T) {
	names := []string{
		"example.org",
		"hello.com",
		"goodbye.net",
		"spanish.mx",
		"english.uk",
		"GERMAN.de",
		"chinese.CN",
		"japanese.yen.jp",
		"numbers1234.com",
		"numbers1234andletters.com",
		"hyphens-1234.com",
	}

	for _, name := range names {
		req := &namespaces.CreateNamespaceRequest{
			Name: name,
		}

		v := getValidator()
		err := v.Validate(req)

		require.NoError(t, err)
	}
}

func TestCreateNamespace_WithMetadata_Valid_Succeeds(t *testing.T) {
	req := &namespaces.CreateNamespaceRequest{
		Name: validName,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"key1": "value1",
			},
		},
	}

	v := getValidator()
	err := v.Validate(req)

	require.NoError(t, err)
}

func TestCreateNamespace_WithSpace_Fails(t *testing.T) {
	req := &namespaces.CreateNamespaceRequest{
		Name: "name with space.org",
	}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "[namespace_format]")
}

func TestCreateNamespace_WithInvalidCharacter_Fails(t *testing.T) {
	// test a couple of the likely most common invalid characters, but knowing the set is much larger
	names := []string{
		"hello@name.com",
		"name/123.io",
		"name?123.net",
		"name*123.org",
		"name:123.uk",
		// preceeding and trailing hyphens
		"-name.org",
		"name.org-",
	}
	for _, name := range names {
		req := &namespaces.CreateNamespaceRequest{
			Name: name,
		}

		v := getValidator()
		err := v.Validate(req)

		require.Error(t, err)
		require.Contains(t, err.Error(), "[namespace_format]")
	}
}

func TestCreateNamespace_NameMissing_Fails(t *testing.T) {
	req := &namespaces.CreateNamespaceRequest{}

	v := getValidator()
	err := v.Validate(req)

	require.Error(t, err)
	require.Contains(t, err.Error(), "name")
	require.Contains(t, err.Error(), "[required]")
}
