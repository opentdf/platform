package namespaces

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/stretchr/testify/require"
)

const (
	validName      = "namespace.org"
	validUUID      = "390e0058-7ae8-48f6-821c-9db07c831276"
	errMessageUUID = "string.uuid"
)

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

func Test_GetNamespaceRequest_Succeeds(t *testing.T) {
	req := &namespaces.GetNamespaceRequest{}
	v := getValidator()

	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req.Id = validUUID
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_UpdateNamespaceRequest_Succeeds(t *testing.T) {
	req := &namespaces.UpdateNamespaceRequest{}
	v := getValidator()

	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req.Id = validUUID
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_DeactivateNamespaceRequest_Succeeds(t *testing.T) {
	req := &namespaces.DeactivateNamespaceRequest{}
	v := getValidator()

	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req.Id = validUUID
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_NamespaceKeyAccessServer_Succeeds(t *testing.T) {
	validNamespaceKas := &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       validUUID,
		KeyAccessServerId: validUUID,
	}

	err := getValidator().Validate(validNamespaceKas)
	require.NoError(t, err)
}

func Test_NamespaceKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		nsID  string
		kasID string
	}{
		{
			"",
			validUUID,
		},
		{
			validUUID,
			"",
		},
		{
			"",
			"",
		},
		{},
	}

	for _, test := range bad {
		invalidNamespaceKAS := &namespaces.NamespaceKeyAccessServer{
			NamespaceId:       test.nsID,
			KeyAccessServerId: test.kasID,
		}
		err := getValidator().Validate(invalidNamespaceKAS)
		require.Error(t, err)
		require.Contains(t, err.Error(), errMessageUUID)
	}
}
