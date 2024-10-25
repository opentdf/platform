package kasregistry

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/stretchr/testify/require"
)

func getValidator() *protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

const (
	validSecureURI   = "https://example.net"
	validInsecureURI = "http://local.something.com"
	validUUID        = "00000000-0000-0000-0000-000000000000"
	errMessageUUID   = "string.uuid"
)

var remotePubKey = &policy.PublicKey{
	PublicKey: &policy.PublicKey_Remote{
		Remote: validSecureURI + "/public_key",
	},
}

func Test_GetKeyAccessServerRequest_Succeeds(t *testing.T) {
	req := &kasregistry.GetKeyAccessServerRequest{}
	v := getValidator()

	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req.Id = validUUID
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_CreateKeyAccessServerRequest_Fails(t *testing.T) {
	v := getValidator()
	bad := []struct {
		pk       *policy.PublicKey
		uri      string
		scenario string
	}{
		{
			nil,
			validSecureURI,
			"no required public key",
		},
		{
			remotePubKey,
			"",
			"empty URI",
		},
	}

	for _, test := range bad {
		req := &kasregistry.CreateKeyAccessServerRequest{
			Uri:       test.uri,
			PublicKey: test.pk,
		}
		err := v.Validate(req)
		require.Error(t, err, test.scenario)
	}
}

func Test_CreateKeyAccessServerRequest_Succeeds(t *testing.T) {
	v := getValidator()
	good := []struct {
		pk  *policy.PublicKey
		uri string
	}{
		{
			remotePubKey,
			validSecureURI,
		},
		{
			remotePubKey,
			validInsecureURI,
		},
		{
			remotePubKey,
			// non http protocol
			"udp://hello.world",
		},
		// ports allowed
		{
			remotePubKey,
			validInsecureURI + ":8080",
		},
		{
			remotePubKey,
			validSecureURI + ":8080",
		},
	}

	for _, test := range good {
		req := &kasregistry.CreateKeyAccessServerRequest{
			Uri:       test.uri,
			PublicKey: test.pk,
		}
		err := v.Validate(req)
		require.NoError(t, err)
	}
}

func Test_UpdateKeyAccessServerRequest_Fails(t *testing.T) {
	v := getValidator()
	bad := []struct {
		id       string
		pk       *policy.PublicKey
		uri      string
		scenario string
	}{
		{
			"",
			remotePubKey,
			validSecureURI,
			"no required ID",
		},
		{
			"bad-id-format",
			remotePubKey,
			validSecureURI,
			"invalid UUID",
		},
	}

	for _, test := range bad {
		req := &kasregistry.UpdateKeyAccessServerRequest{
			Id:        test.id,
			Uri:       test.uri,
			PublicKey: test.pk,
		}
		err := v.Validate(req)
		require.Error(t, err, test.scenario)
	}
}

func Test_UpdateKeyAccessServerRequest_Succeeds(t *testing.T) {
	v := getValidator()

	good := []struct {
		pk       *policy.PublicKey
		uri      string
		scenario string
	}{
		{
			remotePubKey,
			validSecureURI,
			"both https uri and public key",
		},
		{
			remotePubKey,
			"udp://hello.world",
			"other non-http URI",
		},
		{
			remotePubKey,
			validInsecureURI,
			"both http uri and public key",
		},
		{
			remotePubKey,
			validInsecureURI + ":9000",
			"with port",
		},
		{
			nil,
			validSecureURI,
			"no optional public key",
		},
		{
			remotePubKey,
			"",
			"empty optional URI",
		},
	}

	for _, test := range good {
		req := &kasregistry.UpdateKeyAccessServerRequest{
			Id:        validUUID,
			Uri:       test.uri,
			PublicKey: test.pk,
		}
		err := v.Validate(req)
		require.NoError(t, err, test.scenario)
	}
}

func Test_DeleteKeyAccessServerRequest_Succeeds(t *testing.T) {
	req := &kasregistry.DeleteKeyAccessServerRequest{}
	v := getValidator()

	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req.Id = validUUID
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_ListKeyAccessServerGrantsRequest_Fails(t *testing.T) {
	v := getValidator()
	bad := []struct {
		id       string
		uri      string
		scenario string
	}{
		{
			"",
			"missing.scheme",
			"bad URI format",
		},
		{
			"bad-id-format",
			validSecureURI,
			"invalid UUID",
		},
	}

	for _, test := range bad {
		req := &kasregistry.ListKeyAccessServerGrantsRequest{
			KasId:  test.id,
			KasUri: test.uri,
		}
		err := v.Validate(req)
		require.Error(t, err, test.scenario)
	}
}

func Test_ListKeyAccessServerGrantsRequest_Succeeds(t *testing.T) {
	v := getValidator()

	good := []struct {
		id       string
		uri      string
		scenario string
	}{
		{
			validUUID,
			validSecureURI,
			"both https URI and ID",
		},
		{
			validUUID,
			validInsecureURI,
			"both http URI and ID",
		},
		{
			validUUID,
			"",
			"no optional URI",
		},
		{
			"",
			validSecureURI,
			"no optional KAS ID",
		},
		{
			"",
			"",
			"neither optional ID nor URI",
		},
	}

	for _, test := range good {
		req := &kasregistry.ListKeyAccessServerGrantsRequest{
			KasId:  test.id,
			KasUri: test.uri,
		}
		err := v.Validate(req)
		require.NoError(t, err, test.scenario)
	}
}
