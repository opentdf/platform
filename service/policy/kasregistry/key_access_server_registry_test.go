package kasregistry

import (
	"strings"
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

var (
	remotePubKey = &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: validSecureURI + "/public_key",
		},
	}

	fakeCachedKey = &policy.PublicKey{
		PublicKey: &policy.PublicKey_Cached{
			Cached: &policy.KasPublicKeySet{
				Keys: []*policy.KasPublicKey{
					{
						Pem: "fake PEM",
					},
				},
			},
		},
	}
	fakeURI = "https://someuri.com"
	fakeID  = "6321ea85-ca04-466f-aefb-174bcdbc0612"
)

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

func Test_CreateKeyAccessServer_Succeeds(t *testing.T) {
	good := []struct {
		uri      string
		key      *policy.PublicKey
		name     string
		scenario string
	}{
		{
			fakeURI,
			fakeCachedKey,
			"",
			"no optional KAS name & cached key",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas_name",
			"included KAS name & cached key",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name",
			"hyphenated KAS name",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name123",
			"numeric KAS name",
		},
		{
			fakeURI,
			fakeCachedKey,
			"KASnameIsMiXeDCaSe",
			"mixed case KAS name",
		},
		{
			fakeURI,
			remotePubKey,
			"",
			"no optional KAS name & remote key",
		},
	}

	for _, test := range good {
		createReq := &kasregistry.CreateKeyAccessServerRequest{
			Uri:       test.uri,
			PublicKey: test.key,
			Name:      test.name,
		}

		err := getValidator().Validate(createReq)
		require.NoError(t, err, test.scenario+" should be valid")
	}
}

func Test_CreateKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		uri      string
		key      *policy.PublicKey
		name     string
		scenario string
	}{
		{
			"",
			fakeCachedKey,
			"",
			"no uri",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas name",
			"kas name has spaces",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas_name_",
			"kas name ends in underscore",
		},
		{
			fakeURI,
			fakeCachedKey,
			"_kas_name",
			"kas name starts with underscore",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name-",
			"kas name ends in hyphen",
		},
		{
			fakeURI,
			fakeCachedKey,
			"-kas-name",
			"kas name starts with hyphen",
		},
		{
			fakeURI,
			fakeCachedKey,
			strings.Repeat("a", 254),
			"name too long",
		},
		{
			fakeURI,
			nil,
			"",
			"no public key",
		},
		{
			fakeURI,
			&policy.PublicKey{
				PublicKey: &policy.PublicKey_Remote{
					Remote: "bad format",
				},
			},
			"",
			"remote public key bad format",
		},
	}

	for _, test := range bad {
		createReq := &kasregistry.CreateKeyAccessServerRequest{
			Uri:       test.uri,
			PublicKey: test.key,
			Name:      test.name,
		}

		err := getValidator().Validate(createReq)
		require.Error(t, err, test.scenario+" should be invalid")
	}
}

func Test_UpdateKeyAccessServer_Succeeds(t *testing.T) {
	good := []struct {
		uri      string
		key      *policy.PublicKey
		name     string
		scenario string
	}{
		{
			fakeURI,
			fakeCachedKey,
			"",
			"no optional KAS name",
		},
		{
			fakeURI + "/somewhere-over-the-rainbow",
			nil,
			"",
			"only URI",
		},
		{
			"",
			fakeCachedKey,
			"",
			"only cached key",
		},
		{
			"",
			remotePubKey,
			"",
			"only remote key",
		},
		{
			"",
			nil,
			"KASnameIsMiXeDCaSe",
			"mixed case KAS name",
		},
		{
			fakeURI,
			remotePubKey,
			"new-name1",
			"everything included",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name",
			"hyphenated KAS name",
		},
		{
			fakeURI,
			fakeCachedKey,
			"kas-name123",
			"numeric KAS name",
		},
	}

	for _, test := range good {
		updateReq := &kasregistry.UpdateKeyAccessServerRequest{
			Id:        fakeID,
			Uri:       test.uri,
			PublicKey: test.key,
			Name:      test.name,
		}

		err := getValidator().Validate(updateReq)
		require.NoError(t, err, test.scenario+" should be valid")
	}
}

func Test_UpdateKeyAccessServer_Fails(t *testing.T) {
	bad := []struct {
		id       string
		uri      string
		key      *policy.PublicKey
		name     string
		scenario string
	}{
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas name",
			"kas name has spaces",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas_name_",
			"kas name ends in underscore",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"_kas_name",
			"kas name starts with underscore",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"kas-name-",
			"kas name ends in hyphen",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			"-kas-name",
			"kas name starts with hyphen",
		},
		{
			validUUID,
			fakeURI,
			fakeCachedKey,
			strings.Repeat("a", 254),
			"name too long",
		},
		{
			validUUID,
			fakeURI,
			&policy.PublicKey{
				PublicKey: &policy.PublicKey_Remote{
					Remote: "bad URL",
				},
			},
			"",
			"remote public key bad format",
		},
		{
			"bad-id",
			fakeURI,
			fakeCachedKey,
			"",
			"invalid id",
		},
		{
			"",
			fakeURI,
			fakeCachedKey,
			"",
			"no id",
		},
	}

	for _, test := range bad {
		updateReq := &kasregistry.UpdateKeyAccessServerRequest{
			Id:        test.id,
			Uri:       test.uri,
			PublicKey: test.key,
			Name:      test.name,
		}

		err := getValidator().Validate(updateReq)
		require.Error(t, err, "scenario should be invalid: "+test.scenario)
	}
}

func Test_UpdateKeyAccessServer_ShouldRequireID(t *testing.T) {
	updateReq := &kasregistry.UpdateKeyAccessServerRequest{
		Uri: fakeURI,
	}

	err := getValidator().Validate(updateReq)
	require.Error(t, err, "ID should be required")
}
