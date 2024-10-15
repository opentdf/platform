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

var (
	fakeRemoteKey = &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://someuri.com/kas",
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

func Test_CreateKeyAccessServer_ShouldWork(t *testing.T) {
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
			fakeRemoteKey,
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

func Test_CreateKeyAccessServer_BadInputsShouldFail(t *testing.T) {
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

func Test_UpdateKeyAccessServer_ShouldBePatchStyle(t *testing.T) {
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
			fakeRemoteKey,
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
			fakeRemoteKey,
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

func Test_UpdateKeyAccessServer_BadInputsShouldFail(t *testing.T) {
	bad := []struct {
		uri      string
		key      *policy.PublicKey
		name     string
		scenario string
	}{
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
		updateReq := &kasregistry.UpdateKeyAccessServerRequest{
			Id:        fakeID,
			Uri:       test.uri,
			PublicKey: test.key,
			Name:      test.name,
		}

		err := getValidator().Validate(updateReq)
		require.Error(t, err, test.scenario+" should be invalid")
	}
}

func Test_UpdateKeyAccessServer_ShouldRequireID(t *testing.T) {
	updateReq := &kasregistry.UpdateKeyAccessServerRequest{
		Uri: fakeURI,
	}

	err := getValidator().Validate(updateReq)
	require.Error(t, err, "ID should be required")
}
