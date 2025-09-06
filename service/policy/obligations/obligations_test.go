package obligations

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/stretchr/testify/require"
)

const (
	validUUID          = "00000000-0000-0000-0000-000000000000"
	validFQN           = "https://namespace.com/obl/drm/value/watermark"
	invalidUUID        = "invalid-uuid"
	invalidFQN         = "invalid-fqn"
	errMessageUUID     = "string.uuid"
	errMessageURI      = "string.uri"
	errMessageMinItems = "repeated.min_items"
	errMessageUnique   = "repeated.unique"
	errMessageOneOf    = "message.oneof"
	errMessageRequired = "required"
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func Test_GetObligation_Succeeds(t *testing.T) {
	req := &obligations.GetObligationRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.GetObligationRequest{
		Fqn: validFQN,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_GetObligation_Fails(t *testing.T) {
	req := &obligations.GetObligationRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.GetObligationRequest{
		Fqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.GetObligationRequest{
		Id:  validUUID,
		Fqn: validFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_GetObligationsByFQNs_Succeeds(t *testing.T) {
	validFQNs := []string{
		validFQN,
		"https://namespace.com/obl/drm/value/expiration",
	}
	req := &obligations.GetObligationsByFQNsRequest{
		Fqns: validFQNs,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)
}

func Test_GetObligationsByFQNs_Fails(t *testing.T) {
	emptyFQNs := []string{}
	req := &obligations.GetObligationsByFQNsRequest{
		Fqns: emptyFQNs,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageMinItems)

	invalidFQNs := []string{invalidFQN}
	req = &obligations.GetObligationsByFQNsRequest{
		Fqns: invalidFQNs,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	duplicateFQNs := []string{validFQN, validFQN}
	req = &obligations.GetObligationsByFQNsRequest{
		Fqns: duplicateFQNs,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUnique)
}

func Test_CreateObligation_Succeeds(t *testing.T) {
	req := &obligations.CreateObligationRequest{
		NamespaceId: validUUID,
		Name:        "drm",
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.CreateObligationRequest{
		NamespaceFqn: validFQN,
		Name:         "drm",
		Values:       []string{"watermark", "expiration"},
	}
	v = getValidator()
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_CreateObligation_Fails(t *testing.T) {
	req := &obligations.CreateObligationRequest{
		NamespaceId: invalidUUID,
		Name:        "drm",
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.CreateObligationRequest{
		NamespaceFqn: invalidFQN,
		Name:         "drm",
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.CreateObligationRequest{
		NamespaceId: validUUID,
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageRequired)

	req = &obligations.CreateObligationRequest{
		NamespaceId:  validUUID,
		NamespaceFqn: validFQN,
		Name:         "drm",
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.CreateObligationRequest{
		NamespaceId:  validUUID,
		NamespaceFqn: validFQN,
		Name:         "drm",
		Values:       []string{"watermark", "watermark"},
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUnique)
}
