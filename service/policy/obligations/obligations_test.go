package obligations

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/stretchr/testify/require"
)

const (
	validFQN           = "https://namespace.com/obl/drm/value/watermark"
	invalidUUID        = "invalid-uuid"
	invalidFQN         = "invalid-fqn"
	errMessageUUID     = "string.uuid"
	errMessageURI      = "string.uri"
	errMessageMinItems = "repeated.min_items"
	errMessageUnique   = "repeated.unique"
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func Test_GetObligation_Succeeds(t *testing.T) {
	validUUID := uuid.NewString()
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
