package obligations

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/stretchr/testify/require"
)

const (
	validUUID             = "00000000-0000-0000-0000-000000000000"
	validName             = "drm"
	validValue1           = "watermark"
	validFQN1             = "https://namespace.com/obl/" + validName + "/value/" + validValue1
	validValue2           = "expiration"
	validFQN2             = "https://namespace.com/obl/" + validName + "/value/" + validValue2
	invalidUUID           = "invalid-uuid"
	invalidName           = "invalid name"
	invalidFQN            = "invalid-fqn"
	errMessageUUID        = "string.uuid"
	errMessageURI         = "string.uri"
	errMessageMinItems    = "repeated.min_items"
	errMessageUnique      = "repeated.unique"
	errMessageOneOf       = "message.oneof"
	errMessageRequired    = "required"
	errMessageNameFormat  = "obligation_name_format"
	errMessageValueFormat = "obligation_value_format"
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
		Fqn: validFQN1,
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
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_GetObligationsByFQNs_Succeeds(t *testing.T) {
	validFQNs := []string{
		validFQN1,
		validFQN2,
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

	duplicateFQNs := []string{validFQN1, validFQN1}
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
		Name:        validName,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.CreateObligationRequest{
		NamespaceFqn: validFQN1,
		Name:         validName,
		Values:       []string{validValue1, validValue2},
	}
	v = getValidator()
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_CreateObligation_Fails(t *testing.T) {
	req := &obligations.CreateObligationRequest{
		NamespaceId: invalidUUID,
		Name:        validName,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.CreateObligationRequest{
		NamespaceFqn: invalidFQN,
		Name:         validName,
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
		NamespaceFqn: validFQN1,
		Name:         validName,
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.CreateObligationRequest{
		NamespaceId:  validUUID,
		NamespaceFqn: validFQN1,
		Name:         validName,
		Values:       []string{validValue1, validValue1},
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUnique)
}

func Test_UpdateObligation_Succeeds(t *testing.T) {
	req := &obligations.UpdateObligationRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.UpdateObligationRequest{
		Id:   validUUID,
		Name: validName,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_UpdateObligation_Fails(t *testing.T) {
	req := &obligations.UpdateObligationRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.UpdateObligationRequest{
		Id:   validUUID,
		Name: invalidName,
	}
	v = getValidator()
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageNameFormat)
}

func Test_DeleteObligation_Succeeds(t *testing.T) {
	req := &obligations.DeleteObligationRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.DeleteObligationRequest{
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_DeleteObligation_Fails(t *testing.T) {
	req := &obligations.DeleteObligationRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.DeleteObligationRequest{
		Fqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.DeleteObligationRequest{
		Id:  validUUID,
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.DeleteObligationRequest{}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_ListObligations_Succeeds(t *testing.T) {
	req := &obligations.ListObligationsRequest{}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.ListObligationsRequest{
		NamespaceId: validUUID,
	}
	err = v.Validate(req)
	require.NoError(t, err)

	req = &obligations.ListObligationsRequest{
		NamespaceFqn: validFQN1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_ListObligations_Fails(t *testing.T) {
	req := &obligations.ListObligationsRequest{
		NamespaceId: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.ListObligationsRequest{
		NamespaceFqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)
}

func Test_GetObligationValue_Succeeds(t *testing.T) {
	req := &obligations.GetObligationValueRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.GetObligationValueRequest{
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_GetObligationValue_Fails(t *testing.T) {
	req := &obligations.GetObligationValueRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.GetObligationValueRequest{
		Fqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.GetObligationValueRequest{
		Id:  validUUID,
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.GetObligationValueRequest{}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_GetObligationValuesByFQNs_Succeeds(t *testing.T) {
	validFQNs := []string{
		validFQN1,
		validFQN2,
	}
	req := &obligations.GetObligationValuesByFQNsRequest{
		Fqns: validFQNs,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)
}

func Test_GetObligationValuesByFQNs_Fails(t *testing.T) {
	emptyFQNs := []string{}
	req := &obligations.GetObligationValuesByFQNsRequest{
		Fqns: emptyFQNs,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageMinItems)

	invalidFQNs := []string{invalidFQN}
	req = &obligations.GetObligationValuesByFQNsRequest{
		Fqns: invalidFQNs,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	duplicateFQNs := []string{validFQN1, validFQN1}
	req = &obligations.GetObligationValuesByFQNsRequest{
		Fqns: duplicateFQNs,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUnique)
}

func Test_CreateObligationValue_Succeeds(t *testing.T) {
	req := &obligations.CreateObligationValueRequest{
		ObligationId: validUUID,
		Value:        validValue1,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.CreateObligationValueRequest{
		ObligationFqn: validFQN1,
		Value:         validValue1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_CreateObligationValue_Fails(t *testing.T) {
	req := &obligations.CreateObligationValueRequest{
		ObligationId: invalidUUID,
		Value:        validValue1,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.CreateObligationValueRequest{
		ObligationFqn: invalidFQN,
		Value:         validValue1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.CreateObligationValueRequest{
		ObligationId: validUUID,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageRequired)

	req = &obligations.CreateObligationValueRequest{
		ObligationId:  validUUID,
		ObligationFqn: validFQN1,
		Value:         validValue1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.CreateObligationValueRequest{
		ObligationId: validUUID,
		Value:        invalidName,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageValueFormat)

	req = &obligations.CreateObligationValueRequest{}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}

func Test_UpdateObligationValue_Succeeds(t *testing.T) {
	req := &obligations.UpdateObligationValueRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.UpdateObligationValueRequest{
		Id:    validUUID,
		Value: validValue1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_UpdateObligationValue_Fails(t *testing.T) {
	req := &obligations.UpdateObligationValueRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.UpdateObligationValueRequest{
		Id:    validUUID,
		Value: invalidName,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageValueFormat)
}

func Test_DeleteObligationValue_Succeeds(t *testing.T) {
	req := &obligations.DeleteObligationValueRequest{
		Id: validUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.NoError(t, err)

	req = &obligations.DeleteObligationValueRequest{
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.NoError(t, err)
}

func Test_DeleteObligationValue_Fails(t *testing.T) {
	req := &obligations.DeleteObligationValueRequest{
		Id: invalidUUID,
	}
	v := getValidator()
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req = &obligations.DeleteObligationValueRequest{
		Fqn: invalidFQN,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageURI)

	req = &obligations.DeleteObligationValueRequest{
		Id:  validUUID,
		Fqn: validFQN1,
	}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)

	req = &obligations.DeleteObligationValueRequest{}
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOneOf)
}
