package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/sdk"
	experimentaltdf "github.com/opentdf/platform/sdk/experimental/tdf"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteTDFSegmentsUsesBoundedReads(t *testing.T) {
	reader := &countingReader{remaining: encryptSegmentSize*2 + 7}
	writer, err := experimentaltdf.NewWriter(t.Context())
	require.NoError(t, err)

	var output bytes.Buffer
	require.NoError(t, writeTDFSegments(t.Context(), writer, &output, reader))
	assert.LessOrEqual(t, reader.maxRead, encryptSegmentSize)
	assert.Positive(t, output.Len())
}

func TestWriteTDFSegmentsWritesEmptyPayload(t *testing.T) {
	writer, err := experimentaltdf.NewWriter(t.Context())
	require.NoError(t, err)

	var output bytes.Buffer
	require.NoError(t, writeTDFSegments(t.Context(), writer, &output, strings.NewReader("")))
	assert.Positive(t, output.Len())
}

func TestWriteTDFSegmentsPropagatesOutputFailure(t *testing.T) {
	writer, err := experimentaltdf.NewWriter(t.Context())
	require.NoError(t, err)

	err = writeTDFSegments(t.Context(), writer, errorWriter{}, strings.NewReader("payload"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "writing encrypted segment 0")
}

func TestEncryptStreamsBeforeReadingEntirePayload(t *testing.T) {
	fqn := "https://example.com/attr/classification/value/secret"
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	kasKey := simpleKASKey("rsa", policy.Algorithm_ALGORITHM_RSA_2048)
	kasKey.PublicKey.Pem = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey}))
	client := &attributeResolutionClient{
		mappings: &attributes.GetKeyMappingsByFqnsResponse{
			FqnKeyMappings: map[string]*attributes.GetKeyMappingsByFqnsResponse_AttributeKeyMapping{
				fqn: {
					Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Keys: []*policy.SimpleKasKey{kasKey},
				},
			},
		},
	}
	handler := Handler{sdk: &sdk.SDK{Attributes: client}}
	reader := &countingReader{remaining: encryptSegmentSize + 7}
	output := &observingWriter{reader: reader}

	err = handler.Encrypt(t.Context(), output, reader, EncryptOptions{
		Attributes:           []string{fqn},
		MimeType:             "application/octet-stream",
		WrappingKeyAlgorithm: ocrypto.RSA2048Key,
	})
	require.NoError(t, err)
	assert.True(t, output.wroteBeforeEOF)
	assert.Equal(t, sdk.Standard, sdk.GetTdfType(bytes.NewReader(output.Bytes())))
}

func TestResolveTDFAttributeValuesUsesEffectiveKeyMappings(t *testing.T) {
	fqn := "https://Example.com/attr/Classification/value/Secret"
	rsaKey := simpleKASKey("rsa", policy.Algorithm_ALGORITHM_RSA_2048)
	ecKey := simpleKASKey("ec", policy.Algorithm_ALGORITHM_EC_P256)
	client := &attributeResolutionClient{
		mappings: &attributes.GetKeyMappingsByFqnsResponse{
			FqnKeyMappings: map[string]*attributes.GetKeyMappingsByFqnsResponse_AttributeKeyMapping{
				strings.ToLower(fqn): {
					Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					Keys: []*policy.SimpleKasKey{ecKey, rsaKey},
				},
			},
		},
	}
	handler := Handler{sdk: &sdk.SDK{Attributes: client}}

	values, err := handler.resolveTDFAttributeValues(t.Context(), []string{fqn}, ocrypto.RSA2048Key)
	require.NoError(t, err)
	require.Len(t, values, 1)
	assert.Equal(t, fqn, values[0].GetFqn())
	assert.Equal(t, "https://Example.com/attr/Classification", values[0].GetAttribute().GetFqn())
	require.Len(t, values[0].GetKasKeys(), 1)
	assert.Equal(t, "rsa", values[0].GetKasKeys()[0].GetPublicKey().GetKid())
}

func TestResolveTDFAttributeValuesFallsBackForOlderPlatforms(t *testing.T) {
	fqn := "https://example.com/attr/classification/value/secret"
	definition := &policy.Attribute{
		Fqn:  "https://example.com/attr/classification",
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		KasKeys: []*policy.SimpleKasKey{
			simpleKASKey("definition", policy.Algorithm_ALGORITHM_RSA_2048),
		},
	}
	client := &attributeResolutionClient{
		mappingErr: connect.NewError(connect.CodeUnimplemented, errors.New("not implemented")),
		values: &attributes.GetAttributeValuesByFqnsResponse{
			FqnAttributeValues: map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				fqn: {Attribute: definition},
			},
		},
	}
	handler := Handler{sdk: &sdk.SDK{Attributes: client}}

	values, err := handler.resolveTDFAttributeValues(t.Context(), []string{fqn}, ocrypto.RSA2048Key)
	require.NoError(t, err)
	require.Len(t, values, 1)
	assert.Equal(t, fqn, values[0].GetFqn())
	assert.Equal(t, definition.GetFqn(), values[0].GetAttribute().GetFqn())
}

type countingReader struct {
	remaining int
	maxRead   int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.remaining)
	clear(p[:n])
	r.remaining -= n
	return n, nil
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type observingWriter struct {
	bytes.Buffer
	reader         *countingReader
	wroteBeforeEOF bool
}

func (w *observingWriter) Write(p []byte) (int, error) {
	if w.reader.remaining > 0 {
		w.wroteBeforeEOF = true
	}
	return w.Buffer.Write(p)
}

type attributeResolutionClient struct {
	sdkconnect.AttributesServiceClient
	mappings   *attributes.GetKeyMappingsByFqnsResponse
	mappingErr error
	values     *attributes.GetAttributeValuesByFqnsResponse
	valuesErr  error
}

func (c *attributeResolutionClient) GetKeyMappingsByFqns(context.Context, *attributes.GetKeyMappingsByFqnsRequest) (*attributes.GetKeyMappingsByFqnsResponse, error) {
	return c.mappings, c.mappingErr
}

func (c *attributeResolutionClient) GetAttributeValuesByFqns(context.Context, *attributes.GetAttributeValuesByFqnsRequest) (*attributes.GetAttributeValuesByFqnsResponse, error) {
	return c.values, c.valuesErr
}

func simpleKASKey(kid string, algorithm policy.Algorithm) *policy.SimpleKasKey {
	return &policy.SimpleKasKey{
		KasUri: "https://kas.example.com",
		PublicKey: &policy.SimpleKasPublicKey{
			Kid:       kid,
			Algorithm: algorithm,
			Pem:       "public key",
		},
	}
}
