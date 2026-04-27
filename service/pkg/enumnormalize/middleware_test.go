package enumnormalize

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPath = "/policy.subjectmapping.SubjectMappingService/CreateSubjectConditionSet"

var testRules = []EnumFieldRule{
	{JSONField: "operator", Prefix: "SUBJECT_MAPPING_OPERATOR_ENUM_"},
	{JSONField: "booleanOperator", Prefix: "CONDITION_BOOLEAN_TYPE_ENUM_"},
}

// captureHandler records the request body it receives.
type captureHandler struct {
	body string
}

func (h *captureHandler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.body = string(b)
}

func TestMiddleware_NormalizesMatchingJSONRequest(t *testing.T) {
	capture := &captureHandler{}
	mw := NewMiddleware(testRules, []string{testPath}, 0)
	handler := mw(capture)

	body := `{"booleanOperator":"AND","conditions":[{"operator":"IN"}]}`
	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Contains(t, capture.body, "CONDITION_BOOLEAN_TYPE_ENUM_AND")
	assert.Contains(t, capture.body, "SUBJECT_MAPPING_OPERATOR_ENUM_IN")
}

func TestMiddleware_ConnectJSONContentType(t *testing.T) {
	capture := &captureHandler{}
	mw := NewMiddleware(testRules, []string{testPath}, 0)
	handler := mw(capture)

	body := `{"operator":"NOT_IN"}`
	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/connect+json")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Contains(t, capture.body, "SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN")
}

func TestMiddleware_NonMatchingPathPassesThrough(t *testing.T) {
	capture := &captureHandler{}
	mw := NewMiddleware(testRules, []string{testPath}, 0)
	handler := mw(capture)

	body := `{"operator":"IN"}`
	req := httptest.NewRequest(http.MethodPost, "/policy.attributes.AttributesService/ListAttributes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// Should be the original body, not normalized
	assert.Equal(t, body, capture.body)
}

func TestMiddleware_NonJSONContentTypePassesThrough(t *testing.T) {
	capture := &captureHandler{}
	mw := NewMiddleware(testRules, []string{testPath}, 0)
	handler := mw(capture)

	body := `{"operator":"IN"}`
	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/proto")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, body, capture.body)
}

func TestMiddleware_CanonicalNamesUnchanged(t *testing.T) {
	capture := &captureHandler{}
	mw := NewMiddleware(testRules, []string{testPath}, 0)
	handler := mw(capture)

	body := `{"operator":"SUBJECT_MAPPING_OPERATOR_ENUM_IN"}`
	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.JSONEq(t, body, capture.body)
}

func TestMiddleware_NumericEnumValuesPassThrough(t *testing.T) {
	capture := &captureHandler{}
	mw := NewMiddleware(testRules, []string{testPath}, 0)
	handler := mw(capture)

	// Numeric enum values (e.g., 1 for IN, 3 for IN_CONTAINS) are valid
	// protojson and should pass through the middleware unchanged.
	body := `{"booleanOperator":1,"conditions":[{"operator":3}]}`
	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.JSONEq(t, body, capture.body)
}

func TestMiddleware_ContentLengthUpdated(t *testing.T) {
	capture := &captureHandler{}
	mw := NewMiddleware(testRules, []string{testPath}, 0)
	handler := mw(capture)

	body := `{"operator":"IN"}`
	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// The normalized body is longer than the original
	require.Greater(t, len(capture.body), len(body))
}

func TestMiddleware_OversizedBodySkipsNormalization(t *testing.T) {
	capture := &captureHandler{}
	mw := NewMiddleware(testRules, []string{testPath}, 0)
	handler := mw(capture)

	// Build a body that exceeds the default max body size (1 MB).
	oversized := `{"operator":"` + strings.Repeat("A", defaultMaxBodySize) + `"}`
	req := httptest.NewRequest(http.MethodPost, testPath, strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// The middleware should skip normalization on read error and forward the
	// request. The downstream handler receives whatever MaxBytesReader yielded
	// before the limit — NOT a normalized body.
	assert.NotContains(t, capture.body, "SUBJECT_MAPPING_OPERATOR_ENUM_")
}
