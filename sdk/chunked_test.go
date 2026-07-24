package sdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestChunkedRoundTrip writes segments through NewChunkedWriter and
// reads the resulting TDF back through the mainline SDK.LoadTDF path
// (single-KAS, RSA-2048), verifying end-to-end interop.
func TestChunkedRoundTrip(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	chunks := [][]byte{[]byte("hello, "), []byte("chunked "), []byte("world!")}
	body := writeChunkedSegments(ctx, t, writer, chunks)

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.NotNil(t, fin.Manifest)

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello, chunked world!"), plain)
}

// TestChunkedKeepSegments verifies WithChunkedSegments trims the
// manifest to a contiguous prefix and the mainline reader decrypts
// only the retained segments.
func TestChunkedKeepSegments(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, writer, [][]byte{
		[]byte("keep-0-"), []byte("keep-1-"), []byte("drop-2!"),
	})
	fin, err := writer.Finalize(ctx, WithChunkedSegments([]int{0, 1}))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 2)

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("keep-0-keep-1-"), plain)
}

// TestChunkedFinalizeRejectsAssertions verifies that supplying
// assertions to Finalize returns the sentinel error until assertion
// signing is wired.
func TestChunkedFinalizeRejectsAssertions(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)
	_, err = writer.WriteSegment(ctx, 0, []byte("x"))
	require.NoError(t, err)

	_, err = writer.Finalize(ctx, WithChunkedAssertions([]AssertionConfig{
		{ID: "a", Type: BaseAssertion, Scope: PayloadScope, AppliesToState: Unencrypted},
	}))
	require.ErrorIs(t, err, ErrChunkedAssertionsUnsupported)
}

// writeChunkedSegments writes each element of segments as an ordered
// segment and returns the concatenated ciphertext produced by the
// writer.
func writeChunkedSegments(ctx context.Context, t *testing.T, w ChunkedWriter, segments [][]byte) []byte {
	t.Helper()
	var body bytes.Buffer
	for i, chunk := range segments {
		seg, err := w.WriteSegment(ctx, i, chunk)
		require.NoError(t, err)
		_, err = io.Copy(&body, seg.TDFData)
		require.NoError(t, err)
	}
	return body.Bytes()
}

// chunkedFakeKAS bundles an in-process RSA-2048 KAS + the httptest
// server it is registered on. Rewrap only handles the "wrapped"
// (RSA-OAEP) KeyType — matches what DefaultKeySplitter emits
// against an RSA-2048 KAS public key.
type chunkedFakeKAS struct {
	kasconnect.UnimplementedAccessServiceHandler
	privatePEM string
	publicPEM  string
	kid        string
	url        string
	server     *httptest.Server
}

// newChunkedFakeKAS starts an httptest server hosting a fake KAS with
// a freshly-generated RSA-2048 keypair.
func newChunkedFakeKAS(t *testing.T) *chunkedFakeKAS {
	t.Helper()
	pair, err := ocrypto.NewRSAKeyPair(2048)
	require.NoError(t, err)
	pubPEM, err := pair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privPEM, err := pair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	kas := &chunkedFakeKAS{
		privatePEM: privPEM,
		publicPEM:  pubPEM,
		kid:        "chunked-test-kid",
	}
	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(kas)
	mux.Handle(path, handler)
	kas.server = httptest.NewServer(mux)
	kas.url = kas.server.URL
	return kas
}

// Rewrap unwraps every RSA-wrapped KAO under the KAS private key and
// re-wraps under the caller's session public key.
func (k *chunkedFakeKAS) Rewrap(_ context.Context, in *connect.Request[kaspb.RewrapRequest]) (*connect.Response[kaspb.RewrapResponse], error) {
	tok, err := jwt.ParseInsecure([]byte(in.Msg.GetSignedRequestToken()))
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}
	rawBody, ok := tok.Get("requestBody")
	if !ok {
		return nil, errors.New("requestBody missing from token")
	}
	bodyStr, ok := rawBody.(string)
	if !ok {
		return nil, errors.New("requestBody not a string")
	}
	body := kaspb.UnsignedRewrapRequest{}
	if err := protojson.Unmarshal([]byte(bodyStr), &body); err != nil {
		return nil, fmt.Errorf("unmarshal request body: %w", err)
	}

	dec, err := ocrypto.FromPrivatePEM(k.privatePEM)
	if err != nil {
		return nil, fmt.Errorf("kas priv: %w", err)
	}
	enc, err := ocrypto.FromPublicPEM(body.GetClientPublicKey())
	if err != nil {
		return nil, fmt.Errorf("client pub: %w", err)
	}

	resp := &kaspb.RewrapResponse{}
	for _, req := range body.GetRequests() {
		policyResult := &kaspb.PolicyRewrapResult{PolicyId: req.GetPolicy().GetId()}
		for _, kaoReq := range req.GetKeyAccessObjects() {
			kao := kaoReq.GetKeyAccessObject()
			if kao.GetKeyType() != "wrapped" {
				return nil, fmt.Errorf("unsupported key type %q", kao.GetKeyType())
			}
			share, err := dec.Decrypt(kao.GetWrappedKey())
			if err != nil {
				return nil, fmt.Errorf("unwrap: %w", err)
			}
			wrapped, err := enc.Encrypt(share)
			if err != nil {
				return nil, fmt.Errorf("rewrap: %w", err)
			}
			policyResult.Results = append(policyResult.Results, &kaspb.KeyAccessRewrapResult{
				Result:            &kaspb.KeyAccessRewrapResult_KasWrappedKey{KasWrappedKey: wrapped},
				Status:            "permit",
				KeyAccessObjectId: kaoReq.GetKeyAccessObjectId(),
			})
		}
		resp.Responses = append(resp.Responses, policyResult)
	}
	return connect.NewResponse(resp), nil
}

// simpleKey returns the KAS descriptor the writer accepts.
func (k *chunkedFakeKAS) simpleKey() *policy.SimpleKasKey {
	return &policy.SimpleKasKey{
		KasUri: k.url,
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       k.kid,
			Pem:       k.publicPEM,
		},
	}
}

// newChunkedTestSDK builds a minimal SDK value wired to the fake KAS.
// The SDK is package-private-field constructed to skip New()'s
// platform-lookup requirement — LoadTDF only needs conn and
// tokenSource.
func newChunkedTestSDK(t *testing.T, _ *chunkedFakeKAS) SDK {
	t.Helper()
	ats := getTokenSource(t)
	return SDK{
		conn:        &ConnectRPCConnection{Client: http.DefaultClient},
		tokenSource: ats,
	}
}
