package sdk

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// TestChunkedAssertions verifies Finalize signs assertions with the
// writer's DEK and that the mainline reader verifies them.
func TestChunkedAssertions(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("assert me")})
	fin, err := writer.Finalize(ctx, WithChunkedAssertions([]AssertionConfig{{
		ID:             "assertion-1",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "json",
			Schema: "urn:example:chunked",
			Value:  `{"chunked":true}`,
		},
	}}))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Assertions, 1)
	assert.NotEmpty(t, fin.Manifest.Assertions[0].Binding.Signature)

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	// Reading verifies the assertion signature against the payload key.
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("assert me"), plain)
}

// TestChunkedOutOfOrderWrites exercises the core value proposition of
// ChunkedWriter: segments may be written in any order provided the
// caller concatenates TDFData in index order before Finalize.Data.
func TestChunkedOutOfOrderWrites(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)

	writer, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
	)
	require.NoError(t, err)

	chunks := [][]byte{[]byte("aaa-"), []byte("bbb-"), []byte("ccc-"), []byte("ddd!")}

	// Write in scrambled order: 2, 0, 3, 1.
	segBytes := make([][]byte, len(chunks))
	for _, idx := range []int{2, 0, 3, 1} {
		seg, err := writer.WriteSegment(ctx, idx, chunks[idx])
		require.NoError(t, err)
		buf, err := io.ReadAll(seg.TDFData)
		require.NoError(t, err)
		segBytes[idx] = buf
	}

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.Equal(t, 4, fin.TotalSegments)

	// Concat in INDEX order (segment 0 carries the ZIP local header).
	var body bytes.Buffer
	for _, buf := range segBytes {
		body.Write(buf)
	}
	body.Write(fin.Data)

	reader, err := s.LoadTDF(bytes.NewReader(body.Bytes()),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("aaa-bbb-ccc-ddd!"), plain)
}

// TestChunkedClockThreadedToZipHeaders verifies WithChunkedClock is
// threaded into the zipstream layer so every ZIP entry ModTime
// stamps from the injected clock rather than time.Now. This is the
// invariant that enables byte-deterministic ZIP headers for xtest
// fixtures (DEK / session-key randomness still varies the payload
// and KAS-wrap ciphertexts, which is not the scope of this test).
func TestChunkedClockThreadedToZipHeaders(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	// Pick a 2-second-aligned instant so DOS timestamp truncation is
	// a no-op.
	pinned := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	s := newChunkedTestSDK(t, kasBundle)

	w, err := s.NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedClock(FixedClock{T: pinned}),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, w, [][]byte{[]byte("payload-abc")})
	fin, err := w.Finalize(ctx)
	require.NoError(t, err)

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	zr, err := zip.NewReader(bytes.NewReader(tdfBytes), int64(len(tdfBytes)))
	require.NoError(t, err)
	require.NotEmpty(t, zr.File)

	for _, f := range zr.File {
		// archive/zip normalises DOS timestamps to the local zone; compare in UTC.
		assert.Equal(t, pinned, f.Modified.UTC(),
			"entry %q ModTime must match injected clock", f.Name)
	}
}

// TestChunkedDuplicateSegment verifies WriteSegment rejects an index
// that was already written.
func TestChunkedDuplicateSegment(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("first"))
	require.NoError(t, err)
	_, err = w.WriteSegment(ctx, 0, []byte("second"))
	require.ErrorIs(t, err, ErrChunkedSegmentAlreadyWritten)
}

// TestChunkedNegativeIndex verifies WriteSegment rejects a negative
// segment index.
func TestChunkedNegativeIndex(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, -1, []byte("x"))
	require.ErrorIs(t, err, ErrChunkedInvalidSegmentIndex)
}

// TestChunkedWriteAfterFinalize verifies WriteSegment fails once the
// writer has been finalized.
func TestChunkedWriteAfterFinalize(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("x"))
	require.NoError(t, err)
	_, err = w.Finalize(ctx)
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 1, []byte("late"))
	require.ErrorIs(t, err, ErrChunkedAlreadyFinalized)
}

// TestChunkedDoubleFinalize verifies Finalize is not idempotent and
// returns the sentinel on the second call.
func TestChunkedDoubleFinalize(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("x"))
	require.NoError(t, err)
	_, err = w.Finalize(ctx)
	require.NoError(t, err)
	_, err = w.Finalize(ctx)
	require.ErrorIs(t, err, ErrChunkedAlreadyFinalized)
}

// TestChunkedKeepSegmentsNonContiguous verifies WithChunkedSegments
// rejects a non-contiguous prefix.
func TestChunkedKeepSegmentsNonContiguous(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	for i, chunk := range [][]byte{[]byte("a"), []byte("b"), []byte("c")} {
		_, err = w.WriteSegment(ctx, i, chunk)
		require.NoError(t, err)
	}
	_, err = w.Finalize(ctx, WithChunkedSegments([]int{0, 2}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "contiguous prefix")
}

// TestChunkedKeepSegmentsUnwritten verifies WithChunkedSegments
// rejects a keep list that names an index the caller never wrote.
func TestChunkedKeepSegmentsUnwritten(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("only-zero"))
	require.NoError(t, err)
	_, err = w.Finalize(ctx, WithChunkedSegments([]int{0, 1}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not written")
}

// TestChunkedGetManifestBeforeFinalize verifies GetManifest returns a
// snapshot of the currently-written segments prior to Finalize and
// the frozen manifest afterwards.
func TestChunkedGetManifestBeforeFinalize(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	s := newChunkedTestSDK(t, kasBundle)
	w, err := s.NewChunkedWriter(ctx, WithChunkedDefaultKAS(kasBundle.simpleKey()))
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("first"))
	require.NoError(t, err)
	_, err = w.WriteSegment(ctx, 1, []byte("second"))
	require.NoError(t, err)

	snap, err := w.GetManifest(ctx)
	require.NoError(t, err)
	require.NotNil(t, snap)
	assert.Len(t, snap.Segments, 2)

	fin, err := w.Finalize(ctx)
	require.NoError(t, err)

	frozen, err := w.GetManifest(ctx)
	require.NoError(t, err)
	assert.Equal(t, fin.Manifest.Method.Algorithm, frozen.Method.Algorithm)
	assert.Len(t, frozen.Segments, 2)
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
