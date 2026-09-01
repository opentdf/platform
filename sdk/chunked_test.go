package sdk

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/internal/zipstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestChunkedRoundTrip writes segments through NewChunkedWriter and
// reads the resulting TDF back through the mainline SDK.LoadTDF path
// (single-KAS, RSA-2048), verifying end-to-end interop.
func TestChunkedRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t)

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

// TestChunkedKeepSegments verifies WithChunkedSegments trims trailing
// segments from the manifest and the mainline reader decrypts only the
// retained ones.
func TestChunkedKeepSegments(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t)

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

// TestChunkedKeepSegmentsRequiresDroppedBytesAppended pins the
// invariant WithChunkedSegments documents: dropping a segment from
// the manifest does not shrink the archive, because CleanupSegment is
// never called for a trimmed index, so the archive's recorded size
// and CRC already include it. Omitting a dropped segment's bytes when
// assembling the file must not silently produce a readable TDF.
func TestChunkedKeepSegmentsRequiresDroppedBytesAppended(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t)

	seg0, err := writer.WriteSegment(ctx, 0, []byte("keep-0-"))
	require.NoError(t, err)
	seg0Bytes, err := io.ReadAll(seg0.TDFData)
	require.NoError(t, err)

	seg1, err := writer.WriteSegment(ctx, 1, []byte("keep-1-"))
	require.NoError(t, err)
	seg1Bytes, err := io.ReadAll(seg1.TDFData)
	require.NoError(t, err)

	// Written but dropped from the manifest below -- and its bytes are
	// omitted from the assembled file too, the mistake the doc now
	// warns against.
	_, err = writer.WriteSegment(ctx, 2, []byte("drop-2!"))
	require.NoError(t, err)

	fin, err := writer.Finalize(ctx, WithChunkedSegments([]int{0, 1}))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 2)

	shortBytes := bytes.Join([][]byte{seg0Bytes, seg1Bytes, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(shortBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	require.Error(t, err, "an archive missing a written-but-dropped segment's bytes must not read back cleanly")
}

// TestChunkedFinalizeSignsAssertions verifies assertions supplied to
// Finalize land in the manifest signed with the default HS256-over-DEK
// key, and that the mainline reader verifies them on the way back out.
func TestChunkedFinalizeSignsAssertions(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t)

	body := writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("asserted payload")})

	fin, err := writer.Finalize(ctx, WithChunkedAssertions([]AssertionConfig{{
		ID:             "a",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement:      Statement{Format: "json", Schema: "urn:test", Value: `{"k":"v"}`},
	}}))
	require.NoError(t, err)

	require.Len(t, fin.Manifest.Assertions, 1)
	got := fin.Manifest.Assertions[0]
	assert.Equal(t, "a", got.ID)
	assert.Equal(t, JWS.String(), got.Binding.Method)
	assert.NotEmpty(t, got.Binding.Signature)

	// The reader recomputes the aggregate hash and re-verifies the
	// binding, so a round trip is the real check that the assertion was
	// bound to this payload and not merely well-formed.
	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("asserted payload"), plain)
}

// TestChunkedOutOfOrderWrites exercises the core value proposition of
// ChunkedWriter: segments may be written in any order provided the
// caller concatenates TDFData in index order before Finalize.Data.
func TestChunkedOutOfOrderWrites(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t)

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

// TestChunkedClockThreadedToZipHeaders verifies withChunkedClock is
// threaded into the zipstream layer so every ZIP entry ModTime
// stamps from the injected clock rather than time.Now. This is the
// invariant that enables byte-deterministic ZIP headers for xtest
// fixtures (DEK / session-key randomness still varies the payload
// and KAS-wrap ciphertexts, which is not the scope of this test).
func TestChunkedClockThreadedToZipHeaders(t *testing.T) {
	ctx := context.Background()

	// Pick a 2-second-aligned instant so DOS timestamp truncation is
	// a no-op.
	pinned := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	w, _ := newChunkedWriterForTest(ctx, t, withChunkedClock(fixedClock{T: pinned}))

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

// TestChunkedRejectsInvalidSequencing pins the sentinel each of
// WriteSegment and Finalize returns for a call that is out of sequence
// with the writer's lifecycle.
func TestChunkedRejectsInvalidSequencing(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		provoke func(t *testing.T, w ChunkedWriter) error
		wantErr error
	}{
		{
			name: "duplicate segment",
			provoke: func(t *testing.T, w ChunkedWriter) error {
				t.Helper()
				_, err := w.WriteSegment(ctx, 0, []byte("first"))
				require.NoError(t, err)
				_, err = w.WriteSegment(ctx, 0, []byte("second"))
				return err
			},
			wantErr: ErrChunkedSegmentAlreadyWritten,
		},
		{
			name: "negative index",
			provoke: func(_ *testing.T, w ChunkedWriter) error {
				_, err := w.WriteSegment(ctx, -1, []byte("x"))
				return err
			},
			wantErr: ErrChunkedInvalidSegmentIndex,
		},
		{
			name: "write after finalize",
			provoke: func(t *testing.T, w ChunkedWriter) error {
				t.Helper()
				_, err := w.WriteSegment(ctx, 0, []byte("x"))
				require.NoError(t, err)
				_, err = w.Finalize(ctx)
				require.NoError(t, err)
				_, err = w.WriteSegment(ctx, 1, []byte("late"))
				return err
			},
			wantErr: ErrChunkedAlreadyFinalized,
		},
		{
			name: "double finalize",
			provoke: func(t *testing.T, w ChunkedWriter) error {
				t.Helper()
				_, err := w.WriteSegment(ctx, 0, []byte("x"))
				require.NoError(t, err)
				_, err = w.Finalize(ctx)
				require.NoError(t, err)
				_, err = w.Finalize(ctx)
				return err
			},
			wantErr: ErrChunkedAlreadyFinalized,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := newChunkedWriterForTest(ctx, t)
			require.ErrorIs(t, tc.provoke(t, w), tc.wantErr)
		})
	}
}

// TestChunkedKeepSegmentsSparse verifies WithChunkedSegments accepts a
// sparse index set. This is the S3 multipart shape: each upload part
// reserves a fixed block of indices and fills only the front of it, so
// the written indices have large gaps but are still emitted in order.
func TestChunkedKeepSegmentsSparse(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	w, kasBundle := newChunkedWriterForTest(ctx, t)

	const stride = 5000
	chunks := map[int][]byte{
		0:          []byte("part1-a-"),
		1:          []byte("part1-b-"),
		stride:     []byte("part2-a-"),
		stride + 1: []byte("part2-b"),
	}
	indices := []int{0, 1, stride, stride + 1}

	// Write out of order to prove the index, not the call order,
	// determines layout.
	encrypted := make(map[int][]byte, len(indices))
	for _, idx := range []int{stride, 0, stride + 1, 1} {
		seg, err := w.WriteSegment(ctx, idx, chunks[idx])
		require.NoError(t, err)
		buf, err := io.ReadAll(seg.TDFData)
		require.NoError(t, err)
		encrypted[idx] = buf
	}

	// Concatenate in ascending index order, as the contract requires.
	var body bytes.Buffer
	for _, idx := range indices {
		body.Write(encrypted[idx])
	}

	fin, err := w.Finalize(ctx, WithChunkedSegments(indices))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, len(indices))

	tdfBytes := bytes.Join([][]byte{body.Bytes(), fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("part1-a-part1-b-part2-a-part2-b"), plain)
}

// TestChunkedKeepSegmentsRejects pins the validation Finalize applies to
// WithChunkedSegments: the keep list must name only written indices, in
// strictly ascending order, with no gaps that would shift a later
// segment's offset.
func TestChunkedKeepSegmentsRejects(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name       string
		writes     []int
		keep       []int
		wantErrSub string
	}{
		// Dropping segment 1 while keeping 2 would shift 2's offset and
		// make the payload unreadable.
		{"skips a written segment", []int{0, 1, 2}, []int{0, 2}, "ascending index order"},
		// Rejected even though every named index was written.
		{"descending order", []int{0, 1}, []int{1, 0}, "ascending index order"},
		{"names an unwritten index", []int{0, 5}, []int{0, 1}, "not written"},
		{"longer than the written set", []int{0}, []int{0, 1}, "only 1 were written"},
		// A repeat cannot be ascending, so it fails the ordering rule
		// rather than needing its own check.
		{"names an index twice", []int{0, 1}, []int{0, 0}, "ascending index order"},
		// WriteSegment never accepts a negative index, so it can only
		// ever be reported as unwritten.
		{"negative index", []int{0, 1}, []int{-1, 0}, "not written"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := newChunkedWriterForTest(ctx, t)
			for _, idx := range tc.writes {
				_, err := w.WriteSegment(ctx, idx, []byte("x"))
				require.NoError(t, err)
			}
			_, err := w.Finalize(ctx, WithChunkedSegments(tc.keep))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrSub)
		})
	}
}

// TestChunkedFinalizeRequiresSegmentZero pins the sentinel Finalize
// returns for a write set that omits segment 0, and that the rejection
// leaves the writer usable: the caller's only recovery is to write the
// missing segment and finalize again.
//
// The write set here -- indices 5 and 6, nothing lower -- is what a
// caller gets if it reserves a block of indices per upload part and
// part 0 never runs, or if it simply numbers parts from 1. Only
// segment 0 emits the payload's ZIP local file header (see
// zipstream.segmentWriter.WriteSegment), so the assembled bytes would
// not be a ZIP container at all; refusing is the only safe answer,
// since by Finalize the caller has already uploaded what it encrypted.
func TestChunkedFinalizeRequiresSegmentZero(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	w, kasBundle := newChunkedWriterForTest(ctx, t)

	encrypted := make(map[int][]byte, 3)
	write := func(index int, chunk string) {
		t.Helper()
		seg, err := w.WriteSegment(ctx, index, []byte(chunk))
		require.NoError(t, err)
		buf, err := io.ReadAll(seg.TDFData)
		require.NoError(t, err)
		encrypted[index] = buf
	}

	write(5, "hello-")
	write(6, "world!")

	_, err := w.Finalize(ctx)
	require.ErrorIs(t, err, ErrChunkedMissingSegmentZero)

	// A rejected Finalize must not consume the writer, or the caller has
	// no way back: the segments it already encrypted would be stranded.
	write(0, "zero-")
	fin, err := w.Finalize(ctx)
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 3)

	var body bytes.Buffer
	for _, idx := range []int{0, 5, 6} {
		body.Write(encrypted[idx])
	}
	body.Write(fin.Data)

	reader, err := s.LoadTDF(bytes.NewReader(body.Bytes()),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("zero-hello-world!"), plain)
}

// TestChunkedFinalizeWithNoSegments verifies an untouched writer fails
// with the same sentinel rather than the archive layer's wrapped
// "segment missing".
func TestChunkedFinalizeWithNoSegments(t *testing.T) {
	ctx := context.Background()
	w, _ := newChunkedWriterForTest(ctx, t)

	_, err := w.Finalize(ctx)
	require.ErrorIs(t, err, ErrChunkedMissingSegmentZero)
}

// TestChunkedGetManifestWithoutSegmentZero guards the placement of the
// segment-0 check. GetManifest shares buildManifest with Finalize but
// is a pre-finalize snapshot, so it must keep working while segment 0
// is still outstanding.
func TestChunkedGetManifestWithoutSegmentZero(t *testing.T) {
	ctx := context.Background()
	w, _ := newChunkedWriterForTest(ctx, t)

	_, err := w.WriteSegment(ctx, 5, []byte("hello-"))
	require.NoError(t, err)
	_, err = w.WriteSegment(ctx, 6, []byte("world!"))
	require.NoError(t, err)

	snap, err := w.GetManifest(ctx)
	require.NoError(t, err)
	assert.Len(t, snap.Segments, 2)
}

// TestChunkedGetManifestBeforeFinalize verifies GetManifest returns a
// snapshot of the currently-written segments prior to Finalize and
// the frozen manifest afterwards.
func TestChunkedGetManifestBeforeFinalize(t *testing.T) {
	ctx := context.Background()
	w, _ := newChunkedWriterForTest(ctx, t)

	_, err := w.WriteSegment(ctx, 0, []byte("first"))
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

// newChunkedWriterForTest starts a fake RSA-2048 KAS, registers its
// shutdown via t.Cleanup, and constructs a ChunkedWriter against it
// with opts layered on top of the default KAS option. Every case that
// expects NewChunkedWriter to succeed shares this setup; callers that
// need construction itself to fail build the fake KAS and call
// NewChunkedWriter directly instead.
func newChunkedWriterForTest(ctx context.Context, t *testing.T, opts ...ChunkedWriterOption) (ChunkedWriter, *chunkedFakeKAS) {
	t.Helper()
	kasBundle := newChunkedFakeKAS(t)
	t.Cleanup(kasBundle.server.Close)

	all := append([]ChunkedWriterOption{WithChunkedDefaultKAS(kasBundle.simpleKey())}, opts...)
	w, err := NewChunkedWriter(ctx, all...)
	require.NoError(t, err)
	return w, kasBundle
}

// Rewrap unwraps every RSA-wrapped KAO under the KAS private key and
// re-wraps under the caller's session public key.
//
// It verifies the policy binding before doing so, as a real KAS does. That
// check is the whole reason the binding exists: it is what stops a holder of
// one TDF from swapping in a looser policy and replaying the KAOs against it.
// A fake that skipped it would accept a writer that bound the policy under the
// wrong key, or in the wrong encoding, and the round-trip tests would still
// pass -- the binding is never consulted on the decrypt path.
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
			if kao.GetKeyType() != kWrapped {
				return nil, fmt.Errorf("unsupported key type %q", kao.GetKeyType())
			}
			share, err := dec.Decrypt(kao.GetWrappedKey())
			if err != nil {
				return nil, fmt.Errorf("unwrap: %w", err)
			}
			// Checked against the share, not the DEK: each KAO binds the
			// policy under its own split, which is what makes a binding
			// non-transferable between KAOs.
			if err := verifyChunkedPolicyBinding(kao.GetPolicyBinding(), share, req.GetPolicy().GetBody()); err != nil {
				return nil, fmt.Errorf("kao %q: %w", kaoReq.GetKeyAccessObjectId(), err)
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

// verifyChunkedPolicyBinding recomputes the HMAC a KAS checks before it will
// release a key share, and compares it constant-time to the one the KAO
// carries.
func verifyChunkedPolicyBinding(binding *kaspb.PolicyBinding, share []byte, base64Policy string) error {
	if binding == nil {
		return errors.New("policy binding missing")
	}
	// A KAS dispatches on the algorithm rather than assuming HMAC; an unknown
	// value is a refusal, not something to verify past.
	if binding.GetAlgorithm() != hmacIntegrityAlgorithm {
		return fmt.Errorf("unsupported policy binding algorithm %q", binding.GetAlgorithm())
	}
	want := string(ocrypto.Base64Encode([]byte(
		hex.EncodeToString(ocrypto.CalculateSHA256Hmac(share, []byte(base64Policy))),
	)))
	if subtle.ConstantTimeCompare([]byte(want), []byte(binding.GetHash())) != 1 {
		return errors.New("policy binding does not match the policy")
	}
	return nil
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

// newChunkedTestSDK builds a minimal SDK value for these tests. It is
// constructed from package-private fields to skip New()'s
// platform-lookup requirement, since LoadTDF only needs conn and
// tokenSource.
//
// Deliberately not wired to the fake KAS: the SDK never learns the KAS
// address. Each key access object carries its own URL, so the reader
// reaches the fake through the manifest. Pass the fake's URL to
// WithChunkedDefaultKAS when writing and WithKasAllowlist when
// reading.
func newChunkedTestSDK(t *testing.T) SDK {
	t.Helper()
	ats := getTokenSource(t)
	return SDK{
		conn:        &ConnectRPCConnection{Client: http.DefaultClient},
		tokenSource: ats,
	}
}

// TestChunkedKAOShape pins the key access object fields the chunked
// writer emits, so they cannot silently drift from the ones
// SDK.CreateTDF produces via the shared createKeyAccess helper.
func TestChunkedKAOShape(t *testing.T) {
	ctx := context.Background()
	writer, kasBundle := newChunkedWriterForTest(ctx, t)

	writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})
	fin, err := writer.Finalize(ctx, WithChunkedEncryptedMetadata("meta"))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.KeyAccessObjs, 1)

	kao := fin.Manifest.KeyAccessObjs[0]
	assert.Equal(t, kWrapped, kao.KeyType)
	assert.Equal(t, kKasProtocol, kao.Protocol)
	assert.Equal(t, keyAccessSchemaVersion, kao.SchemaVersion)
	assert.Equal(t, kasBundle.url, kao.KasURL)
	assert.Equal(t, kasBundle.kid, kao.KID)
	assert.NotEmpty(t, kao.WrappedKey)
	assert.NotEmpty(t, kao.EncryptedMetadata)

	binding, ok := kao.PolicyBinding.(PolicyBinding)
	require.True(t, ok, "policy binding should be a PolicyBinding, got %T", kao.PolicyBinding)
	assert.Equal(t, hmacIntegrityAlgorithm, binding.Alg)
	assert.NotEmpty(t, binding.Hash)
}

// TestChunkedECKeyAccess covers the EC wrapping path, which the
// round-trip tests miss because the fake KAS is RSA-only. It asserts
// the manifest key type is the one the real KAS dispatches on
// ("ec-wrapped", not "eccWrapped") and that the wrapped key actually
// decrypts under the KAS private key using the AES-GCM envelope the
// KAS rewrap path expects.
func TestChunkedECKeyAccess(t *testing.T) {
	pair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	require.NoError(t, err)
	pubPEM, err := pair.PublicKeyInPemFormat()
	require.NoError(t, err)
	privPEM, err := pair.PrivateKeyInPemFormat()
	require.NoError(t, err)

	const kasURL = "https://kas.example.com"
	dek := make([]byte, kKeySize)
	for i := range dek {
		dek[i] = byte(i)
	}
	shares := []splitShare{{
		data: dek,
		kases: []KASInfo{{
			URL:       kasURL,
			PublicKey: pubPEM,
			KID:       "ec-kid",
			Algorithm: string(ocrypto.EC256Key),
		}},
	}}

	kaos, err := buildKeyAccessObjects(shares, `{"uuid":"test"}`, "")
	require.NoError(t, err)
	require.Len(t, kaos, 1)

	kao := kaos[0]
	assert.Equal(t, kECWrapped, kao.KeyType, "KAS dispatches on this exact string")
	require.NotEmpty(t, kao.EphemeralPublicKey)

	// Unwrap the way service/kas/access/rewrap.go does for "ec-wrapped".
	keySize, err := ocrypto.GetECKeySize([]byte(kao.EphemeralPublicKey))
	require.NoError(t, err)
	mode, err := ocrypto.ECSizeToMode(keySize)
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(kao.EphemeralPublicKey))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	compressed, err := ocrypto.CompressedECPublicKey(mode, *ecPub)
	require.NoError(t, err)

	priv, err := ocrypto.ECPrivateKeyFromPem([]byte(privPEM))
	require.NoError(t, err)
	dec, err := ocrypto.NewSaltedECDecryptor(priv, tdfSalt(), nil)
	require.NoError(t, err)

	wrapped, err := ocrypto.Base64Decode([]byte(kao.WrappedKey))
	require.NoError(t, err)
	unwrapped, err := dec.DecryptWithEphemeralKey(wrapped, compressed)
	require.NoError(t, err, "KAS must be able to unwrap the EC-wrapped DEK")
	assert.Equal(t, dek, unwrapped)
}

// TestChunkedKeyAccessRejectsShareWithNoKAS pins the per-split
// invariant. Each split is one XOR share of the DEK, so a share that
// gets no key access object of its own is unrecoverable -- and the
// reader cannot tell: it builds its split set from the KAOs actually
// present in the manifest, so the missing share passes the
// completeness check, the DEK reconstructs wrong, and the failure
// surfaces as ErrRootSignatureFailure, which reads as tampering.
// Failing at creation is the only point where the cause is still
// visible.
func TestChunkedKeyAccessRejectsShareWithNoKAS(t *testing.T) {
	pair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	require.NoError(t, err)
	pubPEM, err := pair.PublicKeyInPemFormat()
	require.NoError(t, err)

	const kasURL = "https://kas.example.com"
	dek := make([]byte, kKeySize)
	shares := []splitShare{
		{
			id:   "wrapped",
			data: dek,
			kases: []KASInfo{{
				URL:       kasURL,
				PublicKey: pubPEM,
				KID:       "ec-kid",
				Algorithm: string(ocrypto.EC256Key),
			}},
		},
		{id: "orphaned", data: dek},
	}

	_, err = buildKeyAccessObjects(shares, `{"uuid":"test"}`, "")
	require.Error(t, err, "a share with no KAS to unwrap it makes the DEK unrecoverable")
	assert.Contains(t, err.Error(), "orphaned", "the error must name the split that cannot be recovered")
}

// TestChunkedFinalizeManifestIsIndependent checks that the manifest
// Finalize hands back is not the one the writer keeps. GetManifest
// clones for this reason; returning the original from Finalize would
// let a caller's edit come back out of a later GetManifest, or race
// one.
func TestChunkedFinalizeManifestIsIndependent(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)

	_, err := writer.WriteSegment(ctx, 0, []byte("payload"))
	require.NoError(t, err)
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, fin.Manifest.Segments)

	wantVersion := fin.Manifest.TDFVersion
	wantHash := fin.Manifest.Segments[0].Hash
	fin.Manifest.TDFVersion = "mutated"
	fin.Manifest.Segments[0].Hash = "mutated"

	got, err := writer.GetManifest(ctx)
	require.NoError(t, err)
	assert.Equal(t, wantVersion, got.TDFVersion)
	assert.Equal(t, wantHash, got.Segments[0].Hash)
}

// TestChunkedLegacyTargetMode verifies that a pre-4.3.0 target mode
// produces the doubly-encoded (hex-then-base64) signatures that legacy
// readers require, and that the mainline reader -- which infers legacy
// mode solely from a missing schemaVersion -- still round-trips it.
func TestChunkedLegacyTargetMode(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t, WithChunkedTargetMode("4.2.2"))

	body := writeChunkedSegments(ctx, t, writer, [][]byte{
		[]byte("legacy "), []byte("hex "), []byte("payload"),
	})
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	// Absence of schemaVersion is the pre-4.3.0 marker readers key on.
	assert.Empty(t, fin.Manifest.TDFVersion, "legacy manifest must omit schemaVersion")

	// A legacy signature is base64(hex(mac)), so it decodes to twice
	// the MAC length: 64 for the 32-byte HS256 root, 32 for a 16-byte
	// GMAC segment tag. The 4.3.0 form is base64(mac), half of each.
	rootSig, err := ocrypto.Base64Decode([]byte(fin.Manifest.Signature))
	require.NoError(t, err)
	assert.Len(t, rootSig, 64, "root signature must be hex-encoded before base64")

	for i, seg := range fin.Manifest.Segments {
		segSig, err := ocrypto.Base64Decode([]byte(seg.Hash))
		require.NoError(t, err)
		assert.Lenf(t, segSig, 2*kGMACPayloadLength, "segment %d hash must be hex-encoded before base64", i)
	}

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("legacy hex payload"), plain)
}

// TestChunkedCurrentTargetMode pins the 4.3.0-and-later form so a
// regression in either direction is caught.
func TestChunkedCurrentTargetMode(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t, WithChunkedTargetMode("4.3.0"))

	body := writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("current")})
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	assert.Equal(t, TDFSpecVersion, fin.Manifest.TDFVersion)

	rootSig, err := ocrypto.Base64Decode([]byte(fin.Manifest.Signature))
	require.NoError(t, err)
	assert.Len(t, rootSig, 32, "root signature must be the raw HMAC, not hex")

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("current"), plain)
}

// TestChunkedTargetModeInvalid rejects a non-semver target mode at
// construction rather than at Finalize.
func TestChunkedTargetModeInvalid(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	_, err := NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedTargetMode("not-a-version"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-version")
}

// TestChunkedOptionsRejectNil checks that the injection-seam options
// refuse a nil value instead of storing it. A stored nil is
// indistinguishable from an unset field, so no default gets installed
// and the nil surfaces as a panic partway through writing -- for the
// key splitter, not until Finalize, after the caller has already
// encrypted and uploaded every segment.
func TestChunkedOptionsRejectNil(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	for _, tc := range []struct {
		name string
		opt  ChunkedWriterOption
	}{
		{"archive writer factory", withChunkedArchiveWriterFactory(nil)},
		{"cipher factory", withChunkedCipherFactory(nil)},
		{"clock", withChunkedClock(nil)},
		{"key splitter", WithChunkedKeySplitter(nil)},
		{"rand", withChunkedRand(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer, err := NewChunkedWriter(ctx,
				WithChunkedDefaultKAS(kasBundle.simpleKey()),
				tc.opt,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must not be nil")
			assert.Nil(t, writer)
		})
	}
}

// TestChunkedIntegrityAlgorithmsAreFixed pins the only two algorithms
// the writer emits: an HS256 root over the aggregate hash, and GMAC
// segment hashes read out of the AEAD tag.
func TestChunkedIntegrityAlgorithmsAreFixed(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)

	_, err := writer.WriteSegment(ctx, 0, []byte("first"))
	require.NoError(t, err)

	// Segment 1, not 0: only segment 0's TDFData carries the payload's
	// ZIP local file header, so 1 is exactly the bytes that were hashed.
	second, err := writer.WriteSegment(ctx, 1, []byte("second"))
	require.NoError(t, err)
	sealed, err := io.ReadAll(second.TDFData)
	require.NoError(t, err)

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	assert.Equal(t, hmacIntegrityAlgorithm, fin.Manifest.Algorithm)
	assert.Equal(t, gmacIntegrityAlgorithm, fin.Manifest.SegmentHashAlgorithm)

	// The hash is the AEAD tag itself, not an HMAC over the same bytes.
	segHash, err := ocrypto.Base64Decode([]byte(second.Hash))
	require.NoError(t, err)
	require.Len(t, sealed, int(second.EncryptedSize))
	assert.Equal(t, sealed[len(sealed)-kGMACPayloadLength:], segHash)
}

// errArchiveWriteFailed is the injected archive failure used to drive
// WriteSegment's error paths.
var (
	errArchiveWriteFailed   = errors.New("archive write failed")
	errArchiveCleanupFailed = errors.New("archive cleanup failed")
)

// flakyArchiveWriter fails the first failures writes of one chosen
// segment index and delegates everything else to a real segment
// writer, so the archive itself stays consistent.
type flakyArchiveWriter struct {
	zipstream.SegmentWriter
	failIndex int
	failures  int
}

func (f *flakyArchiveWriter) WriteSegment(ctx context.Context, index int, size uint64, crc32 uint32) ([]byte, error) {
	if index == f.failIndex && f.failures > 0 {
		f.failures--
		return nil, errArchiveWriteFailed
	}
	return f.SegmentWriter.WriteSegment(ctx, index, size, crc32)
}

// flakyArchiveWriterFactory returns a withChunkedArchiveWriterFactory
// option whose archive fails the first failures writes to failIndex.
func flakyArchiveWriterFactory(failIndex, failures int) ChunkedWriterOption {
	return withChunkedArchiveWriterFactory(func(clock clock) zipstream.SegmentWriter {
		return &flakyArchiveWriter{
			SegmentWriter: defaultArchiveWriterFactory(clock),
			failIndex:     failIndex,
			failures:      failures,
		}
	})
}

// TestChunkedArchiveFailureKeepsManifestHonest checks that a segment
// whose bytes never reached the archive is not described in the
// manifest. A manifest covering bytes the caller never received leaves
// the reader mapping every later segment at the wrong payload offset,
// so the metadata is published only once the archive has accepted it.
//
// Skipping the index rather than retrying it is legal here — segment
// indices are ordering keys, not positions, so a sparse set finalizes
// normally (see segmentOrderLocked). Only index 0 is special, because
// it carries the ZIP local file header.
func TestChunkedArchiveFailureKeepsManifestHonest(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t, flakyArchiveWriterFactory(1, 1))

	var body bytes.Buffer
	write := func(index int, chunk string) error {
		seg, err := writer.WriteSegment(ctx, index, []byte(chunk))
		if err != nil {
			return err
		}
		_, err = io.Copy(&body, seg.TDFData)
		return err
	}

	require.NoError(t, write(0, "first "))

	// Rejected by the archive, so the caller gets no bytes to append.
	require.ErrorIs(t, write(1, "second "), errArchiveWriteFailed)

	require.NoError(t, write(2, "third"))

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	body.Write(fin.Data)

	require.Len(t, fin.Manifest.Segments, 2,
		"manifest must not describe the segment the archive rejected")

	reader, err := s.LoadTDF(bytes.NewReader(body.Bytes()),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "first third", string(plain))
}

// TestChunkedSegmentRetryAfterArchiveFailure checks that a failed write
// releases its index, so a transient archive failure leaves the index
// writable rather than permanently blocking Finalize.
func TestChunkedSegmentRetryAfterArchiveFailure(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t, flakyArchiveWriterFactory(1, 1))

	var body bytes.Buffer
	write := func(index int, chunk string) error {
		seg, err := writer.WriteSegment(ctx, index, []byte(chunk))
		if err != nil {
			return err
		}
		_, err = io.Copy(&body, seg.TDFData)
		require.NoError(t, err)
		return nil
	}

	require.NoError(t, write(0, "hello, "))

	err := write(1, "chunked ")
	require.ErrorIs(t, err, errArchiveWriteFailed)

	// The same index must be usable again.
	require.NoError(t, write(1, "chunked "), "a failed segment must be retryable")
	require.NoError(t, write(2, "world!"))

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	tdfBytes := bytes.Join([][]byte{body.Bytes(), fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello, chunked world!"), plain)
}

// postWriteFailArchiveWriter delegates WriteSegment to a real writer
// -- so the archive's internal state is actually mutated -- and only
// then reports failure for one chosen index. Unlike
// flakyArchiveWriter, which fails before delegating, this exercises
// cleanup paths that only matter once the archive has partially
// accepted a write. cleanedUp records every CleanupSegment call so a
// test can assert release() actually rolls the archive back, not
// just the sdk-level reservation.
type postWriteFailArchiveWriter struct {
	zipstream.SegmentWriter
	failIndex int
	failures  int
	cleanedUp []int

	// writer, when set, lets CleanupSegment observe the sdk-level
	// reservation for the index it is rolling back. Each cleanup call
	// appends what it saw to reservedDuringCleanup.
	writer                *chunkedWriter
	reservedDuringCleanup []bool
}

func (f *postWriteFailArchiveWriter) WriteSegment(ctx context.Context, index int, size uint64, crc32 uint32) ([]byte, error) {
	header, err := f.SegmentWriter.WriteSegment(ctx, index, size, crc32)
	if err != nil {
		return header, err
	}
	if index == f.failIndex && f.failures > 0 {
		f.failures--
		return nil, errArchiveWriteFailed
	}
	return header, nil
}

func (f *postWriteFailArchiveWriter) CleanupSegment(index int) error {
	f.cleanedUp = append(f.cleanedUp, index)
	if f.writer != nil {
		f.writer.mu.RLock()
		_, held := f.writer.segments[index]
		f.writer.mu.RUnlock()
		f.reservedDuringCleanup = append(f.reservedDuringCleanup, held)
	}
	return f.SegmentWriter.CleanupSegment(index)
}

// TestChunkedWriteSegmentCleansUpArchiveOnFailure checks that a
// segment the archive already accepted internally, but that
// WriteSegment then reports as failed, is rolled back via
// CleanupSegment rather than merely dropped from the sdk-level
// reservation map. Without this, a retry sees the archive's own
// bookkeeping for the index still present and fails a second time
// with an unrelated duplicate-segment error instead of succeeding.
//
// The rollback has to undo the archive's size and CRC accounting too,
// not just its record of the index, so the test carries on to a real
// TDF: the failed attempt's bytes were never handed to the caller, and
// if the archive still counted them every offset after segment 1 would
// be wrong. Only reading the payload back proves it does not.
func TestChunkedWriteSegmentCleansUpArchiveOnFailure(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	archive := &postWriteFailArchiveWriter{failIndex: 1, failures: 1}
	writer, kasBundle := newChunkedWriterForTest(ctx, t, withChunkedArchiveWriterFactory(func(c clock) zipstream.SegmentWriter {
		archive.SegmentWriter = defaultArchiveWriterFactory(c)
		return archive
	}))

	var body bytes.Buffer
	write := func(index int, chunk string) error {
		seg, err := writer.WriteSegment(ctx, index, []byte(chunk))
		if err != nil {
			return err
		}
		_, err = io.Copy(&body, seg.TDFData)
		require.NoError(t, err)
		return nil
	}

	require.NoError(t, write(0, "hello, "))

	require.ErrorIs(t, write(1, "doomed"), errArchiveWriteFailed)
	assert.Equal(t, []int{1}, archive.cleanedUp)

	// Deliberately a different length from the failed attempt: if the
	// archive kept the doomed write's size, the mismatch shows up as a
	// corrupt payload rather than being masked by identical accounting.
	require.NoError(t, write(1, "chunked "),
		"the archive's own record of the failed attempt must be rolled back, not just the sdk-level reservation")
	require.NoError(t, write(2, "world!"))

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 3)
	body.Write(fin.Data)

	reader, err := s.LoadTDF(bytes.NewReader(body.Bytes()),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello, chunked world!"), plain)
}

// TestChunkedCleanupRunsBeforeReleasingIndex pins the ordering of the
// two halves of the rollback. CleanupSegment addresses an index, not a
// particular attempt at it, so the reservation has to outlive it: if
// the index were released first, a racing write could claim it and get
// its bytes accepted by the archive, only for the losing attempt's
// cleanup to delete that record and roll back its size accounting.
// The winner would then publish segment metadata for bytes the archive
// no longer knows about.
//
// Observing the reservation from inside CleanupSegment pins the
// ordering directly, without needing a goroutine to lose the race
// often enough to be reliable.
func TestChunkedCleanupRunsBeforeReleasingIndex(t *testing.T) {
	ctx := context.Background()
	archive := &postWriteFailArchiveWriter{failIndex: 1, failures: 1}
	writer, _ := newChunkedWriterForTest(ctx, t, withChunkedArchiveWriterFactory(func(c clock) zipstream.SegmentWriter {
		archive.SegmentWriter = defaultArchiveWriterFactory(c)
		return archive
	}))
	inner, ok := writer.(*chunkedWriter)
	require.True(t, ok)
	archive.writer = inner

	_, err := writer.WriteSegment(ctx, 1, []byte("doomed"))
	require.ErrorIs(t, err, errArchiveWriteFailed)
	assert.Equal(t, []bool{true}, archive.reservedDuringCleanup,
		"the index must stay reserved until the archive rollback has finished")
}

// TestChunkedConcurrentWrites exercises the contract WriteSegment
// documents but nothing tested: distinct indices may be written
// concurrently. Every other out-of-order test drives a single
// goroutine, so -race never saw the locking around w.mu, and neither
// the reservation nor the rollback path was observed under contention.
func TestChunkedConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t)

	const segments = 16
	chunks := make([][]byte, segments)
	var want bytes.Buffer
	for i := range chunks {
		chunks[i] = []byte(fmt.Sprintf("segment-%02d;", i))
		want.Write(chunks[i])
	}

	// Index-keyed slices, so the goroutines share no mutable state of
	// this test's own making and any race -race reports belongs to the
	// writer.
	segBytes := make([][]byte, segments)
	errs := make([]error, segments)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range segments {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // widen the window in which the writes overlap
			seg, err := writer.WriteSegment(ctx, i, chunks[i])
			if err != nil {
				errs[i] = err
				return
			}
			segBytes[i], errs[i] = io.ReadAll(seg.TDFData)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "segment %d", i)
	}

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.Equal(t, segments, fin.TotalSegments)

	// Concatenation is in index order regardless of write order.
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
	assert.Equal(t, want.String(), string(plain))
}

// TestChunkedConcurrentDuplicateIndex checks the other half of the
// contract: when several goroutines race on one index, exactly one
// wins and the rest are rejected. The reservation is what makes this
// deterministic, so it is worth pinning under -race.
func TestChunkedConcurrentDuplicateIndex(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)

	const racers = 8
	errs := make([]error, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = writer.WriteSegment(ctx, 0, []byte("contested"))
		}()
	}
	close(start)
	wg.Wait()

	var won int
	for i, err := range errs {
		if err == nil {
			won++
			continue
		}
		require.ErrorIs(t, err, ErrChunkedSegmentAlreadyWritten, "racer %d", i)
	}
	assert.Equal(t, 1, won, "exactly one writer may claim an index")
}

// errArchiveFinalizeFailed and errArchiveCloseFailed are the injected
// trailer-time failures used to drive Finalize's fencing paths.
var (
	errArchiveFinalizeFailed = errors.New("archive finalize failed")
	errArchiveCloseFailed    = errors.New("archive close failed")
)

// trailerFailArchiveWriter delegates to a real segment writer and then
// reports failure from Finalize or Close. Delegating first is the
// point: it reproduces the state the sdk cannot recover from, where the
// archive has already mutated itself -- appended the payload entry to
// its central directory, written the manifest -- and only then failed.
type trailerFailArchiveWriter struct {
	zipstream.SegmentWriter
	failFinalize bool
	failClose    bool
}

func (f *trailerFailArchiveWriter) Finalize(ctx context.Context, manifest []byte) ([]byte, error) {
	out, err := f.SegmentWriter.Finalize(ctx, manifest)
	if err != nil {
		return out, err
	}
	if f.failFinalize {
		return nil, errArchiveFinalizeFailed
	}
	return out, nil
}

func (f *trailerFailArchiveWriter) Close() error {
	if err := f.SegmentWriter.Close(); err != nil {
		return err
	}
	if f.failClose {
		return errArchiveCloseFailed
	}
	return nil
}

// TestChunkedTrailerFailureFencesWriter pins that a failure from the
// archive's Finalize or from the Close after it leaves the writer
// permanently unusable, with every later call returning the same
// sentinel and the underlying cause still wrapped inside it.
//
// Neither is retryable. zipstream's Finalize appends the payload entry
// to its central directory partway through and can still fail
// afterwards without marking itself finalized, so a second attempt
// would append that entry twice; and an archive whose Finalize
// succeeded is terminally finalized regardless of what Close returned.
// The writer must therefore say so rather than look retryable -- the
// alternative is a caller looping on an operation that can only
// produce a corrupt archive or the same error forever.
func TestChunkedTrailerFailureFencesWriter(t *testing.T) {
	for _, tc := range []struct {
		name     string
		finalize bool
		close    bool
		want     error
		cause    error
	}{
		{"finalize", true, false, ErrChunkedFinalizeFailed, errArchiveFinalizeFailed},
		{"close after finalize", false, true, ErrChunkedCloseFailed, errArchiveCloseFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			writer, _ := newChunkedWriterForTest(ctx, t, withChunkedArchiveWriterFactory(func(c clock) zipstream.SegmentWriter {
				return &trailerFailArchiveWriter{
					SegmentWriter: defaultArchiveWriterFactory(c),
					failFinalize:  tc.finalize,
					failClose:     tc.close,
				}
			}))

			_, err := writer.WriteSegment(ctx, 0, []byte("payload"))
			require.NoError(t, err)

			_, err = writer.Finalize(ctx)
			require.ErrorIs(t, err, tc.want)
			require.ErrorIs(t, err, tc.cause, "the sentinel must not swallow the archive's own error")

			// Every door is closed, and closed with the same error: a
			// caller that kept a handle to the writer learns why rather
			// than getting ErrChunkedAlreadyFinalized, which would be a
			// lie -- nothing was finalized.
			_, err = writer.Finalize(ctx)
			require.ErrorIs(t, err, tc.want)
			require.NotErrorIs(t, err, ErrChunkedAlreadyFinalized)

			_, err = writer.WriteSegment(ctx, 1, []byte("more"))
			require.ErrorIs(t, err, tc.want)

			_, err = writer.GetManifest(ctx)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// nonMutatingFinalizeArchiveWriter reports the other kind of trailer
// failure: one the archive caught before it changed anything, flagged as
// such. zipstream does raise these -- every refusal above its SetOrder
// call carries Mutated false -- but chunkedWriter's own preconditions
// pre-empt each one (closed writer, missing segment, missing segment 0,
// cancelled ctx), so reaching them through this package needs an injected
// writer. What that makes this test is a contract test, not a reachability
// one: given Mutated false, chunkedWriter must leave the writer retryable.
type nonMutatingFinalizeArchiveWriter struct {
	zipstream.SegmentWriter
	failures int
}

func (f *nonMutatingFinalizeArchiveWriter) Finalize(ctx context.Context, manifest []byte) ([]byte, error) {
	if f.failures > 0 {
		f.failures--
		return nil, &zipstream.Error{
			Op:      "finalize",
			Type:    "segment",
			Err:     errArchiveFinalizeFailed,
			Mutated: false,
		}
	}
	return f.SegmentWriter.Finalize(ctx, manifest)
}

// TestChunkedNonMutatingTrailerFailureKeepsWriterUsable is the
// counterpart to TestChunkedTrailerFailureFencesWriter: an archive that
// says it failed before touching itself must not cost the caller the
// payload. Fencing here would discard an already-uploaded archive over
// a failure that leaves it byte-for-byte retryable, and the fence being
// too wide went unnoticed precisely because only the post-mutation case
// was exercised.
func TestChunkedNonMutatingTrailerFailureKeepsWriterUsable(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t, withChunkedArchiveWriterFactory(func(c clock) zipstream.SegmentWriter {
		return &nonMutatingFinalizeArchiveWriter{
			SegmentWriter: defaultArchiveWriterFactory(c),
			failures:      1,
		}
	}))

	seg0, err := writer.WriteSegment(ctx, 0, []byte("survives "))
	require.NoError(t, err)
	body, err := io.ReadAll(seg0.TDFData)
	require.NoError(t, err)

	_, err = writer.Finalize(ctx)
	require.ErrorIs(t, err, errArchiveFinalizeFailed, "the archive's own error must still reach the caller")
	require.NotErrorIs(t, err, ErrChunkedFinalizeFailed, "an unmutated archive must not fence the writer")

	// Usable in every direction the fence would have closed.
	seg1, err := writer.WriteSegment(ctx, 1, []byte("the refusal"))
	require.NoError(t, err)
	tail, err := io.ReadAll(seg1.TDFData)
	require.NoError(t, err)

	_, err = writer.GetManifest(ctx)
	require.NoError(t, err)

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 2)

	tdfBytes := bytes.Join([][]byte{body, tail, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("survives the refusal"), plain)
}

// TestChunkedFinalizeContextCancellationIsRetryable pins the one
// non-mutating Finalize refusal reachable in production: a request-scoped
// deadline firing before the archive is touched.
//
// The refusal comes from chunkedWriter's own ctx.Err() check, not from
// zipstream's -- chunkedWriter checks immediately before handing off, which
// is what makes "nothing was mutated" structural rather than something
// inferred from an error the archive raised. What matters is the
// consequence: fencing here would destroy an already-encrypted,
// already-uploaded payload and blame the archive for a deadline.
func TestChunkedFinalizeContextCancellationIsRetryable(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t)

	seg0, err := writer.WriteSegment(ctx, 0, []byte("deadline "))
	require.NoError(t, err)
	body, err := io.ReadAll(seg0.TDFData)
	require.NoError(t, err)

	expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()

	_, err = writer.Finalize(expired)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotErrorIs(t, err, ErrChunkedFinalizeFailed, "nothing was written, so nothing to fence")

	seg1, err := writer.WriteSegment(ctx, 1, []byte("survived"))
	require.NoError(t, err)
	tail, err := io.ReadAll(seg1.TDFData)
	require.NoError(t, err)

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 2)

	tdfBytes := bytes.Join([][]byte{body, tail, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("deadline survived"), plain)
}

// TestChunkedWriteSegmentContextCancellationFreesIndex checks the same
// property one level down: a cancelled write must not wedge its index.
// A reservation left behind would make the index unwritable forever and
// now also blocks Finalize outright, so the recovery path matters more
// than it did.
func TestChunkedWriteSegmentContextCancellationFreesIndex(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)

	expired, cancel := context.WithCancel(ctx)
	cancel()
	_, err := writer.WriteSegment(expired, 0, []byte("cancelled"))
	require.ErrorIs(t, err, context.Canceled)

	_, err = writer.WriteSegment(ctx, 0, []byte("retried"))
	require.NoError(t, err, "the cancelled write must have released its reservation")

	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	assert.Len(t, fin.Manifest.Segments, 1)
}

// errCipherFailed is the injected cipher failure.
var errCipherFailed = errors.New("cipher failed")

// failingCipher fails or panics on every call, depending on how it is
// built. Segment encryption is the one step before the archive is
// touched, so it exercises the reservation-rollback path with
// archiveWriteAttempted still false.
type failingCipher struct {
	panics bool
}

func (c failingCipher) EncryptInPlace(_ []byte) ([]byte, []byte, error) {
	if c.panics {
		panic("cipher exploded")
	}
	return nil, nil, errCipherFailed
}

// TestChunkedCipherFailureReleasesIndex checks the reservation is
// released when encryption fails before the archive is involved, so the
// index stays writable. A wedged index is unrecoverable for the caller:
// every retry returns ErrChunkedSegmentAlreadyWritten for a segment
// that was never written.
func TestChunkedCipherFailureReleasesIndex(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t, withChunkedCipherFactory(func([]byte) (segmentCipher, error) {
		return failingCipher{}, nil
	}))

	_, err := writer.WriteSegment(ctx, 0, []byte("doomed"))
	require.ErrorIs(t, err, errCipherFailed)

	inner, ok := writer.(*chunkedWriter)
	require.True(t, ok)
	inner.mu.RLock()
	_, held := inner.segments[0]
	inner.mu.RUnlock()
	assert.False(t, held, "a failed encrypt must leave the index free to retry")
}

// TestChunkedCipherPanicReleasesIndex covers the same rollback for a
// panic rather than an error. The release runs from a defer precisely
// so an injected cipher that panics -- or any future panic between the
// reservation and the commit -- cannot strand the index; a caller that
// recovers and retries has to find it free.
func TestChunkedCipherPanicReleasesIndex(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t, withChunkedCipherFactory(func([]byte) (segmentCipher, error) {
		return failingCipher{panics: true}, nil
	}))

	func() {
		defer func() {
			assert.NotNil(t, recover(), "the cipher was supposed to panic")
		}()
		_, _ = writer.WriteSegment(ctx, 0, []byte("doomed"))
	}()

	inner, ok := writer.(*chunkedWriter)
	require.True(t, ok)
	inner.mu.RLock()
	_, held := inner.segments[0]
	inner.mu.RUnlock()
	assert.False(t, held, "a panic between reservation and commit must still release the index")
}

// xorSplitter splits the DEK into one share per KAS: n-1 random shares
// plus a final share chosen so the XOR of all of them is the DEK. This
// is the multi-KAS AND shape DefaultKeySplitter does not produce. With
// one split the reader's XOR loop runs over a single operand and the
// split-id grouping is never exercised.
type xorSplitter struct {
	kases []*policy.SimpleKasKey
}

func (s *xorSplitter) Split(_ context.Context, _ []*policy.Value, dek []byte, _ *policy.SimpleKasKey) (*SplitResult, error) {
	out := &SplitResult{KASPublicKeys: make(map[string]KASPublicKey, len(s.kases))}
	accum := make([]byte, len(dek))
	for i, kas := range s.kases {
		share := make([]byte, len(dek))
		if i == len(s.kases)-1 {
			// Last share closes the XOR back onto the DEK.
			for j := range share {
				share[j] = dek[j] ^ accum[j]
			}
		} else {
			if _, err := io.ReadFull(rand.Reader, share); err != nil {
				return nil, err
			}
			for j := range share {
				accum[j] ^= share[j]
			}
		}
		url := kas.GetKasUri()
		alg, err := PolicyAlgorithmToKeyType(kas.GetPublicKey().GetAlgorithm())
		if err != nil {
			return nil, err
		}
		out.KASPublicKeys[url] = KASPublicKey{
			Algorithm: alg,
			KID:       kas.GetPublicKey().GetKid(),
			PEM:       kas.GetPublicKey().GetPem(),
			URL:       url,
		}
		out.Splits = append(out.Splits, Split{
			Data:    share,
			ID:      fmt.Sprintf("split-%d", i),
			KASURLs: []string{url},
		})
	}
	return out, nil
}

// TestChunkedMultiSplitRoundTrip drives two splits against two
// independent KASes end to end, so the reader has to collect more than
// one share, group the key access objects by sid, and XOR the results.
// A writer-side change that emitted the right number of KAOs with the
// wrong sids fails nowhere until decryption.
func TestChunkedMultiSplitRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)

	kasA := newChunkedFakeKAS(t)
	t.Cleanup(kasA.server.Close)
	kasB := newChunkedFakeKAS(t)
	t.Cleanup(kasB.server.Close)

	writer, err := NewChunkedWriter(ctx,
		WithChunkedKeySplitter(&xorSplitter{kases: []*policy.SimpleKasKey{kasA.simpleKey(), kasB.simpleKey()}}),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, writer, [][]byte{
		[]byte("two "), []byte("kas "), []byte("split"),
	})
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	require.Len(t, fin.Manifest.KeyAccessObjs, 2)
	sids := make(map[string]string, 2)
	for _, kao := range fin.Manifest.KeyAccessObjs {
		sids[kao.SplitID] = kao.KasURL
	}
	assert.Equal(t, map[string]string{
		"split-0": kasA.url,
		"split-1": kasB.url,
	}, sids, "each share must be wrapped to its own KAS under its own sid")

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasA.url, kasB.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("two kas split"), plain)
}

// TestChunkedAttributes covers the three attribute/KAS options: the
// writer-level default, the Finalize-level override, and the
// Finalize-level KAS. They reach the manifest by two different
// routes -- attributes become the policy body, the KAS decides which
// endpoint each key access object names -- so a regression in the
// override precedence is invisible without checking both.
func TestChunkedAttributes(t *testing.T) {
	ctx := context.Background()

	initial := []*policy.Value{{Fqn: "https://example.com/attr/initial/value/one"}}
	override := []*policy.Value{
		{Fqn: "https://example.com/attr/override/value/a"},
		{Fqn: "https://example.com/attr/override/value/b"},
	}

	// policyFQNs decodes the base64 policy the manifest carries and
	// returns the attribute FQNs inside it.
	policyFQNs := func(t *testing.T, m *Manifest) []string {
		t.Helper()
		raw, err := ocrypto.Base64Decode([]byte(m.Policy))
		require.NoError(t, err)
		var p PolicyObject
		require.NoError(t, json.Unmarshal(raw, &p))
		out := make([]string, 0, len(p.Body.DataAttributes))
		for _, a := range p.Body.DataAttributes {
			out = append(out, a.Attribute)
		}
		return out
	}

	t.Run("initial attributes reach the policy", func(t *testing.T) {
		writer, _ := newChunkedWriterForTest(ctx, t, WithChunkedInitialAttributes(initial))
		writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})
		fin, err := writer.Finalize(ctx)
		require.NoError(t, err)
		assert.Equal(t, []string{initial[0].GetFqn()}, policyFQNs(t, fin.Manifest))
	})

	t.Run("finalize attributes replace them", func(t *testing.T) {
		writer, _ := newChunkedWriterForTest(ctx, t, WithChunkedInitialAttributes(initial))
		writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})
		fin, err := writer.Finalize(ctx, WithChunkedAttributes(override))
		require.NoError(t, err)
		// Replace, not merge: the initial set must be gone entirely.
		assert.Equal(t, []string{override[0].GetFqn(), override[1].GetFqn()}, policyFQNs(t, fin.Manifest))
	})

	// An empty override reads as "not specified", so the initial set
	// survives. Documented on WithChunkedAttributes, and pinned here
	// because the alternative -- letting an empty slice win -- would
	// silently loosen the policy on the data, and nothing downstream
	// could tell that from a writer that never had attributes.
	for _, tc := range []struct {
		name   string
		values []*policy.Value
	}{
		{"nil finalize attributes keep the initial set", nil},
		{"empty finalize attributes keep the initial set", []*policy.Value{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer, _ := newChunkedWriterForTest(ctx, t, WithChunkedInitialAttributes(initial))
			writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})
			fin, err := writer.Finalize(ctx, WithChunkedAttributes(tc.values))
			require.NoError(t, err)
			assert.Equal(t, []string{initial[0].GetFqn()}, policyFQNs(t, fin.Manifest))
		})
	}

	t.Run("finalize default KAS overrides the writer's", func(t *testing.T) {
		writer, initialKAS := newChunkedWriterForTest(ctx, t)
		lateKAS := newChunkedFakeKAS(t)
		t.Cleanup(lateKAS.server.Close)

		writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})
		fin, err := writer.Finalize(ctx, WithChunkedDefaultKASForFinalize(lateKAS.simpleKey()))
		require.NoError(t, err)

		require.Len(t, fin.Manifest.KeyAccessObjs, 1)
		assert.Equal(t, lateKAS.url, fin.Manifest.KeyAccessObjs[0].KasURL)
		assert.NotEqual(t, initialKAS.url, fin.Manifest.KeyAccessObjs[0].KasURL)
	})
}

// blockingCipher lets a test hold one WriteSegment inside encryption
// while it inspects writer state from another goroutine. started fires
// once the call is inside; release unblocks it.
type blockingCipher struct {
	inner   segmentCipher
	target  int
	calls   int
	mu      sync.Mutex
	started chan struct{}
	release chan struct{}
}

func (c *blockingCipher) EncryptInPlace(data []byte) ([]byte, []byte, error) {
	c.mu.Lock()
	n := c.calls
	c.calls++
	c.mu.Unlock()
	if n == c.target {
		close(c.started)
		<-c.release
	}
	return c.inner.EncryptInPlace(data)
}

// TestChunkedGetManifestDuringInFlightWrite pins that a reserved but
// not-yet-written index is invisible to the manifest. The reservation
// exists from the moment WriteSegment claims the index, well before the
// archive has accepted anything, so a manifest built in that window
// would otherwise either describe a segment with no hash and no size or
// fail outright -- and GetManifest running alongside in-flight writes is
// the whole point of the snapshot.
func TestChunkedGetManifestDuringInFlightWrite(t *testing.T) {
	ctx := context.Background()
	cipher := &blockingCipher{
		// Segments 0 and 2 go through; the third call -- index 1 -- is
		// held. Leaving a written index above the blocked one is what
		// lets the keepSegments check below reach its per-index branch
		// rather than stopping at the count.
		target:  2,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writer, _ := newChunkedWriterForTest(ctx, t, withChunkedCipherFactory(func(dek []byte) (segmentCipher, error) {
		inner, err := defaultSegmentCipherFactory(dek)
		if err != nil {
			return nil, err
		}
		cipher.inner = inner
		return cipher, nil
	}))

	_, err := writer.WriteSegment(ctx, 0, []byte("first"))
	require.NoError(t, err)
	_, err = writer.WriteSegment(ctx, 2, []byte("third"))
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := writer.WriteSegment(ctx, 1, []byte("second"))
		done <- err
	}()
	<-cipher.started

	snap, err := writer.GetManifest(ctx)
	require.NoError(t, err, "a reservation in flight must not fail the snapshot")
	assert.Len(t, snap.Segments, 2, "the snapshot must describe only segments the archive has accepted")

	// The same index must also be refused as a keepSegments member while
	// it is merely reserved, for the same reason: naming it would put a
	// segment in the manifest that has no bytes behind it.
	_, err = writer.GetManifest(ctx, WithChunkedSegments([]int{0, 1}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "references segment 1 which was not written")

	close(cipher.release)
	require.NoError(t, <-done)

	snap, err = writer.GetManifest(ctx)
	require.NoError(t, err)
	assert.Len(t, snap.Segments, 3, "the segment appears once the archive has it")
}

// TestChunkedFinalizeRejectsInFlightWrite pins the answer to the race
// GetManifest is allowed to ignore. A manifest is a snapshot and may be
// one segment short; an archive may not. zipstream has already counted
// the in-flight segment's bytes into the payload entry by the time it
// is visible here, so a trailer built now records offsets that overshoot
// unless the caller appends bytes the manifest never mentions -- while
// the racing WriteSegment returns success. Refusing costs a retry;
// proceeding costs the payload.
func TestChunkedFinalizeRejectsInFlightWrite(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	cipher := &blockingCipher{
		// Call 0 is segment 0; call 1 -- segment 1 -- is held open.
		target:  1,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writer, kasBundle := newChunkedWriterForTest(ctx, t, withChunkedCipherFactory(func(dek []byte) (segmentCipher, error) {
		inner, err := defaultSegmentCipherFactory(dek)
		if err != nil {
			return nil, err
		}
		cipher.inner = inner
		return cipher, nil
	}))

	seg0, err := writer.WriteSegment(ctx, 0, []byte("held "))
	require.NoError(t, err)
	body, err := io.ReadAll(seg0.TDFData)
	require.NoError(t, err)

	done := make(chan *ChunkedSegmentResult, 1)
	go func() {
		seg, err := writer.WriteSegment(ctx, 1, []byte("open"))
		assert.NoError(t, err)
		done <- seg
	}()
	<-cipher.started

	_, err = writer.Finalize(ctx)
	require.ErrorIs(t, err, ErrChunkedWriteInFlight)
	assert.Contains(t, err.Error(), "[1]", "the error must name the index the caller has to wait on")

	// GetManifest must not inherit the rejection. It produces nothing
	// durable, so a snapshot one segment short is a correct snapshot of
	// this instant -- and running alongside in-flight writes is its
	// entire purpose.
	snap, err := writer.GetManifest(ctx)
	require.NoError(t, err)
	assert.Len(t, snap.Segments, 1)

	close(cipher.release)
	seg1 := <-done
	require.NotNil(t, seg1)
	tail, err := io.ReadAll(seg1.TDFData)
	require.NoError(t, err)

	// Not fenced: the refusal happened before anything was touched, so
	// joining the goroutine and retrying is all the recovery needed.
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 2)

	tdfBytes := bytes.Join([][]byte{body, tail, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("held open"), plain)
}

// TestChunkedRealisticSegmentSizes runs a 2 MiB segment size rather
// than the handful of bytes every other test uses. Segment
// sizing is where the ZIP64 thresholds, the CRC combine over full-size
// segments, and the offset arithmetic actually get exercised; a
// three-byte payload passes all of them trivially.
func TestChunkedRealisticSegmentSizes(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~6 MiB and encrypts it")
	}
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	writer, kasBundle := newChunkedWriterForTest(ctx, t)

	const segSize = 2 * 1024 * 1024
	chunks := make([][]byte, 3)
	var want bytes.Buffer
	for i := range chunks {
		chunk := make([]byte, segSize)
		// Varied, reproducible content: a constant fill would hide a
		// segment written at the wrong offset.
		for j := range chunk {
			chunk[j] = byte(i*7 + j)
		}
		chunks[i] = chunk
		want.Write(chunk)
	}

	body := writeChunkedSegments(ctx, t, writer, chunks)
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3*segSize), fin.TotalSize)
	assert.Equal(t, int64(segSize), fin.Manifest.DefaultSegmentSize)

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, want.Bytes(), plain)
}

// partialSplitter names two KAS URLs on one split but resolves a public
// key for only the first, the shape a splitter produces when a KAS
// lookup fails and the failure is swallowed upstream.
type partialSplitter struct {
	known *policy.SimpleKasKey
	// missingURL is listed on the split but absent from KASPublicKeys.
	missingURL string
}

func (s partialSplitter) Split(_ context.Context, _ []*policy.Value, dek []byte, _ *policy.SimpleKasKey) (*SplitResult, error) {
	url := s.known.GetKasUri()
	share := make([]byte, len(dek))
	copy(share, dek)
	return &SplitResult{
		KASPublicKeys: map[string]KASPublicKey{
			url: {
				Algorithm: ocrypto.RSA2048Key,
				KID:       s.known.GetPublicKey().GetKid(),
				PEM:       s.known.GetPublicKey().GetPem(),
				URL:       url,
			},
		},
		Splits: []Split{{
			Data:    share,
			KASURLs: []string{url, s.missingURL},
		}},
	}, nil
}

// TestChunkedFinalizeRejectsUnresolvedKAS checks that a split naming a
// KAS with no resolved public key fails Finalize. Skipping it would
// emit a TDF whose KAO set silently omits that KAS -- and if every URL
// on a split were missing, the share would be unrecoverable.
func TestChunkedFinalizeRejectsUnresolvedKAS(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	defer kasBundle.server.Close()

	w, err := NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedKeySplitter(partialSplitter{
			known:      kasBundle.simpleKey(),
			missingURL: "https://unresolved.example.com",
		}),
	)
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("payload"))
	require.NoError(t, err)

	_, err = w.Finalize(ctx)
	require.ErrorIs(t, err, errKasPubKeyMissing)
	assert.Contains(t, err.Error(), "https://unresolved.example.com")
}

// brokenSplitter returns a share that passes every structural check
// and still does not rebuild the DEK -- the failure mode SplitResult's
// own doc describes, where the reader collects every share it is told
// about, XORs them, and reports a root signature failure that reads as
// tampering.
type brokenSplitter struct {
	kas *policy.SimpleKasKey
	// short truncates the share instead of corrupting it. A single
	// short share agrees with itself on length, so Validate accepts it
	// and the DEK's tail is left unmasked.
	short bool
}

func (s brokenSplitter) Split(_ context.Context, _ []*policy.Value, dek []byte, _ *policy.SimpleKasKey) (*SplitResult, error) {
	share := slices.Clone(dek)
	if s.short {
		share = share[:len(share)/2]
	} else {
		share[0] ^= 0xFF
	}
	url := s.kas.GetKasUri()
	return &SplitResult{
		KASPublicKeys: map[string]KASPublicKey{
			url: {
				Algorithm: ocrypto.RSA2048Key,
				KID:       s.kas.GetPublicKey().GetKid(),
				PEM:       s.kas.GetPublicKey().GetPem(),
				URL:       url,
			},
		},
		Splits: []Split{{Data: share, KASURLs: []string{url}}},
	}, nil
}

// TestChunkedFinalizeRejectsNonReconstructingSplitter checks that a
// splitter whose shares do not rebuild the DEK is caught at Finalize
// rather than at the reader's root signature check, hours later and on
// someone else's machine.
func TestChunkedFinalizeRejectsNonReconstructingSplitter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		short   bool
		wantSub string
	}{
		{"share of the wrong value", false, "do not XOR back to the DEK"},
		{"share shorter than the DEK", true, "the length of the DEK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			kasBundle := newChunkedFakeKAS(t)
			t.Cleanup(kasBundle.server.Close)

			w, err := NewChunkedWriter(ctx,
				WithChunkedDefaultKAS(kasBundle.simpleKey()),
				WithChunkedKeySplitter(brokenSplitter{kas: kasBundle.simpleKey(), short: tc.short}),
			)
			require.NoError(t, err)

			_, err = w.WriteSegment(ctx, 0, []byte("payload"))
			require.NoError(t, err)

			_, err = w.Finalize(ctx)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)

			// The splits are built before the archive is touched, so a
			// splitter fault is a correctable mistake rather than a lost
			// payload. Moving the key access build below the archive call
			// would make it terminal, silently.
			require.NotErrorIs(t, err, ErrChunkedFinalizeFailed)
			_, err = w.WriteSegment(ctx, 1, []byte("more"))
			require.NoError(t, err, "a splitter fault must not fence the writer")
		})
	}
}

// dekZeroingSplitter wipes the slice it is handed once it has taken a
// copy, the way a splitter treating the DEK as scratch space would. Its
// output is correct; only the caller's buffer is damaged.
type dekZeroingSplitter struct {
	kas *policy.SimpleKasKey
}

func (s dekZeroingSplitter) Split(_ context.Context, _ []*policy.Value, dek []byte, _ *policy.SimpleKasKey) (*SplitResult, error) {
	share := slices.Clone(dek)
	clear(dek)
	url := s.kas.GetKasUri()
	return &SplitResult{
		KASPublicKeys: map[string]KASPublicKey{
			url: {
				Algorithm: ocrypto.RSA2048Key,
				KID:       s.kas.GetPublicKey().GetKid(),
				PEM:       s.kas.GetPublicKey().GetPem(),
				URL:       url,
			},
		},
		Splits: []Split{{Data: share, KASURLs: []string{url}}},
	}, nil
}

// TestChunkedSplitterCannotDamageTheDEK checks that the writer hands
// the splitter a copy. The splitter runs between the segment signatures
// (already computed against the DEK) and the root signature (computed
// after it), so a splitter that mutates its argument desynchronizes the
// two and produces a TDF that fails verification exactly as a tampered
// one does -- with the wrapped key still correct, so the KAS grants
// access and the failure surfaces only at the last step.
func TestChunkedSplitterCannotDamageTheDEK(t *testing.T) {
	ctx := context.Background()
	s := newChunkedTestSDK(t)
	kasBundle := newChunkedFakeKAS(t)
	t.Cleanup(kasBundle.server.Close)

	writer, err := NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedKeySplitter(dekZeroingSplitter{kas: kasBundle.simpleKey()}),
	)
	require.NoError(t, err)

	body := writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("intact "), []byte("key")})
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
	reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
		WithKasAllowlist([]string{kasBundle.url}),
	)
	require.NoError(t, err)

	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("intact key"), plain)
}

// TestChunkedInitialAttributesAreCloned checks that reusing the slice
// passed at construction cannot change the policy the writer later
// writes. The writer holds it for its whole lifetime, and a policy
// quietly loosened after the fact is the one mistake here that nothing
// downstream can detect.
func TestChunkedInitialAttributesAreCloned(t *testing.T) {
	ctx := context.Background()
	const want = "https://example.com/attr/clone/value/original"

	attrs := []*policy.Value{{Fqn: want}}
	writer, _ := newChunkedWriterForTest(ctx, t, WithChunkedInitialAttributes(attrs))
	attrs[0] = &policy.Value{Fqn: "https://example.com/attr/clone/value/swapped"}

	writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})
	fin, err := writer.Finalize(ctx)
	require.NoError(t, err)

	raw, err := ocrypto.Base64Decode([]byte(fin.Manifest.Policy))
	require.NoError(t, err)
	var p PolicyObject
	require.NoError(t, json.Unmarshal(raw, &p))
	require.Len(t, p.Body.DataAttributes, 1)
	assert.Equal(t, want, p.Body.DataAttributes[0].Attribute)
}

// TestChunkedEncryptedSizeIsNotTheByteCount pins the trap in
// ChunkedFinalizeResult.EncryptedSize: it describes the manifest, not the
// file. A caller who sizes an upload from it truncates the payload, and the
// corruption surfaces only at decrypt.
//
// Two distinct shortfalls stack here, and the test measures them separately so
// a regression names which one moved. Segment 0's TDFData carries the
// payload's ZIP local file header, which EncryptedSize does not count; and
// WithChunkedSegments drops segment 2 from the manifest while the archive
// still counts its bytes and the caller must still append them.
func TestChunkedEncryptedSizeIsNotTheByteCount(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)

	chunks := [][]byte{[]byte("keep-0-"), []byte("keep-1-"), []byte("drop-2!")}
	var appended, keptManifestBytes, droppedBytes, headerBytes int64
	for i, chunk := range chunks {
		seg, err := writer.WriteSegment(ctx, i, chunk)
		require.NoError(t, err)
		n, err := io.Copy(io.Discard, seg.TDFData)
		require.NoError(t, err)
		appended += n
		if i == 0 {
			// Whatever TDFData carries beyond the segment's own ciphertext is
			// the local file header. Derived, not hardcoded: the header's
			// length depends on the archive writer's naming, and pinning a
			// literal here would only assert the default factory.
			headerBytes = n - seg.EncryptedSize
		}
		if i < 2 {
			keptManifestBytes += seg.EncryptedSize
		} else {
			droppedBytes += n
		}
	}
	require.Positive(t, headerBytes, "segment 0's TDFData must carry the payload header")
	require.Positive(t, droppedBytes)

	fin, err := writer.Finalize(ctx, WithChunkedSegments([]int{0, 1}))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.Segments, 2)

	assert.Equal(t, keptManifestBytes, fin.EncryptedSize,
		"EncryptedSize sums exactly the segments the manifest describes")
	assert.Equal(t, fin.EncryptedSize+headerBytes+droppedBytes, appended,
		"the bytes to append exceed EncryptedSize by the payload header plus every dropped segment")
	assert.Less(t, fin.EncryptedSize, appended,
		"sizing an upload from EncryptedSize truncates it")
}

// TestChunkedMimeType covers the default and the override together:
// the default is what a caller who never sets one ships, so it is as
// much a part of the contract as the option.
func TestChunkedMimeType(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)
	writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})

	snap, err := writer.GetManifest(ctx)
	require.NoError(t, err)
	assert.Equal(t, "application/octet-stream", snap.MimeType)

	fin, err := writer.Finalize(ctx, WithChunkedMimeType("application/pdf"))
	require.NoError(t, err)
	assert.Equal(t, "application/pdf", fin.Manifest.MimeType)
}

// TestChunkedZeroLengthSegments exercises the invariant segmentSlot's
// two-field design exists for: a written segment is distinguished from
// an absent one by a flag, not by its size, so an empty segment must be
// a segment and not a gap. An interior empty segment also checks that
// the offsets of everything after it are unaffected.
func TestChunkedZeroLengthSegments(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chunks [][]byte
		want   string
	}{
		{"empty interior segment", [][]byte{[]byte("a"), {}, []byte("b")}, "ab"},
		{"empty trailing segment", [][]byte{[]byte("ab"), {}}, "ab"},
		{"empty payload", [][]byte{{}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := newChunkedTestSDK(t)
			writer, kasBundle := newChunkedWriterForTest(ctx, t)

			body := writeChunkedSegments(ctx, t, writer, tc.chunks)
			fin, err := writer.Finalize(ctx)
			require.NoError(t, err)
			require.Len(t, fin.Manifest.Segments, len(tc.chunks),
				"an empty segment is still a segment")

			tdfBytes := bytes.Join([][]byte{body, fin.Data}, nil)
			reader, err := s.LoadTDF(bytes.NewReader(tdfBytes),
				WithKasAllowlist([]string{kasBundle.url}),
			)
			require.NoError(t, err)

			plain, err := io.ReadAll(reader)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(plain))
		})
	}
}

// TestChunkedManifestCloneIsDeep pins that the slices hanging off a
// returned manifest are copies too. Segments is already covered by the
// round trips; KeyAccessObjs and Assertions are not, so dropping either
// clone would leave a caller's edit -- or a data race against a
// concurrent GetManifest -- in the writer's own record of what the
// archive bytes say.
func TestChunkedManifestCloneIsDeep(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)
	writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})

	fin, err := writer.Finalize(ctx, WithChunkedAssertions([]AssertionConfig{{
		ID:             "a",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement:      Statement{Format: "json", Schema: "urn:test", Value: `{"k":"v"}`},
	}}))
	require.NoError(t, err)
	require.Len(t, fin.Manifest.KeyAccessObjs, 1)
	require.Len(t, fin.Manifest.Assertions, 1)
	require.Len(t, fin.Manifest.Segments, 1)

	wantKAS := fin.Manifest.KeyAccessObjs[0].KasURL
	wantAssertion := fin.Manifest.Assertions[0].ID
	wantHash := fin.Manifest.Segments[0].Hash

	fin.Manifest.KeyAccessObjs[0].KasURL = "https://tampered.example.com"
	fin.Manifest.Assertions[0].ID = "tampered"
	fin.Manifest.Segments[0].Hash = "tampered"

	again, err := writer.GetManifest(ctx)
	require.NoError(t, err)
	assert.Equal(t, wantKAS, again.KeyAccessObjs[0].KasURL)
	assert.Equal(t, wantAssertion, again.Assertions[0].ID)
	assert.Equal(t, wantHash, again.Segments[0].Hash)
}

// TestSummarizeSegmentIndices covers the truncation branch, which only
// fires on a writer with more segments in flight than any test would
// realistically hold open. Unbounded, the ErrChunkedWriteInFlight
// message on a ten-thousand-segment writer is measured in kilobytes.
func TestSummarizeSegmentIndices(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		want string
	}{
		{"empty", 0, "[]"},
		{"at the cap", maxReportedSegmentIndices, "[0 1 2 3 4 5 6 7]"},
		{"past the cap", maxReportedSegmentIndices + 3, "[0 1 2 3 4 5 6 7] ... (3 more)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			indices := make([]int, tc.n)
			for i := range indices {
				indices[i] = i
			}
			assert.Equal(t, tc.want, summarizeSegmentIndices(indices))
		})
	}
}

// TestChunkedEmptyAttributeFQNRejected checks that Finalize refuses an
// attribute value whose FQN is empty rather than writing it into the policy.
//
// GetFqn is nil-receiver safe, so both a nil element and a value that never
// had its FQN populated reach buildChunkedPolicy as "". Emitting that produces
// a policy naming no attribute: it fails closed, but only at decrypt, after
// the caller has encrypted and uploaded every byte. Nothing between here and
// there looks at it.
func TestChunkedEmptyAttributeFQNRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs []*policy.Value
	}{
		{"unpopulated FQN", []*policy.Value{{Fqn: ""}}},
		{"nil value", []*policy.Value{nil}},
		{
			"one good, one empty",
			[]*policy.Value{{Fqn: "https://example.com/attr/a/value/b"}, {Fqn: ""}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			writer, _ := newChunkedWriterForTest(ctx, t, WithChunkedInitialAttributes(tc.attrs))
			writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})

			_, err := writer.Finalize(ctx)
			require.ErrorContains(t, err, "empty FQN")

			// Not fenced: nothing was written, so a caller who can supply the
			// real attributes may still finalize this payload.
			fin, err := writer.Finalize(ctx,
				WithChunkedAttributes([]*policy.Value{{Fqn: "https://example.com/attr/a/value/b"}}))
			require.NoError(t, err)
			require.NotNil(t, fin)
		})
	}
}

// cleanupFailArchiveWriter fails the rollback of a failed write, leaving the
// archive in a state this package cannot characterize.
type cleanupFailArchiveWriter struct {
	zipstream.SegmentWriter
	failIndex int
}

func (f *cleanupFailArchiveWriter) WriteSegment(ctx context.Context, index int, size uint64, crc32 uint32) ([]byte, error) {
	if index == f.failIndex {
		return nil, errArchiveWriteFailed
	}
	return f.SegmentWriter.WriteSegment(ctx, index, size, crc32)
}

func (f *cleanupFailArchiveWriter) CleanupSegment(index int) error {
	if index == f.failIndex {
		return errArchiveCleanupFailed
	}
	return f.SegmentWriter.CleanupSegment(index)
}

// TestChunkedCleanupFailureFencesWriter checks that a rollback the archive
// could not perform stops the writer instead of being swallowed.
//
// CleanupSegment is what makes a failed WriteSegment retryable. If it fails,
// the archive may still carry the attempt's contribution to the payload's size
// and CRC, and nothing here can tell how much -- so every later segment would
// be placed at an offset computed from a length the manifest never describes.
// That assembles into a file readers accept and misread, which is exactly the
// failure mode worth trading a dead writer for.
func TestChunkedCleanupFailureFencesWriter(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t,
		withChunkedArchiveWriterFactory(func(clock clock) zipstream.SegmentWriter {
			return &cleanupFailArchiveWriter{
				SegmentWriter: defaultArchiveWriterFactory(clock),
				failIndex:     1,
			}
		}))

	seg0, err := writer.WriteSegment(ctx, 0, []byte("first "))
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, seg0.TDFData)
	require.NoError(t, err)

	// The caller sees the write error, not the rollback error: the write is
	// the cause, and reporting the rollback instead would hide it.
	_, err = writer.WriteSegment(ctx, 1, []byte("second "))
	require.ErrorIs(t, err, errArchiveWriteFailed)
	require.NotErrorIs(t, err, errArchiveCleanupFailed)

	// Every later call reports the fence, wrapping the rollback's cause.
	for _, call := range []struct {
		name string
		run  func() error
	}{
		{"WriteSegment", func() error { _, err := writer.WriteSegment(ctx, 2, []byte("third")); return err }},
		{"Finalize", func() error { _, err := writer.Finalize(ctx); return err }},
		{"GetManifest", func() error { _, err := writer.GetManifest(ctx); return err }},
		{"retry the failed index", func() error {
			_, err := writer.WriteSegment(ctx, 1, []byte("second "))
			return err
		}},
	} {
		t.Run(call.name, func(t *testing.T) {
			err := call.run()
			require.ErrorIs(t, err, ErrChunkedCleanupFailed)
			assert.ErrorIs(t, err, errArchiveCleanupFailed, "the fence must carry its cause")
		})
	}
}

// TestChunkedEmptyMimeTypeFallsBackToDefault checks that
// WithChunkedMimeType("") is treated as "not specified" rather than taken
// literally. The empty string is what a caller forwarding an unset field
// passes, and a manifest with no MIME type at all is not what they meant.
func TestChunkedEmptyMimeTypeFallsBackToDefault(t *testing.T) {
	ctx := context.Background()
	writer, _ := newChunkedWriterForTest(ctx, t)
	writeChunkedSegments(ctx, t, writer, [][]byte{[]byte("payload")})

	fin, err := writer.Finalize(ctx, WithChunkedMimeType(""))
	require.NoError(t, err)
	assert.Equal(t, defaultMimeType, fin.Manifest.MimeType)
}

// blockingSplitter signals when Split is entered and stays there until
// released, so a test can observe what the writer holds while a split
// is in flight. Only the first Split blocks; later ones pass straight
// through.
type blockingSplitter struct {
	inner   KeySplitter
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingSplitter) Split(ctx context.Context, attrs []*policy.Value, dek []byte, defaultKAS *policy.SimpleKasKey) (*SplitResult, error) {
	first := false
	s.once.Do(func() {
		first = true
		close(s.entered)
	})
	if first {
		<-s.release
	}
	return s.inner.Split(ctx, attrs, dek, defaultKAS)
}

// TestChunkedGetManifestDoesNotBlockWriteSegment pins the reason
// GetManifest snapshots segment state and releases the lock before
// splitting. A real splitter resolves KAS keys over the network; while
// GetManifest held RLock across that call, every WriteSegment queued on
// the write lock for its duration. This test deadlocks on the old shape
// and passes on the new one.
func TestChunkedGetManifestDoesNotBlockWriteSegment(t *testing.T) {
	ctx := context.Background()
	kasBundle := newChunkedFakeKAS(t)
	t.Cleanup(kasBundle.server.Close)

	splitter := &blockingSplitter{
		inner:   DefaultKeySplitter(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	w, err := NewChunkedWriter(ctx,
		WithChunkedDefaultKAS(kasBundle.simpleKey()),
		WithChunkedKeySplitter(splitter),
	)
	require.NoError(t, err)

	_, err = w.WriteSegment(ctx, 0, []byte("first"))
	require.NoError(t, err)

	type manifestResult struct {
		manifest *Manifest
		err      error
	}
	manifests := make(chan manifestResult, 1)
	go func() {
		m, err := w.GetManifest(ctx)
		manifests <- manifestResult{manifest: m, err: err}
	}()

	select {
	case <-splitter.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("GetManifest never reached the splitter")
	}

	wrote := make(chan error, 1)
	go func() {
		_, err := w.WriteSegment(ctx, 1, []byte("second"))
		wrote <- err
	}()
	select {
	case err := <-wrote:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		close(splitter.release)
		t.Fatal("WriteSegment blocked while GetManifest was splitting")
	}

	close(splitter.release)
	got := <-manifests
	require.NoError(t, got.err)

	// The manifest describes the writer as of the snapshot, not as of
	// the return. Segment 1 landed after the lock was released, so it
	// is deliberately absent -- GetManifest is a point-in-time view.
	assert.Len(t, got.manifest.Segments, 1)

	// The segment written during the split is still committed and shows
	// up in the next call.
	later, err := w.GetManifest(ctx)
	require.NoError(t, err)
	assert.Len(t, later.Segments, 2)
}
