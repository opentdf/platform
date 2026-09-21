package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"hash/crc32"
	"io"
	"testing"

	"github.com/opentdf/platform/sdk/internal/zipstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webSDKSegmentSize is web-sdk's DEFAULT_SEGMENT_SIZE. It is the point at
// which a web-sdk container first contains a segment whose size equals the
// manifest-level default, and therefore the point at which web-sdk starts
// omitting the per-segment sizes.
const webSDKSegmentSize = 1024 * 1024

// rewriteManifest rewrites a TDF's integrityInformation via mutate, leaving
// the payload and the ciphertext segment hashes untouched, and returns the
// rewritten archive.
//
// The manifest is only re-serialized, never re-signed: the root signature
// covers the segment hashes, not the JSON encoding, so mutating these fields
// leaves a container that is still internally consistent on the wire --
// exactly the situation go-sdk has to cope with, whether the mutation comes
// from a writer omitting defaulted fields or from tampering.
func (s *TDFSuite) rewriteManifest(tdfBytes []byte, mutate func(integrityInfo map[string]any)) []byte {
	s.T().Helper()

	zipReader, err := zipstream.NewReader(bytes.NewReader(tdfBytes))
	s.Require().NoError(err)

	manifestBytes, err := zipReader.ReadAllFileData(zipstream.TDFManifestFileName, 10*oneMB)
	s.Require().NoError(err)

	payloadSize, err := zipReader.ReadFileSize(zipstream.TDFPayloadFileName)
	s.Require().NoError(err)
	payload, err := zipReader.ReadFileData(zipstream.TDFPayloadFileName, 0, payloadSize)
	s.Require().NoError(err)

	var manifest map[string]any
	s.Require().NoError(json.Unmarshal(manifestBytes, &manifest))

	encryptionInfo, ok := manifest["encryptionInformation"].(map[string]any)
	s.Require().True(ok)
	integrityInfo, ok := encryptionInfo["integrityInformation"].(map[string]any)
	s.Require().True(ok)

	mutate(integrityInfo)

	rewritten, err := json.Marshal(manifest)
	s.Require().NoError(err)

	ctx := context.Background()
	writer := zipstream.NewSegmentTDFWriter(1)
	defer func() { s.Require().NoError(writer.Close()) }()

	out := &bytes.Buffer{}
	header, err := writer.WriteSegment(ctx, 0, uint64(len(payload)), crc32.ChecksumIEEE(payload))
	s.Require().NoError(err)
	out.Write(header)
	out.Write(payload)

	final, err := writer.Finalize(ctx, rewritten)
	s.Require().NoError(err)
	out.Write(final)

	return out.Bytes()
}

// stripDefaultSegmentSizes rewrites a TDF so that every segment whose sizes
// match the manifest-level defaults carries neither segmentSize nor
// encryptedSegmentSize, reproducing what web-sdk emits. It returns the
// rewritten archive and the number of segments it stripped.
func (s *TDFSuite) stripDefaultSegmentSizes(tdfBytes []byte) ([]byte, int) {
	s.T().Helper()

	stripped := 0
	rewritten := s.rewriteManifest(tdfBytes, func(integrityInfo map[string]any) {
		segments, ok := integrityInfo["segments"].([]any)
		s.Require().True(ok)

		defaultSize, ok := integrityInfo["segmentSizeDefault"].(float64)
		s.Require().True(ok)
		defaultEncryptedSize, ok := integrityInfo["encryptedSegmentSizeDefault"].(float64)
		s.Require().True(ok)

		for _, raw := range segments {
			segment, isObject := raw.(map[string]any)
			s.Require().True(isObject)
			if segment["segmentSize"] != defaultSize || segment["encryptedSegmentSize"] != defaultEncryptedSize {
				continue
			}
			delete(segment, "segmentSize")
			delete(segment, "encryptedSegmentSize")
			stripped++
		}
	})

	return rewritten, stripped
}

// Test_SegmentSizesOmittedFallBackToDefaults asserts that a TDF with
// per-segment sizes omitted -- legal per manifest.schema.json whenever they
// equal the manifest-level defaults, and what web-sdk emits for every
// full-width segment -- still decrypts correctly via both WriteTo and
// ReadAt.
func (s *TDFSuite) Test_SegmentSizesOmittedFallBackToDefaults() {
	// Two full segments plus a partial one, so the fixture covers both the
	// omitted and the explicitly-sized case.
	plaintext := make([]byte, 2*webSDKSegmentSize+4242)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	kasInfoList := make([]KASInfo, len(s.kases))
	for i, ki := range s.kases {
		kasInfoList[i] = ki.KASInfo
		kasInfoList[i].PublicKey = ""
	}
	kasInfoList[0].Default = true

	original := &bytes.Buffer{}
	_, err := s.sdk.CreateTDF(original, bytes.NewReader(plaintext),
		WithKasInformation(kasInfoList...),
		WithSegmentSize(webSDKSegmentSize),
	)
	s.Require().NoError(err)

	tdfBytes, stripped := s.stripDefaultSegmentSizes(original.Bytes())
	s.Require().Equal(2, stripped, "fixture should have two default-sized segments to strip")

	s.Run("WriteTo", func() {
		r, err := s.sdk.LoadTDF(bytes.NewReader(tdfBytes))
		s.Require().NoError(err)

		// payloadSize has to account for the omitted segments too;
		// otherwise Seek and the ReadAt bounds check both truncate.
		s.Require().Equal(int64(len(plaintext)), r.payloadSize)

		decrypted := &bytes.Buffer{}
		n, err := io.Copy(decrypted, r)
		s.Require().NoError(err)
		s.Require().Equal(int64(len(plaintext)), n)
		s.Require().Equal(plaintext, decrypted.Bytes())
	})

	s.Run("ReadAt", func() {
		r, err := s.sdk.LoadTDF(bytes.NewReader(tdfBytes))
		s.Require().NoError(err)

		// Start inside the second segment so the read has to skip a
		// segment whose size was omitted before it decrypts one.
		const offset = webSDKSegmentSize + 100
		buf := make([]byte, 4096)
		n, err := r.ReadAt(buf, offset)
		s.Require().NoError(err)
		s.Require().Equal(len(buf), n)
		s.Require().Equal(plaintext[offset:offset+int64(len(buf))], buf)
	})
}

// Test_TamperedManifestDefaultsRejected asserts that a TDF whose per-segment
// sizes were omitted (as web-sdk emits) is rejected -- not silently
// misdecrypted -- when the manifest-level defaults it falls back to are
// internally inconsistent with AES-GCM's fixed nonce+tag overhead. This
// covers tampering (or a buggy writer) that targets the defaults themselves
// rather than any individual segment's fields.
func (s *TDFSuite) Test_TamperedManifestDefaultsRejected() {
	kasInfoList := make([]KASInfo, len(s.kases))
	for i, ki := range s.kases {
		kasInfoList[i] = ki.KASInfo
		kasInfoList[i].PublicKey = ""
	}
	kasInfoList[0].Default = true

	plaintext := make([]byte, webSDKSegmentSize)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	original := &bytes.Buffer{}
	_, err := s.sdk.CreateTDF(original, bytes.NewReader(plaintext),
		WithKasInformation(kasInfoList...),
		WithSegmentSize(webSDKSegmentSize),
	)
	s.Require().NoError(err)

	tdfBytes, stripped := s.stripDefaultSegmentSizes(original.Bytes())
	s.Require().Equal(1, stripped, "fixture should have one default-sized segment to strip")

	// Inflate the plaintext default by one byte relative to the ciphertext
	// default, so the pair no longer differs by exactly the AES-GCM
	// nonce+tag overhead -- with every per-segment field already omitted,
	// this is the only place left for the inconsistency to live.
	tdfBytes = s.rewriteManifest(tdfBytes, func(integrityInfo map[string]any) {
		defaultSize, ok := integrityInfo["segmentSizeDefault"].(float64)
		s.Require().True(ok)
		integrityInfo["segmentSizeDefault"] = defaultSize + 1
	})

	_, err = s.sdk.LoadTDF(bytes.NewReader(tdfBytes))
	s.Require().ErrorIs(err, ErrSegSizeMismatch)
}

// zeroLenOKReader wraps an empty *bytes.Reader so a zero-length Read reports
// (0, nil) rather than (0, io.EOF). bytes.Reader reports EOF on any Read once
// exhausted, including a zero-length one, which trips CreateTDFContext's
// segment-read loop for a genuinely empty payload before segment sizing is
// ever reached -- a separate, pre-existing quirk this test works around
// rather than exercises. In practice this means SDK.CreateTDF cannot itself
// encrypt a genuinely empty io.Reader today (e.g. bytes.NewReader(nil)); that
// gap is unrelated to segment-size defaulting and is not fixed here.
type zeroLenOKReader struct {
	*bytes.Reader
}

func (r zeroLenOKReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return r.Reader.Read(p)
}

// Test_EmptyPayloadRoundTrip asserts that an empty-payload TDF -- whose sole
// segment has segmentSize: 0 in the manifest (no omitempty on the field),
// indistinguishable on the wire from a segment that omitted the key to
// inherit a non-zero manifest-level default -- round-trips to a payloadSize
// of 0, not the default segment size.
func (s *TDFSuite) Test_EmptyPayloadRoundTrip() {
	kasInfoList := make([]KASInfo, len(s.kases))
	for i, ki := range s.kases {
		kasInfoList[i] = ki.KASInfo
		kasInfoList[i].PublicKey = ""
	}
	kasInfoList[0].Default = true

	tdfBuf := &bytes.Buffer{}
	_, err := s.sdk.CreateTDF(tdfBuf, zeroLenOKReader{bytes.NewReader(nil)}, WithKasInformation(kasInfoList...))
	s.Require().NoError(err)

	r, err := s.sdk.LoadTDF(bytes.NewReader(tdfBuf.Bytes()))
	s.Require().NoError(err)
	s.Require().Equal(int64(0), r.payloadSize)

	decrypted := &bytes.Buffer{}
	n, err := io.Copy(decrypted, r)
	s.Require().NoError(err)
	s.Require().Equal(int64(0), n)
}

// TestResolveSegmentSizes covers the fallback rules directly: EncryptedSize
// defaults whenever it is zero, Size's ambiguous zero is resolved by
// comparing the (possibly already-defaulted) EncryptedSize against its own
// default rather than by whether Size and EncryptedSize were omitted
// together, a legitimate zero-length segment is preserved rather than
// defaulted, and a resolved pair that disagrees with AES-GCM's fixed framing
// is rejected -- whether the inconsistency comes from explicit per-segment
// fields or from the manifest-level defaults themselves.
func TestResolveSegmentSizes(t *testing.T) {
	defaults := IntegrityInformation{
		DefaultSegmentSize:      1024,
		DefaultEncryptedSegSize: 1052,
	}

	for _, tc := range []struct {
		name              string
		integrity         IntegrityInformation
		segment           Segment
		wantSize          int64
		wantEncryptedSize int64
		wantErrIs         error
	}{
		{
			name:              "explicit sizes win",
			integrity:         defaults,
			segment:           Segment{Size: 7, EncryptedSize: 35},
			wantSize:          7,
			wantEncryptedSize: 35,
		},
		{
			name:              "both omitted fall back",
			integrity:         defaults,
			segment:           Segment{},
			wantSize:          1024,
			wantEncryptedSize: 1052,
		},
		{
			// web-sdk decides whether to omit Size and EncryptedSize
			// independently of each other -- an explicit, physically-consistent
			// Size with an omitted EncryptedSize is unusual but not itself
			// contradictory, so Size is trusted as given and EncryptedSize
			// falls back to the default on its own.
			name:              "Size explicit, EncryptedSize omitted, independently",
			integrity:         defaults,
			segment:           Segment{Size: 1024},
			wantSize:          1024,
			wantEncryptedSize: 1052,
		},
		{
			name:              "explicit zero-length segment is legal",
			integrity:         defaults,
			segment:           Segment{Size: 0, EncryptedSize: 28},
			wantSize:          0,
			wantEncryptedSize: 28,
		},
		{
			// Size omitted (0) while EncryptedSize is given explicitly as
			// exactly the default: the disambiguation compares EncryptedSize
			// against DefaultEncryptedSegSize, not against seg.EncryptedSize
			// being zero, so this resolves the same as full omission would.
			name:              "Size omitted, EncryptedSize explicit but equal to its default",
			integrity:         defaults,
			segment:           Segment{Size: 0, EncryptedSize: 1052},
			wantSize:          1024,
			wantEncryptedSize: 1052,
		},
		{
			name:      "no value and no default is an error",
			integrity: IntegrityInformation{},
			segment:   Segment{},
			wantErrIs: ErrSegSizeUnresolved,
		},
		{
			name:      "negative default is an error",
			integrity: IntegrityInformation{DefaultSegmentSize: -1, DefaultEncryptedSegSize: -1},
			segment:   Segment{},
			wantErrIs: ErrSegSizeUnresolved,
		},
		{
			// An explicit Size that doesn't match the AES-GCM framing implied
			// by EncryptedSize (whether EncryptedSize is explicit or defaulted)
			// is rejected here rather than left for a caller to discover
			// downstream.
			name:      "inconsistent explicit sizes are rejected",
			integrity: defaults,
			segment:   Segment{Size: 7, EncryptedSize: 1052},
			wantErrIs: ErrSegSizeMismatch,
		},
		{
			// The same consistency check applies to the manifest-level
			// defaults themselves, not just explicit per-segment fields -- a
			// manifest whose defaults were tampered with is caught the same
			// way, even though every per-segment field is omitted.
			name:      "inconsistent manifest-level defaults are rejected",
			integrity: IntegrityInformation{DefaultSegmentSize: 999, DefaultEncryptedSegSize: 1052},
			segment:   Segment{},
			wantErrIs: ErrSegSizeMismatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			size, encryptedSize, err := tc.integrity.resolveSegmentSizes(tc.segment)
			if tc.wantErrIs != nil {
				require.ErrorIs(t, err, tc.wantErrIs)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantSize, size)
			assert.Equal(t, tc.wantEncryptedSize, encryptedSize)
		})
	}
}
