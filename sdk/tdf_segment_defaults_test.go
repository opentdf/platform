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

// stripDefaultSegmentSizes rewrites a TDF so that every segment whose sizes
// match the manifest-level defaults carries neither segmentSize nor
// encryptedSegmentSize, reproducing what web-sdk emits. It returns the
// rewritten archive and the number of segments it stripped.
//
// The manifest is only re-serialized, never re-signed: the root signature
// covers the segment hashes, not the JSON encoding, so dropping these keys
// leaves a container that is still internally consistent -- exactly the
// situation go-sdk has to cope with.
func (s *TDFSuite) stripDefaultSegmentSizes(tdfBytes []byte) ([]byte, int) {
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
	segments, ok := integrityInfo["segments"].([]any)
	s.Require().True(ok)

	defaultSize, ok := integrityInfo["segmentSizeDefault"].(float64)
	s.Require().True(ok)
	defaultEncryptedSize, ok := integrityInfo["encryptedSegmentSizeDefault"].(float64)
	s.Require().True(ok)

	stripped := 0
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

	return out.Bytes(), stripped
}

// Test_SegmentSizesOmittedFallBackToDefaults covers DSPX-4590 finding 7.
//
// web-sdk omits segmentSize/encryptedSegmentSize whenever they equal the
// manifest-level defaults, which the schema permits. go-sdk used to read the
// absent keys as zero, so every web-sdk container over 1 MiB -- the first
// size at which a full-width segment appears -- failed to decrypt.
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

// TestResolveSegmentSizes covers the fallback rules directly, including the
// zero-length segment that used to slip past the read-length check and fail
// later inside the GMAC calculation.
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
		wantErr           bool
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
			name:              "one omitted falls back",
			integrity:         defaults,
			segment:           Segment{Size: 7},
			wantSize:          7,
			wantEncryptedSize: 1052,
		},
		{
			name:      "no value and no default is an error",
			integrity: IntegrityInformation{},
			segment:   Segment{},
			wantErr:   true,
		},
		{
			name:      "negative default is an error",
			integrity: IntegrityInformation{DefaultSegmentSize: -1, DefaultEncryptedSegSize: -1},
			segment:   Segment{},
			wantErr:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			size, encryptedSize, err := tc.integrity.resolveSegmentSizes(tc.segment)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrSegSizeUnresolved)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantSize, size)
			assert.Equal(t, tc.wantEncryptedSize, encryptedSize)
		})
	}
}
