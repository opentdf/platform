package sdk

import (
	"bytes"
	"io"
)

// Test_SpecVersionDoesNotAffectVerification asserts the property that makes the
// spec-version field safe to be wrong: it is metadata. A container decrypts
// whatever the field is called, whatever value it holds, and whether or not it
// is present at all.
//
// This did not hold until digestMatchesRecorded landed. The reader used to take
// an absent version to mean "pre-4.3.0" and verify integrity with hex digests,
// so the field's spelling and value decided whether a well-formed file could be
// read. Two kinds of file broke:
//
//   - raw digests with the version named tdf_spec_version (the off-spec name
//     from some specification drafts and some older OpenTDF docs, at the root in
//     some writers and under payload in others), or with no version at all
//   - hex digests with any version field present, which a version-trusting
//     reader would verify as raw
//
// Both are covered below. The encoding is now read off the file, so neither the
// name nor the value can make a verifiable container unreadable.
func (s *TDFSuite) Test_SpecVersionDoesNotAffectVerification() {
	plaintext := make([]byte, 4242)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	kasInfoList := make([]KASInfo, len(s.kases))
	for i, ki := range s.kases {
		kasInfoList[i] = ki.KASInfo
		kasInfoList[i].PublicKey = ""
	}
	kasInfoList[0].Default = true

	// build returns a container and a rewriter for its manifest. opts selects
	// the digest encoding: the default writes raw, WithTargetMode("<4.3.0")
	// writes hex and omits the version field entirely.
	build := func(opts ...TDFOption) func(mutate func(manifest map[string]any)) []byte {
		original := &bytes.Buffer{}
		_, err := s.sdk.CreateTDF(original, bytes.NewReader(plaintext),
			append([]TDFOption{WithKasInformation(kasInfoList...)}, opts...)...)
		s.Require().NoError(err)

		return func(mutate func(manifest map[string]any)) []byte {
			return s.rewriteManifestRoot(original.Bytes(), mutate)
		}
	}

	decrypts := func(tdfBytes []byte, wantVersion string) {
		r, err := s.sdk.LoadTDF(bytes.NewReader(tdfBytes))
		s.Require().NoError(err)
		s.Require().Equal(wantVersion, r.Manifest().TDFVersion)

		decrypted := &bytes.Buffer{}
		n, err := io.Copy(decrypted, r)
		s.Require().NoError(err)
		s.Require().Equal(int64(len(plaintext)), n)
		s.Require().Equal(plaintext, decrypted.Bytes())
	}

	setPayloadKey := func(manifest map[string]any, key string, value any) {
		payload, ok := manifest["payload"].(map[string]any)
		s.Require().True(ok)
		payload[key] = value
	}

	s.Run("raw digests", func() {
		rewrite := build()

		// Confirm the fixture is what the rest of this block assumes.
		asWritten := rewrite(func(manifest map[string]any) {
			version, ok := manifest["schemaVersion"].(string)
			s.Require().True(ok, "fixture should have been written with schemaVersion")
			s.Require().Equal(TDFSpecVersion, version)
		})
		decrypts(asWritten, TDFSpecVersion)

		s.Run("version renamed to tdf_spec_version at root", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				manifest["tdf_spec_version"] = manifest["schemaVersion"]
				delete(manifest, "schemaVersion")
			}), TDFSpecVersion)
		})

		s.Run("version renamed to tdf_spec_version under payload", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				setPayloadKey(manifest, "tdf_spec_version", manifest["schemaVersion"])
				delete(manifest, "schemaVersion")
			}), TDFSpecVersion)
		})

		s.Run("version removed entirely", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				delete(manifest, "schemaVersion")
			}), "")
		})
	})

	s.Run("hex digests", func() {
		rewrite := build(WithTargetMode("4.2.2"))

		// Pre-4.3.0 target mode writes hex digests and omits the version.
		asWritten := rewrite(func(manifest map[string]any) {
			s.Require().NotContains(manifest, "schemaVersion")
		})
		decrypts(asWritten, "")

		// The regression this guards: a hex-digest container that nonetheless
		// carries a version field. A reader that inferred "version present means
		// raw digests" would verify these with the wrong encoding and reject
		// them outright.
		s.Run("with off-spec tdf_spec_version at root", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				manifest["tdf_spec_version"] = "4.2.2"
			}), "4.2.2")
		})

		s.Run("with off-spec tdf_spec_version under payload", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				setPayloadKey(manifest, "tdf_spec_version", "4.2.2")
			}), "4.2.2")
		})

		// A version that contradicts the digests outright. Nothing authenticates
		// the field, so a reader must not let it decide the encoding.
		s.Run("with a schemaVersion that contradicts the digests", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				manifest["schemaVersion"] = TDFSpecVersion
			}), TDFSpecVersion)
		})
	})
}
