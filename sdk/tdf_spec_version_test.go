package sdk

import (
	"bytes"
	"io"
)

// Test_SpecVersionSelectsDigestEncoding covers how a reader decides whether a
// container's integrity digests are hex-encoded (pre-4.3.0) or raw: from the
// manifest's spec version, the only signal a file carries for it.
//
// The check used to be "no version at all means hex", which reads the field too
// narrowly. Our writer omits the version and hex-encodes together, so absence
// does imply hex -- but a manifest that records a version below 4.3.0 states
// the same thing outright, and was verified as raw and rejected. That now
// includes versions written under the off-spec tdf_spec_version name, which
// this branch reads: before, such a container decoded to no version at all and
// happened to verify; reading the name without widening the check would have
// flipped it to raw and broken it.
//
// Trusting the field has limits, and the cases below write them down rather
// than leave them implied. Nothing authenticates the spec version, so where it
// disagrees with the digests, or sits somewhere the reader does not look, the
// container does not read.
func (s *TDFSuite) Test_SpecVersionSelectsDigestEncoding() {
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

	// rejected covers the containers the reader verifies with the wrong digest
	// encoding. The manifest still parses and the key still unwraps; the file
	// fails on the integrity check.
	rejected := func(tdfBytes []byte, wantVersion string) {
		r, err := s.sdk.LoadTDF(bytes.NewReader(tdfBytes))
		s.Require().NoError(err)
		s.Require().Equal(wantVersion, r.Manifest().TDFVersion)

		_, err = io.Copy(&bytes.Buffer{}, r)
		s.Require().Error(err)
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

		s.Run("version renamed to tdf_spec_version under payload", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				setPayloadKey(manifest, "tdf_spec_version", manifest["schemaVersion"])
				delete(manifest, "schemaVersion")
			}), TDFSpecVersion)
		})

		// The root is not a placement any schema defines, so the version reads
		// as absent and the reader falls back to hex.
		s.Run("version renamed to tdf_spec_version at root", func() {
			rejected(rewrite(func(manifest map[string]any) {
				manifest["tdf_spec_version"] = manifest["schemaVersion"]
				delete(manifest, "schemaVersion")
			}), "")
		})

		s.Run("version removed entirely", func() {
			rejected(rewrite(func(manifest map[string]any) {
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

		// The case the narrow check got wrong on the canonical path: a version
		// recorded under the correct name, below the 4.3.0 threshold, saying
		// the digests are hex. "Present" was read as "raw" and the container
		// was rejected.
		s.Run("with schemaVersion below the hex threshold", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				manifest["schemaVersion"] = "4.2.2"
			}), "4.2.2")
		})

		// The same statement under the off-spec name. Reading tdf_spec_version
		// without widening the check would have turned this into a rejection.
		s.Run("with off-spec tdf_spec_version under payload", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				setPayloadKey(manifest, "tdf_spec_version", "4.2.2")
			}), "4.2.2")
		})

		s.Run("with off-spec tdf_spec_version at root", func() {
			decrypts(rewrite(func(manifest map[string]any) {
				manifest["tdf_spec_version"] = "4.2.2"
			}), "")
		})

		// A version that contradicts the digests outright. Nothing
		// authenticates the field, so a reader that trusts it verifies with the
		// wrong encoding -- the cost of taking the encoding from metadata.
		s.Run("with a schemaVersion that contradicts the digests", func() {
			rejected(rewrite(func(manifest map[string]any) {
				manifest["schemaVersion"] = TDFSpecVersion
			}), TDFSpecVersion)
		})
	})
}
