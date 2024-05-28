package sdk

import (
	"bytes"
	"io"
	"testing"
)

const (
	kSampleURLBody = "test.virtru.com"
	// kSampleUrlProto = policyTypeRemotePolicy
	kSampleURLFull = "https://" + kSampleURLBody
)

// TestNanoTDFPolicyWrite - Create a new policy, write it to a buffer
func TestNanoTDFPolicy(t *testing.T) {
	pb := &PolicyBody{
		mode: policyTypeRemotePolicy,
		rp: remotePolicy{
			url: ResourceLocator{
				protocol: 1,
				body:     kSampleURLBody,
			},
		},
	}

	buffer := new(bytes.Buffer)
	err := pb.writePolicyBody(io.Writer(buffer))
	if err != nil {
		t.Fatal(err)
	}

	pb2 := &PolicyBody{}
	err = pb2.readPolicyBody(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	fullURL, err := pb2.rp.url.getURL()
	if err != nil {
		t.Fatal(err)
	}
	if fullURL != kSampleURLFull {
		t.Fatal(fullURL)
	}
}
