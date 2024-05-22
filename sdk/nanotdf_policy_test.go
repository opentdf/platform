package sdk

import (
	"bytes"
	"io"
	"testing"
)

const (
	kSampleUrlBody  = "test.virtru.com"
	kSampleUrlProto = policyTypeRemotePolicy
	kSampleUrlFull  = "https://" + kSampleUrlBody
)

// TestNanoTDFPolicyWrite - Create a new policy, write it to a buffer
func TestNanoTDFPolicy(t *testing.T) {
	pb := &PolicyBody{
		mode: policyTypeRemotePolicy,
		rp: remotePolicy{
			url: ResourceLocator{
				protocol: 1,
				body:     kSampleUrlBody,
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

	fullUrl, err := pb2.rp.url.getUrl()
	if err != nil {
		t.Fatal(err)
	}
	if fullUrl != kSampleUrlFull {
		t.Fatal(fullUrl)
	}
}
