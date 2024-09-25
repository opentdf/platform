package main

import (
	"audit-log/tdflog"
	"github.com/opentdf/platform/sdk"
)


func main() {
	sdkClient, err := sdk.New("localhost:8080", sdk.WithInsecurePlaintextConn())
	if err != nil {
		panic(err)
	}

	logger := tdflog.NewTDFLogger("http://localhost:8080", tdflog.WithSDK(sdkClient), 
		tdflog.WithAttributeMap(map[string][]string{
			"PII": {"http://example.com/attr/demo/value/pii"},
			"HIPPA": {"http://example.com/attr/demo/value/hippa"},
			"THIRD": {"http://example.com/attr/demo/value/third"},
		}),
		tdflog.WithAttributes("PII"),
	) 

	//basic test
	logger.Info("basic", "attr", "val") // nothing
	// user-password should be a ntdf with only PII
	logger.Info("encrypted attr", tdflog.Protect("users-password", "password")) // PII

	// should be a ntdf with HIPPA and PII
	logger.Info("have hippa", tdflog.Protect("users-password", "password", "HIPPA")) // HIPPA and PII

	third := logger.With(tdflog.AddAttributes("THIRD"))
	third.Info("simple third", tdflog.Protect("users-password", "password")) // THIRD PII

	third.Info("everyone now!", tdflog.Protect("users-password", "password", "HIPPA")) // THIRD PII and HIPPA
}
