package server

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/internal/auth"
	"github.com/opentdf/platform/internal/config"
	"github.com/opentdf/platform/internal/server"
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
)

type TestServiceService interface{}
type TestService struct{}

func (t TestService) TestHandler(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
	_, err := w.Write([]byte("hello " + pathParams["name"] + " from test service!"))
	if err != nil {
		panic(err)
	}
}

func ServiceRegistrationTest() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace: "test",
		ServiceDesc: &grpc.ServiceDesc{
			ServiceName: "TestService",
			HandlerType: (*TestServiceService)(nil),
		},
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &TestService{}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				err := mux.HandlePath("GET", "/testpath/{name}", server.(*TestService).TestHandler)
				if err != nil {
					return err
				}
				return nil
			}
		},
	}
}

func Test_Start_When_Extra_Service_Registered_Expect_Response(t *testing.T) {
	// Create new opentdf server
	s, err := server.NewOpenTDFServer(server.Config{
		Auth: auth.Config{
			Enabled: false,
		},
		GRPC: server.GRPCConfig{
			Port: 43482,
		},
		HTTP: server.HTTPConfig{
			Enabled: true,
			Port:    43481,
		},
	})
	assert.NoError(t, err)

	// Register Test Service
	err = serviceregistry.RegisterService(ServiceRegistrationTest())
	assert.NoError(t, err)

	// Start services with test service
	err = startServices(config.Config{
		Services: map[string]serviceregistry.ServiceConfig{
			"test": {
				Enabled: true,
			},
		},
	}, s, nil, nil, nil)
	assert.Nil(t, err)

	s.Start()

	defer s.Stop()

	var resp *http.Response
	// Make request to test service and ensure it registered
	for i := 3; i > 0; i-- {
		resp, err = http.Get("http://localhost:43481/testpath/world")
		if err == nil {
			break
		}
		slog.Info("not yet ready", "err", err)
		// retry after a blip
		time.Sleep(100 * time.Millisecond)
	}

	assert.NoError(t, err)
	if t.Failed() {
		return
	}
	assert.Equal(t, resp.StatusCode, http.StatusOK)

	respBody, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, "hello world from test service!", string(respBody))
}
