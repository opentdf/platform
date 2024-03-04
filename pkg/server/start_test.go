package server

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/internal/config"
	"github.com/opentdf/platform/internal/server"
	"github.com/opentdf/platform/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

type TestServiceService interface{}
type TestService struct{}

func (t TestService) TestHandler(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
	w.Write([]byte("hello " + pathParams["name"] + " from test service!"))
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
		Grpc: server.GrpcConfig{
			Port: 43482,
		},
		HTTP: server.HTTPConfig{
			Enabled: true,
			Port:    43481,
		},
	})
	assert.Nil(t, err)

	// Register Test Service
	serviceregistry.RegisterService(ServiceRegistrationTest())

	// Start services with test service
	err = startServices(config.Config{
		Services: map[string]config.ServiceConfig{
			"test": {
				Enabled: true,
			},
		},
	}, s, nil, nil)
	assert.Nil(t, err)

	s.Run()

	defer s.Stop()

	// Make request to test service and ensure it registered
	resp, err := http.Get("http://localhost:43481/testpath/world")
	assert.Nil(t, err)
	assert.Equal(t, resp.StatusCode, http.StatusOK)

	respBody, err := io.ReadAll(resp.Body)
	assert.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, "hello world from test service!", string(respBody))
}
