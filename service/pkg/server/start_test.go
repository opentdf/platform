package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/db"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				t, ok := server.(*TestService)
				if !ok {
					return fmt.Errorf("Surprise! Not a TestService")
				}
				return mux.HandlePath(http.MethodGet, "/testpath/{name}", t.TestHandler)
			}
		},
	}
}

func Test_Start_When_Extra_Service_Registered_Expect_Response(t *testing.T) {
	// Create new opentdf server
	d, _ := db.NewClient(db.Config{})
	s, err := server.NewOpenTDFServer(server.Config{
		WellKnownConfigRegister: func(namespace string, config any) error {
			return nil
		},
		Auth: auth.Config{
			Enabled: false,
			AuthNConfig: auth.AuthNConfig{
				Issuer: "test",
			},
		},
		Port: 43481,
	}, d)
	require.NoError(t, err)

	// Register Test Service
	err = serviceregistry.RegisterService(ServiceRegistrationTest())
	require.NoError(t, err)

	// Start services with test service
	err = startServices(config.Config{
		Services: map[string]serviceregistry.ServiceConfig{
			"test": {
				Enabled: true,
			},
		},
	}, s, nil, nil, nil)
	require.NoError(t, err)

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

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, err := io.ReadAll(resp.Body)

	require.NoError(t, err)
	assert.Equal(t, "hello world from test service!", string(respBody))
}
