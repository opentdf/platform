package trs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"google.golang.org/grpc"
)

type testReadyService struct {
	sdk *otdf.SDK
}

type Config struct {
	Services map[string]Service `json:"services"`
}

type Service struct {
	Enabled    bool                   `json:"enabled"`
	Remote     RemoteConfig           `json:"remote"`
	ExtraProps map[string]interface{} `json:"-"`
}
type RemoteConfig struct {
	Endpoint string `json:"endpoint"`
}

type HelloRequest struct {
	Name string `json:"name"`
}

type HelloReply struct {
	Message string `json:"message"`
}

var (
	platformEndpointWithProtocol = "http://127.0.0.1:8080"
	platformEndpoint             = "127.0.0.1:8080"
)

func encryptString(ctx context.Context, input string, sdk *otdf.SDK) (string, error) {
	var ciphertext bytes.Buffer
	plaintext := strings.NewReader(input)
	baseKasURL := platformEndpoint
	if !strings.HasPrefix(baseKasURL, "http://") && !strings.HasPrefix(baseKasURL, "https://") {
		baseKasURL = "http://" + baseKasURL
	}

	_, err := sdk.CreateTDFContext(
		ctx,
		&ciphertext,
		plaintext,
		otdf.WithDataAttributes(nil...),
		otdf.WithKasInformation(
			otdf.KASInfo{
				URL:       baseKasURL,
				PublicKey: "",
			},
		),
	)

	return ciphertext.String(), err
}

func (trs *testReadyService) SayHelloHandler(ctx context.Context, in *HelloRequest) (*HelloReply, error) {
	slog.InfoContext(ctx, "sayHelloHandler received", slog.String("name", in.Name))
	return &HelloReply{Message: "Hello " + in.Name}, nil
}

func (trs testReadyService) GoodbyeRequestHandler() func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
	x := func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		nameInput := pathParams["name"]
		slog.InfoContext(r.Context(), "goodbyeRequestHandler received", slog.String("name", nameInput))

		_, err := w.Write([]byte("goodbye " + pathParams["name"] + " from custom handler!"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	return x
}

func (trs testReadyService) EncryptNameHandler() func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
	x := func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		toEncrypt := pathParams["name"]
		slog.InfoContext(r.Context(), "encryptNameHandler received", slog.String("name", toEncrypt))

		encryptedString, err := encryptString(r.Context(), toEncrypt, trs.sdk)
		if err != nil {
			slog.ErrorContext(r.Context(), "error encrypting string", slog.String("error", err.Error()))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		encryptedByteString := []byte(encryptedString)

		// The 'encryptedByteString' is a zip file, make it downloadable by the web browser
		// by setting the content type to application/octet-stream
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\"encrypted.zip\"")

		_, err = w.Write(encryptedByteString)
		if err != nil {
			slog.ErrorContext(r.Context(), "error writing response", slog.String("error", err.Error()))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	return x
}

/*
FIXME: Use the given sdkClient, rather than replacing it.
*/
func newSdkClientHack(_ *otdf.SDK) (*otdf.SDK, error) {
	sdkClient, err := otdf.New(platformEndpointWithProtocol,
		otdf.WithPlatformConfiguration(otdf.PlatformConfiguration{}),
		otdf.WithInsecurePlaintextConn(),
		otdf.WithStoreCollectionHeaders(),
	)

	return sdkClient, err
}

func createTestReadyService(sdkClient *otdf.SDK, extraProps map[string]interface{}) testReadyService {
	ctx := context.Background()
	slog.DebugContext(ctx, "caller passed SDK client", slog.String("client", fmt.Sprintf("%+v", sdkClient)))

	slog.InfoContext(ctx, "setting up service")
	var cfg Config
	// Convert map to JSON
	svcJSON, err := json.Marshal(extraProps)
	if err != nil {
		slog.ErrorContext(ctx, "error unmarshalling extra properties to JSON", slog.String("error", err.Error()))
		panic("Error unmarshalling service map to JSON")
	}

	// Unmarshal JSON into Config struct
	if err := json.Unmarshal(svcJSON, &cfg); err != nil {
		slog.ErrorContext(ctx, "error unmarshalling service map to JSON", slog.String("error", err.Error()))
		panic("Error unmarshalling service map to JSON")
	}

	// Create a new SDK client
	sdkClient, err = newSdkClientHack(sdkClient)
	if err != nil {
		panic(err)
	}
	slog.DebugContext(ctx, "returning testReadyService with SDK client", slog.String("sdk_client", fmt.Sprintf("%+v", sdkClient)))

	return testReadyService{
		sdk: sdkClient,
	}
}

func registerServiceEndpoints(trs testReadyService, mux *runtime.ServeMux) error {
	must := func(err error) {
		if err != nil {
			// Just panic on errors, as there isn't much to for failed registration
			panic(err)
		}
	}
	must(mux.HandlePath(http.MethodGet, "/trs/hello/{name}", func(w http.ResponseWriter, r *http.Request, pathParams map[string]string) {
		name := pathParams["name"]
		reply, err := trs.SayHelloHandler(r.Context(), &HelloRequest{Name: name})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, writeErr := w.Write([]byte(reply.Message))
		if writeErr != nil {
			http.Error(w, writeErr.Error(), http.StatusInternalServerError)
		}
	}))
	must(mux.HandlePath(http.MethodGet, "/trs/goodbye/{name}", trs.GoodbyeRequestHandler()))
	must(mux.HandlePath(http.MethodGet, "/trs/encrypt/{name}", trs.EncryptNameHandler()))

	return nil
}

func NewRegistration() *serviceregistry.Service[testReadyService] {
	return &serviceregistry.Service[testReadyService]{
		ServiceOptions: serviceregistry.ServiceOptions[testReadyService]{
			Namespace:   "trs",
			ServiceDesc: &grpc.ServiceDesc{ServiceName: "trs", HandlerType: (*testReadyService)(nil)},
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (testReadyService, serviceregistry.HandlerServer) {
				trsService := createTestReadyService(srp.SDK, srp.Config)

				return trsService, func(ctx context.Context, mux *runtime.ServeMux) error {
					slog.InfoContext(ctx, "registering test ready service")
					return registerServiceEndpoints(trsService, mux)
				}
			},
		},
	}
}
