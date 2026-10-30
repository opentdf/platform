package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/protocol/go/kas/kasconnectv2"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// fakeAccessServiceV2 is a connect-go v2 KAS handler that records what it sees.
type fakeAccessServiceV2 struct {
	kasconnectv2.UnimplementedAccessServiceHandler

	record *kasRecord
}

func (f fakeAccessServiceV2) PublicKey(ctx context.Context, _ *kas.PublicKeyRequest) (*kas.PublicKeyResponse, error) {
	f.record.recordPublicKey(ctx)
	return &kas.PublicKeyResponse{}, nil
}

func (f fakeAccessServiceV2) Rewrap(ctx context.Context, _ *kas.RewrapRequest) (*kas.RewrapResponse, error) {
	if f.record.recordRewrap(ctx) {
		return nil, connectv2.NewError(connectv2.CodeFailedPrecondition, "rewrap failed")
	}
	return &kas.RewrapResponse{}, nil
}

// newV2Server mounts server and serves it over an in-memory transport, adding
// the request body bytes it reads to bodyRead.
func (s *AuthSuite) newV2Server(server *connectv2.Server, bodyRead *atomic.Int64, opts ...connecthttp.Option) *memhttp.Server {
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server, opts...)
	return s.serve(mux, bodyRead)
}

// newV2KASServer serves a fake connect-go v2 KAS behind the v2 authn and authz
// interceptors, wired the way the platform wires external v2 services.
func (s *AuthSuite) newV2KASServer(auth *Authentication, readMaxBytes int) (*memhttp.Server, *kasRecord) {
	record := &kasRecord{}
	server := connectv2.NewServer(auth.ConnectAuthNInterceptorV2(), auth.ConnectAuthZInterceptorV2())
	kasconnectv2.RegisterAccessServiceHandler(server, fakeAccessServiceV2{record: record})
	var opts []connecthttp.Option
	if readMaxBytes > 0 {
		opts = append(opts, connecthttp.WithReadMaxBytes(readMaxBytes))
	}
	return s.newV2Server(server, &record.bodyRead, opts...), record
}

func (s *AuthSuite) newV2GetServer(auth *Authentication) *memhttp.Server {
	server := connectv2.NewServer(auth.ConnectAuthNInterceptorV2())
	server.Register(connectv2.Method{
		Spec: connectv2.Spec{
			Procedure:        gateTestGetProc,
			StreamType:       connectv2.StreamTypeUnary,
			IdempotencyLevel: connectv2.IdempotencyNoSideEffects,
		},
		Handler: func(_ context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
			var req emptypb.Empty
			if err := stream.Receive(&req); err != nil {
				return err
			}
			return stream.Send(&emptypb.Empty{})
		},
	})
	return s.newV2Server(server, new(atomic.Int64))
}

func (s *AuthSuite) newV2UploadServer(auth *Authentication, called *atomic.Bool) *memhttp.Server {
	server := connectv2.NewServer(auth.ConnectAuthNInterceptorV2())
	server.Register(connectv2.Method{
		Spec: connectv2.Spec{Procedure: gateTestUploadProc, StreamType: connectv2.StreamTypeClient},
		Handler: func(_ context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
			called.Store(true)
			for {
				var msg emptypb.Empty
				if err := stream.Receive(&msg); err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return err
				}
			}
			return stream.Send(&emptypb.Empty{})
		},
	})
	return s.newV2Server(server, new(atomic.Int64))
}

func (s *AuthSuite) Test_IPCServerInterceptorV2() {
	var gotClientID string
	var gotRawToken []string
	server := connectv2.NewServer(s.auth.IPCServerInterceptorV2())
	server.Register(connectv2.Method{
		Spec: connectv2.Spec{Procedure: gateTestGetProc, StreamType: connectv2.StreamTypeUnary},
		Handler: func(ctx context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
			var req emptypb.Empty
			if err := stream.Receive(&req); err != nil {
				return err
			}
			inbound := true
			gotClientID, _ = ctxAuth.GetClientIDFromContext(ctx, inbound)
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				gotRawToken = md.Get(ctxAuth.AccessTokenKey)
			}
			return stream.Send(&emptypb.Empty{})
		},
	})
	srv := s.newV2Server(server, new(atomic.Int64))
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](srv.Client(), memhttpBaseURL(srv)+gateTestGetProc)
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set(canonicalIPCHeaderClientID, "client-ipc")

	_, err := client.CallUnary(s.T().Context(), req)

	s.Require().NoError(err)
	s.Equal("client-ipc", gotClientID)
	s.Empty(gotRawToken)

	s.Run("reauth route without credentials is rejected", func() {
		reauthServer := connectv2.NewServer(s.auth.IPCServerInterceptorV2())
		kasconnectv2.RegisterAccessServiceHandler(reauthServer, fakeAccessServiceV2{record: &kasRecord{}})
		reauthSrv := s.newV2Server(reauthServer, new(atomic.Int64))
		kasClient := kasconnect.NewAccessServiceClient(reauthSrv.Client(), memhttpBaseURL(reauthSrv))

		_, err := kasClient.Rewrap(s.T().Context(), connect.NewRequest(&kas.RewrapRequest{}))

		s.Equal(connect.CodeUnauthenticated, connect.CodeOf(err))
	})
}
