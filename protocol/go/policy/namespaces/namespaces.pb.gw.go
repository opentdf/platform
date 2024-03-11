// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.
// source: policy/namespaces/namespaces.proto

/*
Package namespaces is a reverse proxy.

It translates gRPC into RESTful JSON APIs.
*/
package namespaces

import (
	"context"
	"io"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/grpc-ecosystem/grpc-gateway/v2/utilities"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Suppress "imported and not used" errors
var _ codes.Code
var _ io.Reader
var _ status.Status
var _ = runtime.String
var _ = utilities.NewDoubleArray
var _ = metadata.Join

func request_NamespaceService_GetNamespace_0(ctx context.Context, marshaler runtime.Marshaler, client NamespaceServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq GetNamespaceRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "id")
	}

	protoReq.Id, err = runtime.String(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "id", err)
	}

	msg, err := client.GetNamespace(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_NamespaceService_GetNamespace_0(ctx context.Context, marshaler runtime.Marshaler, server NamespaceServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq GetNamespaceRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "id")
	}

	protoReq.Id, err = runtime.String(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "id", err)
	}

	msg, err := server.GetNamespace(ctx, &protoReq)
	return msg, metadata, err

}

var (
	filter_NamespaceService_ListNamespaces_0 = &utilities.DoubleArray{Encoding: map[string]int{}, Base: []int(nil), Check: []int(nil)}
)

func request_NamespaceService_ListNamespaces_0(ctx context.Context, marshaler runtime.Marshaler, client NamespaceServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq ListNamespacesRequest
	var metadata runtime.ServerMetadata

	if err := req.ParseForm(); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := runtime.PopulateQueryParameters(&protoReq, req.Form, filter_NamespaceService_ListNamespaces_0); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.ListNamespaces(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_NamespaceService_ListNamespaces_0(ctx context.Context, marshaler runtime.Marshaler, server NamespaceServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq ListNamespacesRequest
	var metadata runtime.ServerMetadata

	if err := req.ParseForm(); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := runtime.PopulateQueryParameters(&protoReq, req.Form, filter_NamespaceService_ListNamespaces_0); err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := server.ListNamespaces(ctx, &protoReq)
	return msg, metadata, err

}

func request_NamespaceService_CreateNamespace_0(ctx context.Context, marshaler runtime.Marshaler, client NamespaceServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq CreateNamespaceRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := client.CreateNamespace(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_NamespaceService_CreateNamespace_0(ctx context.Context, marshaler runtime.Marshaler, server NamespaceServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq CreateNamespaceRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	msg, err := server.CreateNamespace(ctx, &protoReq)
	return msg, metadata, err

}

func request_NamespaceService_UpdateNamespace_0(ctx context.Context, marshaler runtime.Marshaler, client NamespaceServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq UpdateNamespaceRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "id")
	}

	protoReq.Id, err = runtime.String(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "id", err)
	}

	msg, err := client.UpdateNamespace(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_NamespaceService_UpdateNamespace_0(ctx context.Context, marshaler runtime.Marshaler, server NamespaceServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq UpdateNamespaceRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "id")
	}

	protoReq.Id, err = runtime.String(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "id", err)
	}

	msg, err := server.UpdateNamespace(ctx, &protoReq)
	return msg, metadata, err

}

func request_NamespaceService_DeactivateNamespace_0(ctx context.Context, marshaler runtime.Marshaler, client NamespaceServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq DeactivateNamespaceRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "id")
	}

	protoReq.Id, err = runtime.String(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "id", err)
	}

	msg, err := client.DeactivateNamespace(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_NamespaceService_DeactivateNamespace_0(ctx context.Context, marshaler runtime.Marshaler, server NamespaceServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq DeactivateNamespaceRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "id")
	}

	protoReq.Id, err = runtime.String(val)
	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "id", err)
	}

	msg, err := server.DeactivateNamespace(ctx, &protoReq)
	return msg, metadata, err

}

// RegisterNamespaceServiceHandlerServer registers the http handlers for service NamespaceService to "mux".
// UnaryRPC     :call NamespaceServiceServer directly.
// StreamingRPC :currently unsupported pending https://github.com/grpc/grpc-go/issues/906.
// Note that using this registration option will cause many gRPC library features to stop working. Consider using RegisterNamespaceServiceHandlerFromEndpoint instead.
func RegisterNamespaceServiceHandlerServer(ctx context.Context, mux *runtime.ServeMux, server NamespaceServiceServer) error {

	mux.Handle("GET", pattern_NamespaceService_GetNamespace_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/policy.namespaces.NamespaceService/GetNamespace", runtime.WithHTTPPathPattern("/attributes/namespaces/{id}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_NamespaceService_GetNamespace_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_GetNamespace_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("GET", pattern_NamespaceService_ListNamespaces_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/policy.namespaces.NamespaceService/ListNamespaces", runtime.WithHTTPPathPattern("/attributes/namespaces"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_NamespaceService_ListNamespaces_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_ListNamespaces_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_NamespaceService_CreateNamespace_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/policy.namespaces.NamespaceService/CreateNamespace", runtime.WithHTTPPathPattern("/attributes/namespaces"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_NamespaceService_CreateNamespace_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_CreateNamespace_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("PATCH", pattern_NamespaceService_UpdateNamespace_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/policy.namespaces.NamespaceService/UpdateNamespace", runtime.WithHTTPPathPattern("/attributes/namespaces/{id}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_NamespaceService_UpdateNamespace_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_UpdateNamespace_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("DELETE", pattern_NamespaceService_DeactivateNamespace_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateIncomingContext(ctx, mux, req, "/policy.namespaces.NamespaceService/DeactivateNamespace", runtime.WithHTTPPathPattern("/attributes/namespaces/{id}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_NamespaceService_DeactivateNamespace_0(annotatedContext, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_DeactivateNamespace_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

// RegisterNamespaceServiceHandlerFromEndpoint is same as RegisterNamespaceServiceHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterNamespaceServiceHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterNamespaceServiceHandler(ctx, mux, conn)
}

// RegisterNamespaceServiceHandler registers the http handlers for service NamespaceService to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterNamespaceServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterNamespaceServiceHandlerClient(ctx, mux, NewNamespaceServiceClient(conn))
}

// RegisterNamespaceServiceHandlerClient registers the http handlers for service NamespaceService
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "NamespaceServiceClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "NamespaceServiceClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "NamespaceServiceClient" to call the correct interceptors.
func RegisterNamespaceServiceHandlerClient(ctx context.Context, mux *runtime.ServeMux, client NamespaceServiceClient) error {

	mux.Handle("GET", pattern_NamespaceService_GetNamespace_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/policy.namespaces.NamespaceService/GetNamespace", runtime.WithHTTPPathPattern("/attributes/namespaces/{id}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_NamespaceService_GetNamespace_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_GetNamespace_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("GET", pattern_NamespaceService_ListNamespaces_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/policy.namespaces.NamespaceService/ListNamespaces", runtime.WithHTTPPathPattern("/attributes/namespaces"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_NamespaceService_ListNamespaces_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_ListNamespaces_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_NamespaceService_CreateNamespace_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/policy.namespaces.NamespaceService/CreateNamespace", runtime.WithHTTPPathPattern("/attributes/namespaces"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_NamespaceService_CreateNamespace_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_CreateNamespace_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("PATCH", pattern_NamespaceService_UpdateNamespace_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/policy.namespaces.NamespaceService/UpdateNamespace", runtime.WithHTTPPathPattern("/attributes/namespaces/{id}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_NamespaceService_UpdateNamespace_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_UpdateNamespace_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("DELETE", pattern_NamespaceService_DeactivateNamespace_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		var err error
		var annotatedContext context.Context
		annotatedContext, err = runtime.AnnotateContext(ctx, mux, req, "/policy.namespaces.NamespaceService/DeactivateNamespace", runtime.WithHTTPPathPattern("/attributes/namespaces/{id}"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_NamespaceService_DeactivateNamespace_0(annotatedContext, inboundMarshaler, client, req, pathParams)
		annotatedContext = runtime.NewServerMetadataContext(annotatedContext, md)
		if err != nil {
			runtime.HTTPError(annotatedContext, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_NamespaceService_DeactivateNamespace_0(annotatedContext, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_NamespaceService_GetNamespace_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 1, 0, 4, 1, 5, 2}, []string{"attributes", "namespaces", "id"}, ""))

	pattern_NamespaceService_ListNamespaces_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"attributes", "namespaces"}, ""))

	pattern_NamespaceService_CreateNamespace_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1}, []string{"attributes", "namespaces"}, ""))

	pattern_NamespaceService_UpdateNamespace_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 1, 0, 4, 1, 5, 2}, []string{"attributes", "namespaces", "id"}, ""))

	pattern_NamespaceService_DeactivateNamespace_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 1, 0, 4, 1, 5, 2}, []string{"attributes", "namespaces", "id"}, ""))
)

var (
	forward_NamespaceService_GetNamespace_0 = runtime.ForwardResponseMessage

	forward_NamespaceService_ListNamespaces_0 = runtime.ForwardResponseMessage

	forward_NamespaceService_CreateNamespace_0 = runtime.ForwardResponseMessage

	forward_NamespaceService_UpdateNamespace_0 = runtime.ForwardResponseMessage

	forward_NamespaceService_DeactivateNamespace_0 = runtime.ForwardResponseMessage
)
