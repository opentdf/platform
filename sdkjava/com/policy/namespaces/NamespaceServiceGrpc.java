package com.policy.namespaces;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: policy/namespaces/namespaces.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class NamespaceServiceGrpc {

  private NamespaceServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "policy.namespaces.NamespaceService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<com.policy.namespaces.GetNamespaceRequest,
      com.policy.namespaces.GetNamespaceResponse> getGetNamespaceMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetNamespace",
      requestType = com.policy.namespaces.GetNamespaceRequest.class,
      responseType = com.policy.namespaces.GetNamespaceResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.namespaces.GetNamespaceRequest,
      com.policy.namespaces.GetNamespaceResponse> getGetNamespaceMethod() {
    io.grpc.MethodDescriptor<com.policy.namespaces.GetNamespaceRequest, com.policy.namespaces.GetNamespaceResponse> getGetNamespaceMethod;
    if ((getGetNamespaceMethod = NamespaceServiceGrpc.getGetNamespaceMethod) == null) {
      synchronized (NamespaceServiceGrpc.class) {
        if ((getGetNamespaceMethod = NamespaceServiceGrpc.getGetNamespaceMethod) == null) {
          NamespaceServiceGrpc.getGetNamespaceMethod = getGetNamespaceMethod =
              io.grpc.MethodDescriptor.<com.policy.namespaces.GetNamespaceRequest, com.policy.namespaces.GetNamespaceResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetNamespace"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.GetNamespaceRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.GetNamespaceResponse.getDefaultInstance()))
              .setSchemaDescriptor(new NamespaceServiceMethodDescriptorSupplier("GetNamespace"))
              .build();
        }
      }
    }
    return getGetNamespaceMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.namespaces.ListNamespacesRequest,
      com.policy.namespaces.ListNamespacesResponse> getListNamespacesMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListNamespaces",
      requestType = com.policy.namespaces.ListNamespacesRequest.class,
      responseType = com.policy.namespaces.ListNamespacesResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.namespaces.ListNamespacesRequest,
      com.policy.namespaces.ListNamespacesResponse> getListNamespacesMethod() {
    io.grpc.MethodDescriptor<com.policy.namespaces.ListNamespacesRequest, com.policy.namespaces.ListNamespacesResponse> getListNamespacesMethod;
    if ((getListNamespacesMethod = NamespaceServiceGrpc.getListNamespacesMethod) == null) {
      synchronized (NamespaceServiceGrpc.class) {
        if ((getListNamespacesMethod = NamespaceServiceGrpc.getListNamespacesMethod) == null) {
          NamespaceServiceGrpc.getListNamespacesMethod = getListNamespacesMethod =
              io.grpc.MethodDescriptor.<com.policy.namespaces.ListNamespacesRequest, com.policy.namespaces.ListNamespacesResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListNamespaces"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.ListNamespacesRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.ListNamespacesResponse.getDefaultInstance()))
              .setSchemaDescriptor(new NamespaceServiceMethodDescriptorSupplier("ListNamespaces"))
              .build();
        }
      }
    }
    return getListNamespacesMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.namespaces.CreateNamespaceRequest,
      com.policy.namespaces.CreateNamespaceResponse> getCreateNamespaceMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateNamespace",
      requestType = com.policy.namespaces.CreateNamespaceRequest.class,
      responseType = com.policy.namespaces.CreateNamespaceResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.namespaces.CreateNamespaceRequest,
      com.policy.namespaces.CreateNamespaceResponse> getCreateNamespaceMethod() {
    io.grpc.MethodDescriptor<com.policy.namespaces.CreateNamespaceRequest, com.policy.namespaces.CreateNamespaceResponse> getCreateNamespaceMethod;
    if ((getCreateNamespaceMethod = NamespaceServiceGrpc.getCreateNamespaceMethod) == null) {
      synchronized (NamespaceServiceGrpc.class) {
        if ((getCreateNamespaceMethod = NamespaceServiceGrpc.getCreateNamespaceMethod) == null) {
          NamespaceServiceGrpc.getCreateNamespaceMethod = getCreateNamespaceMethod =
              io.grpc.MethodDescriptor.<com.policy.namespaces.CreateNamespaceRequest, com.policy.namespaces.CreateNamespaceResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateNamespace"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.CreateNamespaceRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.CreateNamespaceResponse.getDefaultInstance()))
              .setSchemaDescriptor(new NamespaceServiceMethodDescriptorSupplier("CreateNamespace"))
              .build();
        }
      }
    }
    return getCreateNamespaceMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.namespaces.UpdateNamespaceRequest,
      com.policy.namespaces.UpdateNamespaceResponse> getUpdateNamespaceMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateNamespace",
      requestType = com.policy.namespaces.UpdateNamespaceRequest.class,
      responseType = com.policy.namespaces.UpdateNamespaceResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.namespaces.UpdateNamespaceRequest,
      com.policy.namespaces.UpdateNamespaceResponse> getUpdateNamespaceMethod() {
    io.grpc.MethodDescriptor<com.policy.namespaces.UpdateNamespaceRequest, com.policy.namespaces.UpdateNamespaceResponse> getUpdateNamespaceMethod;
    if ((getUpdateNamespaceMethod = NamespaceServiceGrpc.getUpdateNamespaceMethod) == null) {
      synchronized (NamespaceServiceGrpc.class) {
        if ((getUpdateNamespaceMethod = NamespaceServiceGrpc.getUpdateNamespaceMethod) == null) {
          NamespaceServiceGrpc.getUpdateNamespaceMethod = getUpdateNamespaceMethod =
              io.grpc.MethodDescriptor.<com.policy.namespaces.UpdateNamespaceRequest, com.policy.namespaces.UpdateNamespaceResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateNamespace"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.UpdateNamespaceRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.UpdateNamespaceResponse.getDefaultInstance()))
              .setSchemaDescriptor(new NamespaceServiceMethodDescriptorSupplier("UpdateNamespace"))
              .build();
        }
      }
    }
    return getUpdateNamespaceMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.namespaces.DeactivateNamespaceRequest,
      com.policy.namespaces.DeactivateNamespaceResponse> getDeactivateNamespaceMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeactivateNamespace",
      requestType = com.policy.namespaces.DeactivateNamespaceRequest.class,
      responseType = com.policy.namespaces.DeactivateNamespaceResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.namespaces.DeactivateNamespaceRequest,
      com.policy.namespaces.DeactivateNamespaceResponse> getDeactivateNamespaceMethod() {
    io.grpc.MethodDescriptor<com.policy.namespaces.DeactivateNamespaceRequest, com.policy.namespaces.DeactivateNamespaceResponse> getDeactivateNamespaceMethod;
    if ((getDeactivateNamespaceMethod = NamespaceServiceGrpc.getDeactivateNamespaceMethod) == null) {
      synchronized (NamespaceServiceGrpc.class) {
        if ((getDeactivateNamespaceMethod = NamespaceServiceGrpc.getDeactivateNamespaceMethod) == null) {
          NamespaceServiceGrpc.getDeactivateNamespaceMethod = getDeactivateNamespaceMethod =
              io.grpc.MethodDescriptor.<com.policy.namespaces.DeactivateNamespaceRequest, com.policy.namespaces.DeactivateNamespaceResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeactivateNamespace"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.DeactivateNamespaceRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.namespaces.DeactivateNamespaceResponse.getDefaultInstance()))
              .setSchemaDescriptor(new NamespaceServiceMethodDescriptorSupplier("DeactivateNamespace"))
              .build();
        }
      }
    }
    return getDeactivateNamespaceMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static NamespaceServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<NamespaceServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<NamespaceServiceStub>() {
        @java.lang.Override
        public NamespaceServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new NamespaceServiceStub(channel, callOptions);
        }
      };
    return NamespaceServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static NamespaceServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<NamespaceServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<NamespaceServiceBlockingStub>() {
        @java.lang.Override
        public NamespaceServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new NamespaceServiceBlockingStub(channel, callOptions);
        }
      };
    return NamespaceServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static NamespaceServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<NamespaceServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<NamespaceServiceFutureStub>() {
        @java.lang.Override
        public NamespaceServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new NamespaceServiceFutureStub(channel, callOptions);
        }
      };
    return NamespaceServiceFutureStub.newStub(factory, channel);
  }

  /**
   */
  public interface AsyncService {

    /**
     * <pre>
     * 
     *Request: 
     *grpcurl -plaintext -d '{"id": "namespace-id"}' localhost:9000 policy.namespaces.NamespaceService/GetNamespace
     *Response:
     *{
     *"namespace": {
     *"id": "namespace-id",
     *"name": "namespace-name",
     *"active": true
     *}
     *}
     * </pre>
     */
    default void getNamespace(com.policy.namespaces.GetNamespaceRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.GetNamespaceResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetNamespaceMethod(), responseObserver);
    }

    /**
     * <pre>
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *Request: 
     *grpcurl -plaintext localhost:9000 policy.namespaces.NamespaceService/ListNamespaces
     *Response:
     *{
     *"namespaces": [
     *{
     *"id": "namespace-id",
     *"name": "namespace-name",
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    default void listNamespaces(com.policy.namespaces.ListNamespacesRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.ListNamespacesResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListNamespacesMethod(), responseObserver);
    }

    /**
     * <pre>
     *Request: 
     *grpcurl -plaintext -d '{"name": "namespace-name"}' localhost:9000 policy.namespaces.NamespaceService/CreateNamespace
     *Response:
     *{ "namespace": { "id": "namespace-id", "active": true } }
     * </pre>
     */
    default void createNamespace(com.policy.namespaces.CreateNamespaceRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.CreateNamespaceResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateNamespaceMethod(), responseObserver);
    }

    /**
     */
    default void updateNamespace(com.policy.namespaces.UpdateNamespaceRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.UpdateNamespaceResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateNamespaceMethod(), responseObserver);
    }

    /**
     */
    default void deactivateNamespace(com.policy.namespaces.DeactivateNamespaceRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.DeactivateNamespaceResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeactivateNamespaceMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service NamespaceService.
   */
  public static abstract class NamespaceServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return NamespaceServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service NamespaceService.
   */
  public static final class NamespaceServiceStub
      extends io.grpc.stub.AbstractAsyncStub<NamespaceServiceStub> {
    private NamespaceServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected NamespaceServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new NamespaceServiceStub(channel, callOptions);
    }

    /**
     * <pre>
     * 
     *Request: 
     *grpcurl -plaintext -d '{"id": "namespace-id"}' localhost:9000 policy.namespaces.NamespaceService/GetNamespace
     *Response:
     *{
     *"namespace": {
     *"id": "namespace-id",
     *"name": "namespace-name",
     *"active": true
     *}
     *}
     * </pre>
     */
    public void getNamespace(com.policy.namespaces.GetNamespaceRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.GetNamespaceResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetNamespaceMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *Request: 
     *grpcurl -plaintext localhost:9000 policy.namespaces.NamespaceService/ListNamespaces
     *Response:
     *{
     *"namespaces": [
     *{
     *"id": "namespace-id",
     *"name": "namespace-name",
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    public void listNamespaces(com.policy.namespaces.ListNamespacesRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.ListNamespacesResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListNamespacesMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Request: 
     *grpcurl -plaintext -d '{"name": "namespace-name"}' localhost:9000 policy.namespaces.NamespaceService/CreateNamespace
     *Response:
     *{ "namespace": { "id": "namespace-id", "active": true } }
     * </pre>
     */
    public void createNamespace(com.policy.namespaces.CreateNamespaceRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.CreateNamespaceResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateNamespaceMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateNamespace(com.policy.namespaces.UpdateNamespaceRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.UpdateNamespaceResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateNamespaceMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deactivateNamespace(com.policy.namespaces.DeactivateNamespaceRequest request,
        io.grpc.stub.StreamObserver<com.policy.namespaces.DeactivateNamespaceResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeactivateNamespaceMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service NamespaceService.
   */
  public static final class NamespaceServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<NamespaceServiceBlockingStub> {
    private NamespaceServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected NamespaceServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new NamespaceServiceBlockingStub(channel, callOptions);
    }

    /**
     * <pre>
     * 
     *Request: 
     *grpcurl -plaintext -d '{"id": "namespace-id"}' localhost:9000 policy.namespaces.NamespaceService/GetNamespace
     *Response:
     *{
     *"namespace": {
     *"id": "namespace-id",
     *"name": "namespace-name",
     *"active": true
     *}
     *}
     * </pre>
     */
    public com.policy.namespaces.GetNamespaceResponse getNamespace(com.policy.namespaces.GetNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetNamespaceMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *Request: 
     *grpcurl -plaintext localhost:9000 policy.namespaces.NamespaceService/ListNamespaces
     *Response:
     *{
     *"namespaces": [
     *{
     *"id": "namespace-id",
     *"name": "namespace-name",
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    public com.policy.namespaces.ListNamespacesResponse listNamespaces(com.policy.namespaces.ListNamespacesRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListNamespacesMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Request: 
     *grpcurl -plaintext -d '{"name": "namespace-name"}' localhost:9000 policy.namespaces.NamespaceService/CreateNamespace
     *Response:
     *{ "namespace": { "id": "namespace-id", "active": true } }
     * </pre>
     */
    public com.policy.namespaces.CreateNamespaceResponse createNamespace(com.policy.namespaces.CreateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateNamespaceMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.namespaces.UpdateNamespaceResponse updateNamespace(com.policy.namespaces.UpdateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateNamespaceMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.namespaces.DeactivateNamespaceResponse deactivateNamespace(com.policy.namespaces.DeactivateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeactivateNamespaceMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service NamespaceService.
   */
  public static final class NamespaceServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<NamespaceServiceFutureStub> {
    private NamespaceServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected NamespaceServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new NamespaceServiceFutureStub(channel, callOptions);
    }

    /**
     * <pre>
     * 
     *Request: 
     *grpcurl -plaintext -d '{"id": "namespace-id"}' localhost:9000 policy.namespaces.NamespaceService/GetNamespace
     *Response:
     *{
     *"namespace": {
     *"id": "namespace-id",
     *"name": "namespace-name",
     *"active": true
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.namespaces.GetNamespaceResponse> getNamespace(
        com.policy.namespaces.GetNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetNamespaceMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *Request: 
     *grpcurl -plaintext localhost:9000 policy.namespaces.NamespaceService/ListNamespaces
     *Response:
     *{
     *"namespaces": [
     *{
     *"id": "namespace-id",
     *"name": "namespace-name",
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.namespaces.ListNamespacesResponse> listNamespaces(
        com.policy.namespaces.ListNamespacesRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListNamespacesMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Request: 
     *grpcurl -plaintext -d '{"name": "namespace-name"}' localhost:9000 policy.namespaces.NamespaceService/CreateNamespace
     *Response:
     *{ "namespace": { "id": "namespace-id", "active": true } }
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.namespaces.CreateNamespaceResponse> createNamespace(
        com.policy.namespaces.CreateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateNamespaceMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.namespaces.UpdateNamespaceResponse> updateNamespace(
        com.policy.namespaces.UpdateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateNamespaceMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.namespaces.DeactivateNamespaceResponse> deactivateNamespace(
        com.policy.namespaces.DeactivateNamespaceRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeactivateNamespaceMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_GET_NAMESPACE = 0;
  private static final int METHODID_LIST_NAMESPACES = 1;
  private static final int METHODID_CREATE_NAMESPACE = 2;
  private static final int METHODID_UPDATE_NAMESPACE = 3;
  private static final int METHODID_DEACTIVATE_NAMESPACE = 4;

  private static final class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final AsyncService serviceImpl;
    private final int methodId;

    MethodHandlers(AsyncService serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_GET_NAMESPACE:
          serviceImpl.getNamespace((com.policy.namespaces.GetNamespaceRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.namespaces.GetNamespaceResponse>) responseObserver);
          break;
        case METHODID_LIST_NAMESPACES:
          serviceImpl.listNamespaces((com.policy.namespaces.ListNamespacesRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.namespaces.ListNamespacesResponse>) responseObserver);
          break;
        case METHODID_CREATE_NAMESPACE:
          serviceImpl.createNamespace((com.policy.namespaces.CreateNamespaceRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.namespaces.CreateNamespaceResponse>) responseObserver);
          break;
        case METHODID_UPDATE_NAMESPACE:
          serviceImpl.updateNamespace((com.policy.namespaces.UpdateNamespaceRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.namespaces.UpdateNamespaceResponse>) responseObserver);
          break;
        case METHODID_DEACTIVATE_NAMESPACE:
          serviceImpl.deactivateNamespace((com.policy.namespaces.DeactivateNamespaceRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.namespaces.DeactivateNamespaceResponse>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  public static final io.grpc.ServerServiceDefinition bindService(AsyncService service) {
    return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
        .addMethod(
          getGetNamespaceMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.namespaces.GetNamespaceRequest,
              com.policy.namespaces.GetNamespaceResponse>(
                service, METHODID_GET_NAMESPACE)))
        .addMethod(
          getListNamespacesMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.namespaces.ListNamespacesRequest,
              com.policy.namespaces.ListNamespacesResponse>(
                service, METHODID_LIST_NAMESPACES)))
        .addMethod(
          getCreateNamespaceMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.namespaces.CreateNamespaceRequest,
              com.policy.namespaces.CreateNamespaceResponse>(
                service, METHODID_CREATE_NAMESPACE)))
        .addMethod(
          getUpdateNamespaceMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.namespaces.UpdateNamespaceRequest,
              com.policy.namespaces.UpdateNamespaceResponse>(
                service, METHODID_UPDATE_NAMESPACE)))
        .addMethod(
          getDeactivateNamespaceMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.namespaces.DeactivateNamespaceRequest,
              com.policy.namespaces.DeactivateNamespaceResponse>(
                service, METHODID_DEACTIVATE_NAMESPACE)))
        .build();
  }

  private static abstract class NamespaceServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    NamespaceServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return com.policy.namespaces.NamespacesProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("NamespaceService");
    }
  }

  private static final class NamespaceServiceFileDescriptorSupplier
      extends NamespaceServiceBaseDescriptorSupplier {
    NamespaceServiceFileDescriptorSupplier() {}
  }

  private static final class NamespaceServiceMethodDescriptorSupplier
      extends NamespaceServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    NamespaceServiceMethodDescriptorSupplier(java.lang.String methodName) {
      this.methodName = methodName;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.MethodDescriptor getMethodDescriptor() {
      return getServiceDescriptor().findMethodByName(methodName);
    }
  }

  private static volatile io.grpc.ServiceDescriptor serviceDescriptor;

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    io.grpc.ServiceDescriptor result = serviceDescriptor;
    if (result == null) {
      synchronized (NamespaceServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new NamespaceServiceFileDescriptorSupplier())
              .addMethod(getGetNamespaceMethod())
              .addMethod(getListNamespacesMethod())
              .addMethod(getCreateNamespaceMethod())
              .addMethod(getUpdateNamespaceMethod())
              .addMethod(getDeactivateNamespaceMethod())
              .build();
        }
      }
    }
    return result;
  }
}
