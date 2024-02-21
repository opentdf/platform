package com.authorization;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: authorization/authorization.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class AuthorizationServiceGrpc {

  private AuthorizationServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "authorization.AuthorizationService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<com.authorization.GetDecisionsRequest,
      com.authorization.GetDecisionsResponse> getGetDecisionsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetDecisions",
      requestType = com.authorization.GetDecisionsRequest.class,
      responseType = com.authorization.GetDecisionsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.authorization.GetDecisionsRequest,
      com.authorization.GetDecisionsResponse> getGetDecisionsMethod() {
    io.grpc.MethodDescriptor<com.authorization.GetDecisionsRequest, com.authorization.GetDecisionsResponse> getGetDecisionsMethod;
    if ((getGetDecisionsMethod = AuthorizationServiceGrpc.getGetDecisionsMethod) == null) {
      synchronized (AuthorizationServiceGrpc.class) {
        if ((getGetDecisionsMethod = AuthorizationServiceGrpc.getGetDecisionsMethod) == null) {
          AuthorizationServiceGrpc.getGetDecisionsMethod = getGetDecisionsMethod =
              io.grpc.MethodDescriptor.<com.authorization.GetDecisionsRequest, com.authorization.GetDecisionsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetDecisions"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.authorization.GetDecisionsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.authorization.GetDecisionsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AuthorizationServiceMethodDescriptorSupplier("GetDecisions"))
              .build();
        }
      }
    }
    return getGetDecisionsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.authorization.GetEntitlementsRequest,
      com.authorization.GetEntitlementsResponse> getGetEntitlementsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetEntitlements",
      requestType = com.authorization.GetEntitlementsRequest.class,
      responseType = com.authorization.GetEntitlementsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.authorization.GetEntitlementsRequest,
      com.authorization.GetEntitlementsResponse> getGetEntitlementsMethod() {
    io.grpc.MethodDescriptor<com.authorization.GetEntitlementsRequest, com.authorization.GetEntitlementsResponse> getGetEntitlementsMethod;
    if ((getGetEntitlementsMethod = AuthorizationServiceGrpc.getGetEntitlementsMethod) == null) {
      synchronized (AuthorizationServiceGrpc.class) {
        if ((getGetEntitlementsMethod = AuthorizationServiceGrpc.getGetEntitlementsMethod) == null) {
          AuthorizationServiceGrpc.getGetEntitlementsMethod = getGetEntitlementsMethod =
              io.grpc.MethodDescriptor.<com.authorization.GetEntitlementsRequest, com.authorization.GetEntitlementsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetEntitlements"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.authorization.GetEntitlementsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.authorization.GetEntitlementsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AuthorizationServiceMethodDescriptorSupplier("GetEntitlements"))
              .build();
        }
      }
    }
    return getGetEntitlementsMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static AuthorizationServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<AuthorizationServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<AuthorizationServiceStub>() {
        @java.lang.Override
        public AuthorizationServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new AuthorizationServiceStub(channel, callOptions);
        }
      };
    return AuthorizationServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static AuthorizationServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<AuthorizationServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<AuthorizationServiceBlockingStub>() {
        @java.lang.Override
        public AuthorizationServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new AuthorizationServiceBlockingStub(channel, callOptions);
        }
      };
    return AuthorizationServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static AuthorizationServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<AuthorizationServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<AuthorizationServiceFutureStub>() {
        @java.lang.Override
        public AuthorizationServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new AuthorizationServiceFutureStub(channel, callOptions);
        }
      };
    return AuthorizationServiceFutureStub.newStub(factory, channel);
  }

  /**
   */
  public interface AsyncService {

    /**
     */
    default void getDecisions(com.authorization.GetDecisionsRequest request,
        io.grpc.stub.StreamObserver<com.authorization.GetDecisionsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetDecisionsMethod(), responseObserver);
    }

    /**
     */
    default void getEntitlements(com.authorization.GetEntitlementsRequest request,
        io.grpc.stub.StreamObserver<com.authorization.GetEntitlementsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetEntitlementsMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service AuthorizationService.
   */
  public static abstract class AuthorizationServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return AuthorizationServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service AuthorizationService.
   */
  public static final class AuthorizationServiceStub
      extends io.grpc.stub.AbstractAsyncStub<AuthorizationServiceStub> {
    private AuthorizationServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AuthorizationServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new AuthorizationServiceStub(channel, callOptions);
    }

    /**
     */
    public void getDecisions(com.authorization.GetDecisionsRequest request,
        io.grpc.stub.StreamObserver<com.authorization.GetDecisionsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetDecisionsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getEntitlements(com.authorization.GetEntitlementsRequest request,
        io.grpc.stub.StreamObserver<com.authorization.GetEntitlementsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetEntitlementsMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service AuthorizationService.
   */
  public static final class AuthorizationServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<AuthorizationServiceBlockingStub> {
    private AuthorizationServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AuthorizationServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new AuthorizationServiceBlockingStub(channel, callOptions);
    }

    /**
     */
    public com.authorization.GetDecisionsResponse getDecisions(com.authorization.GetDecisionsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetDecisionsMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.authorization.GetEntitlementsResponse getEntitlements(com.authorization.GetEntitlementsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetEntitlementsMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service AuthorizationService.
   */
  public static final class AuthorizationServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<AuthorizationServiceFutureStub> {
    private AuthorizationServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AuthorizationServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new AuthorizationServiceFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.authorization.GetDecisionsResponse> getDecisions(
        com.authorization.GetDecisionsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetDecisionsMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.authorization.GetEntitlementsResponse> getEntitlements(
        com.authorization.GetEntitlementsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetEntitlementsMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_GET_DECISIONS = 0;
  private static final int METHODID_GET_ENTITLEMENTS = 1;

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
        case METHODID_GET_DECISIONS:
          serviceImpl.getDecisions((com.authorization.GetDecisionsRequest) request,
              (io.grpc.stub.StreamObserver<com.authorization.GetDecisionsResponse>) responseObserver);
          break;
        case METHODID_GET_ENTITLEMENTS:
          serviceImpl.getEntitlements((com.authorization.GetEntitlementsRequest) request,
              (io.grpc.stub.StreamObserver<com.authorization.GetEntitlementsResponse>) responseObserver);
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
          getGetDecisionsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.authorization.GetDecisionsRequest,
              com.authorization.GetDecisionsResponse>(
                service, METHODID_GET_DECISIONS)))
        .addMethod(
          getGetEntitlementsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.authorization.GetEntitlementsRequest,
              com.authorization.GetEntitlementsResponse>(
                service, METHODID_GET_ENTITLEMENTS)))
        .build();
  }

  private static abstract class AuthorizationServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    AuthorizationServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return com.authorization.AuthorizationProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("AuthorizationService");
    }
  }

  private static final class AuthorizationServiceFileDescriptorSupplier
      extends AuthorizationServiceBaseDescriptorSupplier {
    AuthorizationServiceFileDescriptorSupplier() {}
  }

  private static final class AuthorizationServiceMethodDescriptorSupplier
      extends AuthorizationServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    AuthorizationServiceMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (AuthorizationServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new AuthorizationServiceFileDescriptorSupplier())
              .addMethod(getGetDecisionsMethod())
              .addMethod(getGetEntitlementsMethod())
              .build();
        }
      }
    }
    return result;
  }
}
