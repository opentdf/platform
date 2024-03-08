package io.opentdf.platform.kas;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 * <pre>
 * Get app info from the root path
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: kas/kas.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class AccessServiceGrpc {

  private AccessServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "kas.AccessService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.kas.InfoRequest,
      io.opentdf.platform.kas.InfoResponse> getInfoMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Info",
      requestType = io.opentdf.platform.kas.InfoRequest.class,
      responseType = io.opentdf.platform.kas.InfoResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.kas.InfoRequest,
      io.opentdf.platform.kas.InfoResponse> getInfoMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.kas.InfoRequest, io.opentdf.platform.kas.InfoResponse> getInfoMethod;
    if ((getInfoMethod = AccessServiceGrpc.getInfoMethod) == null) {
      synchronized (AccessServiceGrpc.class) {
        if ((getInfoMethod = AccessServiceGrpc.getInfoMethod) == null) {
          AccessServiceGrpc.getInfoMethod = getInfoMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.kas.InfoRequest, io.opentdf.platform.kas.InfoResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Info"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kas.InfoRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kas.InfoResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AccessServiceMethodDescriptorSupplier("Info"))
              .build();
        }
      }
    }
    return getInfoMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.kas.PublicKeyRequest,
      io.opentdf.platform.kas.PublicKeyResponse> getPublicKeyMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "PublicKey",
      requestType = io.opentdf.platform.kas.PublicKeyRequest.class,
      responseType = io.opentdf.platform.kas.PublicKeyResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.kas.PublicKeyRequest,
      io.opentdf.platform.kas.PublicKeyResponse> getPublicKeyMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.kas.PublicKeyRequest, io.opentdf.platform.kas.PublicKeyResponse> getPublicKeyMethod;
    if ((getPublicKeyMethod = AccessServiceGrpc.getPublicKeyMethod) == null) {
      synchronized (AccessServiceGrpc.class) {
        if ((getPublicKeyMethod = AccessServiceGrpc.getPublicKeyMethod) == null) {
          AccessServiceGrpc.getPublicKeyMethod = getPublicKeyMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.kas.PublicKeyRequest, io.opentdf.platform.kas.PublicKeyResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "PublicKey"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kas.PublicKeyRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kas.PublicKeyResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AccessServiceMethodDescriptorSupplier("PublicKey"))
              .build();
        }
      }
    }
    return getPublicKeyMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.kas.LegacyPublicKeyRequest,
      com.google.protobuf.StringValue> getLegacyPublicKeyMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "LegacyPublicKey",
      requestType = io.opentdf.platform.kas.LegacyPublicKeyRequest.class,
      responseType = com.google.protobuf.StringValue.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.kas.LegacyPublicKeyRequest,
      com.google.protobuf.StringValue> getLegacyPublicKeyMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.kas.LegacyPublicKeyRequest, com.google.protobuf.StringValue> getLegacyPublicKeyMethod;
    if ((getLegacyPublicKeyMethod = AccessServiceGrpc.getLegacyPublicKeyMethod) == null) {
      synchronized (AccessServiceGrpc.class) {
        if ((getLegacyPublicKeyMethod = AccessServiceGrpc.getLegacyPublicKeyMethod) == null) {
          AccessServiceGrpc.getLegacyPublicKeyMethod = getLegacyPublicKeyMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.kas.LegacyPublicKeyRequest, com.google.protobuf.StringValue>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "LegacyPublicKey"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kas.LegacyPublicKeyRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.google.protobuf.StringValue.getDefaultInstance()))
              .setSchemaDescriptor(new AccessServiceMethodDescriptorSupplier("LegacyPublicKey"))
              .build();
        }
      }
    }
    return getLegacyPublicKeyMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.kas.RewrapRequest,
      io.opentdf.platform.kas.RewrapResponse> getRewrapMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Rewrap",
      requestType = io.opentdf.platform.kas.RewrapRequest.class,
      responseType = io.opentdf.platform.kas.RewrapResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.kas.RewrapRequest,
      io.opentdf.platform.kas.RewrapResponse> getRewrapMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.kas.RewrapRequest, io.opentdf.platform.kas.RewrapResponse> getRewrapMethod;
    if ((getRewrapMethod = AccessServiceGrpc.getRewrapMethod) == null) {
      synchronized (AccessServiceGrpc.class) {
        if ((getRewrapMethod = AccessServiceGrpc.getRewrapMethod) == null) {
          AccessServiceGrpc.getRewrapMethod = getRewrapMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.kas.RewrapRequest, io.opentdf.platform.kas.RewrapResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Rewrap"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kas.RewrapRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kas.RewrapResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AccessServiceMethodDescriptorSupplier("Rewrap"))
              .build();
        }
      }
    }
    return getRewrapMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static AccessServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<AccessServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<AccessServiceStub>() {
        @java.lang.Override
        public AccessServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new AccessServiceStub(channel, callOptions);
        }
      };
    return AccessServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static AccessServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<AccessServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<AccessServiceBlockingStub>() {
        @java.lang.Override
        public AccessServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new AccessServiceBlockingStub(channel, callOptions);
        }
      };
    return AccessServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static AccessServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<AccessServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<AccessServiceFutureStub>() {
        @java.lang.Override
        public AccessServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new AccessServiceFutureStub(channel, callOptions);
        }
      };
    return AccessServiceFutureStub.newStub(factory, channel);
  }

  /**
   * <pre>
   * Get app info from the root path
   * </pre>
   */
  public interface AsyncService {

    /**
     * <pre>
     * Get the current version of the service
     * </pre>
     */
    default void info(io.opentdf.platform.kas.InfoRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kas.InfoResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getInfoMethod(), responseObserver);
    }

    /**
     */
    default void publicKey(io.opentdf.platform.kas.PublicKeyRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kas.PublicKeyResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getPublicKeyMethod(), responseObserver);
    }

    /**
     * <pre>
     * buf:lint:ignore RPC_RESPONSE_STANDARD_NAME
     * </pre>
     */
    default void legacyPublicKey(io.opentdf.platform.kas.LegacyPublicKeyRequest request,
        io.grpc.stub.StreamObserver<com.google.protobuf.StringValue> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getLegacyPublicKeyMethod(), responseObserver);
    }

    /**
     */
    default void rewrap(io.opentdf.platform.kas.RewrapRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kas.RewrapResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getRewrapMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service AccessService.
   * <pre>
   * Get app info from the root path
   * </pre>
   */
  public static abstract class AccessServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return AccessServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service AccessService.
   * <pre>
   * Get app info from the root path
   * </pre>
   */
  public static final class AccessServiceStub
      extends io.grpc.stub.AbstractAsyncStub<AccessServiceStub> {
    private AccessServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AccessServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new AccessServiceStub(channel, callOptions);
    }

    /**
     * <pre>
     * Get the current version of the service
     * </pre>
     */
    public void info(io.opentdf.platform.kas.InfoRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kas.InfoResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getInfoMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void publicKey(io.opentdf.platform.kas.PublicKeyRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kas.PublicKeyResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getPublicKeyMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * buf:lint:ignore RPC_RESPONSE_STANDARD_NAME
     * </pre>
     */
    public void legacyPublicKey(io.opentdf.platform.kas.LegacyPublicKeyRequest request,
        io.grpc.stub.StreamObserver<com.google.protobuf.StringValue> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getLegacyPublicKeyMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void rewrap(io.opentdf.platform.kas.RewrapRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kas.RewrapResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getRewrapMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service AccessService.
   * <pre>
   * Get app info from the root path
   * </pre>
   */
  public static final class AccessServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<AccessServiceBlockingStub> {
    private AccessServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AccessServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new AccessServiceBlockingStub(channel, callOptions);
    }

    /**
     * <pre>
     * Get the current version of the service
     * </pre>
     */
    public io.opentdf.platform.kas.InfoResponse info(io.opentdf.platform.kas.InfoRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getInfoMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.kas.PublicKeyResponse publicKey(io.opentdf.platform.kas.PublicKeyRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getPublicKeyMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * buf:lint:ignore RPC_RESPONSE_STANDARD_NAME
     * </pre>
     */
    public com.google.protobuf.StringValue legacyPublicKey(io.opentdf.platform.kas.LegacyPublicKeyRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getLegacyPublicKeyMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.kas.RewrapResponse rewrap(io.opentdf.platform.kas.RewrapRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getRewrapMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service AccessService.
   * <pre>
   * Get app info from the root path
   * </pre>
   */
  public static final class AccessServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<AccessServiceFutureStub> {
    private AccessServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AccessServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new AccessServiceFutureStub(channel, callOptions);
    }

    /**
     * <pre>
     * Get the current version of the service
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.kas.InfoResponse> info(
        io.opentdf.platform.kas.InfoRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getInfoMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.kas.PublicKeyResponse> publicKey(
        io.opentdf.platform.kas.PublicKeyRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getPublicKeyMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * buf:lint:ignore RPC_RESPONSE_STANDARD_NAME
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.google.protobuf.StringValue> legacyPublicKey(
        io.opentdf.platform.kas.LegacyPublicKeyRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getLegacyPublicKeyMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.kas.RewrapResponse> rewrap(
        io.opentdf.platform.kas.RewrapRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getRewrapMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_INFO = 0;
  private static final int METHODID_PUBLIC_KEY = 1;
  private static final int METHODID_LEGACY_PUBLIC_KEY = 2;
  private static final int METHODID_REWRAP = 3;

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
        case METHODID_INFO:
          serviceImpl.info((io.opentdf.platform.kas.InfoRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.kas.InfoResponse>) responseObserver);
          break;
        case METHODID_PUBLIC_KEY:
          serviceImpl.publicKey((io.opentdf.platform.kas.PublicKeyRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.kas.PublicKeyResponse>) responseObserver);
          break;
        case METHODID_LEGACY_PUBLIC_KEY:
          serviceImpl.legacyPublicKey((io.opentdf.platform.kas.LegacyPublicKeyRequest) request,
              (io.grpc.stub.StreamObserver<com.google.protobuf.StringValue>) responseObserver);
          break;
        case METHODID_REWRAP:
          serviceImpl.rewrap((io.opentdf.platform.kas.RewrapRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.kas.RewrapResponse>) responseObserver);
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
          getInfoMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.kas.InfoRequest,
              io.opentdf.platform.kas.InfoResponse>(
                service, METHODID_INFO)))
        .addMethod(
          getPublicKeyMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.kas.PublicKeyRequest,
              io.opentdf.platform.kas.PublicKeyResponse>(
                service, METHODID_PUBLIC_KEY)))
        .addMethod(
          getLegacyPublicKeyMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.kas.LegacyPublicKeyRequest,
              com.google.protobuf.StringValue>(
                service, METHODID_LEGACY_PUBLIC_KEY)))
        .addMethod(
          getRewrapMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.kas.RewrapRequest,
              io.opentdf.platform.kas.RewrapResponse>(
                service, METHODID_REWRAP)))
        .build();
  }

  private static abstract class AccessServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    AccessServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return io.opentdf.platform.kas.KasProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("AccessService");
    }
  }

  private static final class AccessServiceFileDescriptorSupplier
      extends AccessServiceBaseDescriptorSupplier {
    AccessServiceFileDescriptorSupplier() {}
  }

  private static final class AccessServiceMethodDescriptorSupplier
      extends AccessServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    AccessServiceMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (AccessServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new AccessServiceFileDescriptorSupplier())
              .addMethod(getInfoMethod())
              .addMethod(getPublicKeyMethod())
              .addMethod(getLegacyPublicKeyMethod())
              .addMethod(getRewrapMethod())
              .build();
        }
      }
    }
    return result;
  }
}
