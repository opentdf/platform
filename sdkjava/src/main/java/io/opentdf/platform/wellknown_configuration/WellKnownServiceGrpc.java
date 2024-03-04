package io.opentdf.platform.wellknown_configuration;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: wellknownConfiguration/wellknownConfiguration.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class WellKnownServiceGrpc {

  private WellKnownServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "wellknown_configuration.WellKnownService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.wellknown_configuration.WellKnownConfig,
      com.google.protobuf.Struct> getGetWellKnownConfigurationMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetWellKnownConfiguration",
      requestType = io.opentdf.platform.wellknown_configuration.WellKnownConfig.class,
      responseType = com.google.protobuf.Struct.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.wellknown_configuration.WellKnownConfig,
      com.google.protobuf.Struct> getGetWellKnownConfigurationMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.wellknown_configuration.WellKnownConfig, com.google.protobuf.Struct> getGetWellKnownConfigurationMethod;
    if ((getGetWellKnownConfigurationMethod = WellKnownServiceGrpc.getGetWellKnownConfigurationMethod) == null) {
      synchronized (WellKnownServiceGrpc.class) {
        if ((getGetWellKnownConfigurationMethod = WellKnownServiceGrpc.getGetWellKnownConfigurationMethod) == null) {
          WellKnownServiceGrpc.getGetWellKnownConfigurationMethod = getGetWellKnownConfigurationMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.wellknown_configuration.WellKnownConfig, com.google.protobuf.Struct>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetWellKnownConfiguration"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.wellknown_configuration.WellKnownConfig.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.google.protobuf.Struct.getDefaultInstance()))
              .setSchemaDescriptor(new WellKnownServiceMethodDescriptorSupplier("GetWellKnownConfiguration"))
              .build();
        }
      }
    }
    return getGetWellKnownConfigurationMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static WellKnownServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<WellKnownServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<WellKnownServiceStub>() {
        @java.lang.Override
        public WellKnownServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new WellKnownServiceStub(channel, callOptions);
        }
      };
    return WellKnownServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static WellKnownServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<WellKnownServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<WellKnownServiceBlockingStub>() {
        @java.lang.Override
        public WellKnownServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new WellKnownServiceBlockingStub(channel, callOptions);
        }
      };
    return WellKnownServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static WellKnownServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<WellKnownServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<WellKnownServiceFutureStub>() {
        @java.lang.Override
        public WellKnownServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new WellKnownServiceFutureStub(channel, callOptions);
        }
      };
    return WellKnownServiceFutureStub.newStub(factory, channel);
  }

  /**
   */
  public interface AsyncService {

    /**
     */
    default void getWellKnownConfiguration(io.opentdf.platform.wellknown_configuration.WellKnownConfig request,
        io.grpc.stub.StreamObserver<com.google.protobuf.Struct> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetWellKnownConfigurationMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service WellKnownService.
   */
  public static abstract class WellKnownServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return WellKnownServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service WellKnownService.
   */
  public static final class WellKnownServiceStub
      extends io.grpc.stub.AbstractAsyncStub<WellKnownServiceStub> {
    private WellKnownServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected WellKnownServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new WellKnownServiceStub(channel, callOptions);
    }

    /**
     */
    public void getWellKnownConfiguration(io.opentdf.platform.wellknown_configuration.WellKnownConfig request,
        io.grpc.stub.StreamObserver<com.google.protobuf.Struct> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetWellKnownConfigurationMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service WellKnownService.
   */
  public static final class WellKnownServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<WellKnownServiceBlockingStub> {
    private WellKnownServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected WellKnownServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new WellKnownServiceBlockingStub(channel, callOptions);
    }

    /**
     */
    public com.google.protobuf.Struct getWellKnownConfiguration(io.opentdf.platform.wellknown_configuration.WellKnownConfig request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetWellKnownConfigurationMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service WellKnownService.
   */
  public static final class WellKnownServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<WellKnownServiceFutureStub> {
    private WellKnownServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected WellKnownServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new WellKnownServiceFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.google.protobuf.Struct> getWellKnownConfiguration(
        io.opentdf.platform.wellknown_configuration.WellKnownConfig request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetWellKnownConfigurationMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_GET_WELL_KNOWN_CONFIGURATION = 0;

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
        case METHODID_GET_WELL_KNOWN_CONFIGURATION:
          serviceImpl.getWellKnownConfiguration((io.opentdf.platform.wellknown_configuration.WellKnownConfig) request,
              (io.grpc.stub.StreamObserver<com.google.protobuf.Struct>) responseObserver);
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
          getGetWellKnownConfigurationMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.wellknown_configuration.WellKnownConfig,
              com.google.protobuf.Struct>(
                service, METHODID_GET_WELL_KNOWN_CONFIGURATION)))
        .build();
  }

  private static abstract class WellKnownServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    WellKnownServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return io.opentdf.platform.wellknown_configuration.WellknownConfigurationProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("WellKnownService");
    }
  }

  private static final class WellKnownServiceFileDescriptorSupplier
      extends WellKnownServiceBaseDescriptorSupplier {
    WellKnownServiceFileDescriptorSupplier() {}
  }

  private static final class WellKnownServiceMethodDescriptorSupplier
      extends WellKnownServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    WellKnownServiceMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (WellKnownServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new WellKnownServiceFileDescriptorSupplier())
              .addMethod(getGetWellKnownConfigurationMethod())
              .build();
        }
      }
    }
    return result;
  }
}
