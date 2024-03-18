package io.opentdf.platform.kasregistry;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: kasregistry/key_access_server_registry.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class KeyAccessServerRegistryServiceGrpc {

  private KeyAccessServerRegistryServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "kasregistry.KeyAccessServerRegistryService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.ListKeyAccessServersRequest,
      io.opentdf.platform.kasregistry.ListKeyAccessServersResponse> getListKeyAccessServersMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListKeyAccessServers",
      requestType = io.opentdf.platform.kasregistry.ListKeyAccessServersRequest.class,
      responseType = io.opentdf.platform.kasregistry.ListKeyAccessServersResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.ListKeyAccessServersRequest,
      io.opentdf.platform.kasregistry.ListKeyAccessServersResponse> getListKeyAccessServersMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.ListKeyAccessServersRequest, io.opentdf.platform.kasregistry.ListKeyAccessServersResponse> getListKeyAccessServersMethod;
    if ((getListKeyAccessServersMethod = KeyAccessServerRegistryServiceGrpc.getListKeyAccessServersMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getListKeyAccessServersMethod = KeyAccessServerRegistryServiceGrpc.getListKeyAccessServersMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getListKeyAccessServersMethod = getListKeyAccessServersMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.kasregistry.ListKeyAccessServersRequest, io.opentdf.platform.kasregistry.ListKeyAccessServersResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListKeyAccessServers"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.ListKeyAccessServersRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.ListKeyAccessServersResponse.getDefaultInstance()))
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceMethodDescriptorSupplier("ListKeyAccessServers"))
              .build();
        }
      }
    }
    return getListKeyAccessServersMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.GetKeyAccessServerRequest,
      io.opentdf.platform.kasregistry.GetKeyAccessServerResponse> getGetKeyAccessServerMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetKeyAccessServer",
      requestType = io.opentdf.platform.kasregistry.GetKeyAccessServerRequest.class,
      responseType = io.opentdf.platform.kasregistry.GetKeyAccessServerResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.GetKeyAccessServerRequest,
      io.opentdf.platform.kasregistry.GetKeyAccessServerResponse> getGetKeyAccessServerMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.GetKeyAccessServerRequest, io.opentdf.platform.kasregistry.GetKeyAccessServerResponse> getGetKeyAccessServerMethod;
    if ((getGetKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getGetKeyAccessServerMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getGetKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getGetKeyAccessServerMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getGetKeyAccessServerMethod = getGetKeyAccessServerMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.kasregistry.GetKeyAccessServerRequest, io.opentdf.platform.kasregistry.GetKeyAccessServerResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetKeyAccessServer"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.GetKeyAccessServerRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.GetKeyAccessServerResponse.getDefaultInstance()))
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceMethodDescriptorSupplier("GetKeyAccessServer"))
              .build();
        }
      }
    }
    return getGetKeyAccessServerMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest,
      io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse> getCreateKeyAccessServerMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateKeyAccessServer",
      requestType = io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest.class,
      responseType = io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest,
      io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse> getCreateKeyAccessServerMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest, io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse> getCreateKeyAccessServerMethod;
    if ((getCreateKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getCreateKeyAccessServerMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getCreateKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getCreateKeyAccessServerMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getCreateKeyAccessServerMethod = getCreateKeyAccessServerMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest, io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateKeyAccessServer"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse.getDefaultInstance()))
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceMethodDescriptorSupplier("CreateKeyAccessServer"))
              .build();
        }
      }
    }
    return getCreateKeyAccessServerMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest,
      io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse> getUpdateKeyAccessServerMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateKeyAccessServer",
      requestType = io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest.class,
      responseType = io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest,
      io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse> getUpdateKeyAccessServerMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest, io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse> getUpdateKeyAccessServerMethod;
    if ((getUpdateKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getUpdateKeyAccessServerMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getUpdateKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getUpdateKeyAccessServerMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getUpdateKeyAccessServerMethod = getUpdateKeyAccessServerMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest, io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateKeyAccessServer"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse.getDefaultInstance()))
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceMethodDescriptorSupplier("UpdateKeyAccessServer"))
              .build();
        }
      }
    }
    return getUpdateKeyAccessServerMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest,
      io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse> getDeleteKeyAccessServerMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeleteKeyAccessServer",
      requestType = io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest.class,
      responseType = io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest,
      io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse> getDeleteKeyAccessServerMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest, io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse> getDeleteKeyAccessServerMethod;
    if ((getDeleteKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getDeleteKeyAccessServerMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getDeleteKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getDeleteKeyAccessServerMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getDeleteKeyAccessServerMethod = getDeleteKeyAccessServerMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest, io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeleteKeyAccessServer"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse.getDefaultInstance()))
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceMethodDescriptorSupplier("DeleteKeyAccessServer"))
              .build();
        }
      }
    }
    return getDeleteKeyAccessServerMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static KeyAccessServerRegistryServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<KeyAccessServerRegistryServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<KeyAccessServerRegistryServiceStub>() {
        @java.lang.Override
        public KeyAccessServerRegistryServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new KeyAccessServerRegistryServiceStub(channel, callOptions);
        }
      };
    return KeyAccessServerRegistryServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static KeyAccessServerRegistryServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<KeyAccessServerRegistryServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<KeyAccessServerRegistryServiceBlockingStub>() {
        @java.lang.Override
        public KeyAccessServerRegistryServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new KeyAccessServerRegistryServiceBlockingStub(channel, callOptions);
        }
      };
    return KeyAccessServerRegistryServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static KeyAccessServerRegistryServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<KeyAccessServerRegistryServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<KeyAccessServerRegistryServiceFutureStub>() {
        @java.lang.Override
        public KeyAccessServerRegistryServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new KeyAccessServerRegistryServiceFutureStub(channel, callOptions);
        }
      };
    return KeyAccessServerRegistryServiceFutureStub.newStub(factory, channel);
  }

  /**
   */
  public interface AsyncService {

    /**
     */
    default void listKeyAccessServers(io.opentdf.platform.kasregistry.ListKeyAccessServersRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.ListKeyAccessServersResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListKeyAccessServersMethod(), responseObserver);
    }

    /**
     */
    default void getKeyAccessServer(io.opentdf.platform.kasregistry.GetKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.GetKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetKeyAccessServerMethod(), responseObserver);
    }

    /**
     */
    default void createKeyAccessServer(io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateKeyAccessServerMethod(), responseObserver);
    }

    /**
     */
    default void updateKeyAccessServer(io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateKeyAccessServerMethod(), responseObserver);
    }

    /**
     */
    default void deleteKeyAccessServer(io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeleteKeyAccessServerMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service KeyAccessServerRegistryService.
   */
  public static abstract class KeyAccessServerRegistryServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return KeyAccessServerRegistryServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service KeyAccessServerRegistryService.
   */
  public static final class KeyAccessServerRegistryServiceStub
      extends io.grpc.stub.AbstractAsyncStub<KeyAccessServerRegistryServiceStub> {
    private KeyAccessServerRegistryServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected KeyAccessServerRegistryServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new KeyAccessServerRegistryServiceStub(channel, callOptions);
    }

    /**
     */
    public void listKeyAccessServers(io.opentdf.platform.kasregistry.ListKeyAccessServersRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.ListKeyAccessServersResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListKeyAccessServersMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getKeyAccessServer(io.opentdf.platform.kasregistry.GetKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.GetKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetKeyAccessServerMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void createKeyAccessServer(io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateKeyAccessServerMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateKeyAccessServer(io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateKeyAccessServerMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deleteKeyAccessServer(io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeleteKeyAccessServerMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service KeyAccessServerRegistryService.
   */
  public static final class KeyAccessServerRegistryServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<KeyAccessServerRegistryServiceBlockingStub> {
    private KeyAccessServerRegistryServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected KeyAccessServerRegistryServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new KeyAccessServerRegistryServiceBlockingStub(channel, callOptions);
    }

    /**
     */
    public io.opentdf.platform.kasregistry.ListKeyAccessServersResponse listKeyAccessServers(io.opentdf.platform.kasregistry.ListKeyAccessServersRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListKeyAccessServersMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.kasregistry.GetKeyAccessServerResponse getKeyAccessServer(io.opentdf.platform.kasregistry.GetKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetKeyAccessServerMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse createKeyAccessServer(io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateKeyAccessServerMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse updateKeyAccessServer(io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateKeyAccessServerMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse deleteKeyAccessServer(io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeleteKeyAccessServerMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service KeyAccessServerRegistryService.
   */
  public static final class KeyAccessServerRegistryServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<KeyAccessServerRegistryServiceFutureStub> {
    private KeyAccessServerRegistryServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected KeyAccessServerRegistryServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new KeyAccessServerRegistryServiceFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.kasregistry.ListKeyAccessServersResponse> listKeyAccessServers(
        io.opentdf.platform.kasregistry.ListKeyAccessServersRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListKeyAccessServersMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.kasregistry.GetKeyAccessServerResponse> getKeyAccessServer(
        io.opentdf.platform.kasregistry.GetKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetKeyAccessServerMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse> createKeyAccessServer(
        io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateKeyAccessServerMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse> updateKeyAccessServer(
        io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateKeyAccessServerMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse> deleteKeyAccessServer(
        io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeleteKeyAccessServerMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_LIST_KEY_ACCESS_SERVERS = 0;
  private static final int METHODID_GET_KEY_ACCESS_SERVER = 1;
  private static final int METHODID_CREATE_KEY_ACCESS_SERVER = 2;
  private static final int METHODID_UPDATE_KEY_ACCESS_SERVER = 3;
  private static final int METHODID_DELETE_KEY_ACCESS_SERVER = 4;

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
        case METHODID_LIST_KEY_ACCESS_SERVERS:
          serviceImpl.listKeyAccessServers((io.opentdf.platform.kasregistry.ListKeyAccessServersRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.ListKeyAccessServersResponse>) responseObserver);
          break;
        case METHODID_GET_KEY_ACCESS_SERVER:
          serviceImpl.getKeyAccessServer((io.opentdf.platform.kasregistry.GetKeyAccessServerRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.GetKeyAccessServerResponse>) responseObserver);
          break;
        case METHODID_CREATE_KEY_ACCESS_SERVER:
          serviceImpl.createKeyAccessServer((io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse>) responseObserver);
          break;
        case METHODID_UPDATE_KEY_ACCESS_SERVER:
          serviceImpl.updateKeyAccessServer((io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse>) responseObserver);
          break;
        case METHODID_DELETE_KEY_ACCESS_SERVER:
          serviceImpl.deleteKeyAccessServer((io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse>) responseObserver);
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
          getListKeyAccessServersMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.kasregistry.ListKeyAccessServersRequest,
              io.opentdf.platform.kasregistry.ListKeyAccessServersResponse>(
                service, METHODID_LIST_KEY_ACCESS_SERVERS)))
        .addMethod(
          getGetKeyAccessServerMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.kasregistry.GetKeyAccessServerRequest,
              io.opentdf.platform.kasregistry.GetKeyAccessServerResponse>(
                service, METHODID_GET_KEY_ACCESS_SERVER)))
        .addMethod(
          getCreateKeyAccessServerMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest,
              io.opentdf.platform.kasregistry.CreateKeyAccessServerResponse>(
                service, METHODID_CREATE_KEY_ACCESS_SERVER)))
        .addMethod(
          getUpdateKeyAccessServerMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.kasregistry.UpdateKeyAccessServerRequest,
              io.opentdf.platform.kasregistry.UpdateKeyAccessServerResponse>(
                service, METHODID_UPDATE_KEY_ACCESS_SERVER)))
        .addMethod(
          getDeleteKeyAccessServerMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.kasregistry.DeleteKeyAccessServerRequest,
              io.opentdf.platform.kasregistry.DeleteKeyAccessServerResponse>(
                service, METHODID_DELETE_KEY_ACCESS_SERVER)))
        .build();
  }

  private static abstract class KeyAccessServerRegistryServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    KeyAccessServerRegistryServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("KeyAccessServerRegistryService");
    }
  }

  private static final class KeyAccessServerRegistryServiceFileDescriptorSupplier
      extends KeyAccessServerRegistryServiceBaseDescriptorSupplier {
    KeyAccessServerRegistryServiceFileDescriptorSupplier() {}
  }

  private static final class KeyAccessServerRegistryServiceMethodDescriptorSupplier
      extends KeyAccessServerRegistryServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    KeyAccessServerRegistryServiceMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceFileDescriptorSupplier())
              .addMethod(getListKeyAccessServersMethod())
              .addMethod(getGetKeyAccessServerMethod())
              .addMethod(getCreateKeyAccessServerMethod())
              .addMethod(getUpdateKeyAccessServerMethod())
              .addMethod(getDeleteKeyAccessServerMethod())
              .build();
        }
      }
    }
    return result;
  }
}
