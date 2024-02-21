package com.kasregistry;

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
  private static volatile io.grpc.MethodDescriptor<com.kasregistry.ListKeyAccessServersRequest,
      com.kasregistry.ListKeyAccessServersResponse> getListKeyAccessServersMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListKeyAccessServers",
      requestType = com.kasregistry.ListKeyAccessServersRequest.class,
      responseType = com.kasregistry.ListKeyAccessServersResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.kasregistry.ListKeyAccessServersRequest,
      com.kasregistry.ListKeyAccessServersResponse> getListKeyAccessServersMethod() {
    io.grpc.MethodDescriptor<com.kasregistry.ListKeyAccessServersRequest, com.kasregistry.ListKeyAccessServersResponse> getListKeyAccessServersMethod;
    if ((getListKeyAccessServersMethod = KeyAccessServerRegistryServiceGrpc.getListKeyAccessServersMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getListKeyAccessServersMethod = KeyAccessServerRegistryServiceGrpc.getListKeyAccessServersMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getListKeyAccessServersMethod = getListKeyAccessServersMethod =
              io.grpc.MethodDescriptor.<com.kasregistry.ListKeyAccessServersRequest, com.kasregistry.ListKeyAccessServersResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListKeyAccessServers"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.ListKeyAccessServersRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.ListKeyAccessServersResponse.getDefaultInstance()))
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceMethodDescriptorSupplier("ListKeyAccessServers"))
              .build();
        }
      }
    }
    return getListKeyAccessServersMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.kasregistry.GetKeyAccessServerRequest,
      com.kasregistry.GetKeyAccessServerResponse> getGetKeyAccessServerMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetKeyAccessServer",
      requestType = com.kasregistry.GetKeyAccessServerRequest.class,
      responseType = com.kasregistry.GetKeyAccessServerResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.kasregistry.GetKeyAccessServerRequest,
      com.kasregistry.GetKeyAccessServerResponse> getGetKeyAccessServerMethod() {
    io.grpc.MethodDescriptor<com.kasregistry.GetKeyAccessServerRequest, com.kasregistry.GetKeyAccessServerResponse> getGetKeyAccessServerMethod;
    if ((getGetKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getGetKeyAccessServerMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getGetKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getGetKeyAccessServerMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getGetKeyAccessServerMethod = getGetKeyAccessServerMethod =
              io.grpc.MethodDescriptor.<com.kasregistry.GetKeyAccessServerRequest, com.kasregistry.GetKeyAccessServerResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetKeyAccessServer"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.GetKeyAccessServerRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.GetKeyAccessServerResponse.getDefaultInstance()))
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceMethodDescriptorSupplier("GetKeyAccessServer"))
              .build();
        }
      }
    }
    return getGetKeyAccessServerMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.kasregistry.CreateKeyAccessServerRequest,
      com.kasregistry.CreateKeyAccessServerResponse> getCreateKeyAccessServerMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateKeyAccessServer",
      requestType = com.kasregistry.CreateKeyAccessServerRequest.class,
      responseType = com.kasregistry.CreateKeyAccessServerResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.kasregistry.CreateKeyAccessServerRequest,
      com.kasregistry.CreateKeyAccessServerResponse> getCreateKeyAccessServerMethod() {
    io.grpc.MethodDescriptor<com.kasregistry.CreateKeyAccessServerRequest, com.kasregistry.CreateKeyAccessServerResponse> getCreateKeyAccessServerMethod;
    if ((getCreateKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getCreateKeyAccessServerMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getCreateKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getCreateKeyAccessServerMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getCreateKeyAccessServerMethod = getCreateKeyAccessServerMethod =
              io.grpc.MethodDescriptor.<com.kasregistry.CreateKeyAccessServerRequest, com.kasregistry.CreateKeyAccessServerResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateKeyAccessServer"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.CreateKeyAccessServerRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.CreateKeyAccessServerResponse.getDefaultInstance()))
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceMethodDescriptorSupplier("CreateKeyAccessServer"))
              .build();
        }
      }
    }
    return getCreateKeyAccessServerMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.kasregistry.UpdateKeyAccessServerRequest,
      com.kasregistry.UpdateKeyAccessServerResponse> getUpdateKeyAccessServerMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateKeyAccessServer",
      requestType = com.kasregistry.UpdateKeyAccessServerRequest.class,
      responseType = com.kasregistry.UpdateKeyAccessServerResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.kasregistry.UpdateKeyAccessServerRequest,
      com.kasregistry.UpdateKeyAccessServerResponse> getUpdateKeyAccessServerMethod() {
    io.grpc.MethodDescriptor<com.kasregistry.UpdateKeyAccessServerRequest, com.kasregistry.UpdateKeyAccessServerResponse> getUpdateKeyAccessServerMethod;
    if ((getUpdateKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getUpdateKeyAccessServerMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getUpdateKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getUpdateKeyAccessServerMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getUpdateKeyAccessServerMethod = getUpdateKeyAccessServerMethod =
              io.grpc.MethodDescriptor.<com.kasregistry.UpdateKeyAccessServerRequest, com.kasregistry.UpdateKeyAccessServerResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateKeyAccessServer"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.UpdateKeyAccessServerRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.UpdateKeyAccessServerResponse.getDefaultInstance()))
              .setSchemaDescriptor(new KeyAccessServerRegistryServiceMethodDescriptorSupplier("UpdateKeyAccessServer"))
              .build();
        }
      }
    }
    return getUpdateKeyAccessServerMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.kasregistry.DeleteKeyAccessServerRequest,
      com.kasregistry.DeleteKeyAccessServerResponse> getDeleteKeyAccessServerMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeleteKeyAccessServer",
      requestType = com.kasregistry.DeleteKeyAccessServerRequest.class,
      responseType = com.kasregistry.DeleteKeyAccessServerResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.kasregistry.DeleteKeyAccessServerRequest,
      com.kasregistry.DeleteKeyAccessServerResponse> getDeleteKeyAccessServerMethod() {
    io.grpc.MethodDescriptor<com.kasregistry.DeleteKeyAccessServerRequest, com.kasregistry.DeleteKeyAccessServerResponse> getDeleteKeyAccessServerMethod;
    if ((getDeleteKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getDeleteKeyAccessServerMethod) == null) {
      synchronized (KeyAccessServerRegistryServiceGrpc.class) {
        if ((getDeleteKeyAccessServerMethod = KeyAccessServerRegistryServiceGrpc.getDeleteKeyAccessServerMethod) == null) {
          KeyAccessServerRegistryServiceGrpc.getDeleteKeyAccessServerMethod = getDeleteKeyAccessServerMethod =
              io.grpc.MethodDescriptor.<com.kasregistry.DeleteKeyAccessServerRequest, com.kasregistry.DeleteKeyAccessServerResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeleteKeyAccessServer"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.DeleteKeyAccessServerRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.kasregistry.DeleteKeyAccessServerResponse.getDefaultInstance()))
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
     * <pre>
     *Request Examples:
     *{}
     *Response Examples:
     *{
     *"key_access_servers": [
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *},
     *{
     *"id": "cad1fc87-1193-456b-a217-d5cdae1fa67a",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971990",
     *"nanos": 303386000
     *},
     *"updated_at": {
     *"seconds": "1705971990",
     *"nanos": 303386000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas3",
     *"public_key": {
     *"local": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ6ekNDQVhXZ0F3SUJBZ0lVT1J1VjNhdlU5QUU2enNCNlp4eWxsSHBpNWQ0d0NnWUlLb1pJemowRUF3SXcKUFRFTE1Ba0dBMVVFQmhNQ2RYTXhDekFKQmdOVkJBZ01BbU4wTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWAphV1JuYVhSeklGQjBlU0JNZEdRd0hoY05NalF3TVRBeU1UWTFOalUyV2hjTk1qVXdNVEF4TVRZMU5qVTJXakE5Ck1Rc3dDUVlEVlFRR0V3SjFjekVMTUFrR0ExVUVDQXdDWTNReElUQWZCZ05WQkFvTUdFbHVkR1Z5Ym1WMElGZHAKWkdkcGRITWdVSFI1SUV4MFpEQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJMVjlmQ0pIRC9rYwpyWHJVSFF3QVp4ME1jMGRQdkxqc0ovb2pFdE1NbjBST2RlT3g4eWd4Z2NRVEZGQXh5Q3RCdWFkaEFkbS9pVkh0CjhnMkVNejVkTzNXalV6QlJNQjBHQTFVZERnUVdCQlFZTmt1aytKSXVSV3luK2JFOHNCaFJ3MjdPVlRBZkJnTlYKSFNNRUdEQVdnQlFZTmt1aytKSXVSV3luK2JFOHNCaFJ3MjdPVlRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvRwpDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ0FCMmppWWU4QVk2TUo0QURQU1FHRTQ3K2Eza1dGTGNHc0pob1pieHRnClV3SWdjZklJdVBmaDRmYmN2OGNUaTJCbEkzazdzV1B1QW1JRlZyaUkyZDNVeDVRPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
     *}
     *}
     *]
     *}
     * </pre>
     */
    default void listKeyAccessServers(com.kasregistry.ListKeyAccessServersRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.ListKeyAccessServersResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListKeyAccessServersMethod(), responseObserver);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732"
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    default void getKeyAccessServer(com.kasregistry.GetKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.GetKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetKeyAccessServerMethod(), responseObserver);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"key_access_server": {
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    default void createKeyAccessServer(com.kasregistry.CreateKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.CreateKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateKeyAccessServerMethod(), responseObserver);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"key_access_server": {
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    default void updateKeyAccessServer(com.kasregistry.UpdateKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.UpdateKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateKeyAccessServerMethod(), responseObserver);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732"
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    default void deleteKeyAccessServer(com.kasregistry.DeleteKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.DeleteKeyAccessServerResponse> responseObserver) {
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
     * <pre>
     *Request Examples:
     *{}
     *Response Examples:
     *{
     *"key_access_servers": [
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *},
     *{
     *"id": "cad1fc87-1193-456b-a217-d5cdae1fa67a",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971990",
     *"nanos": 303386000
     *},
     *"updated_at": {
     *"seconds": "1705971990",
     *"nanos": 303386000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas3",
     *"public_key": {
     *"local": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ6ekNDQVhXZ0F3SUJBZ0lVT1J1VjNhdlU5QUU2enNCNlp4eWxsSHBpNWQ0d0NnWUlLb1pJemowRUF3SXcKUFRFTE1Ba0dBMVVFQmhNQ2RYTXhDekFKQmdOVkJBZ01BbU4wTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWAphV1JuYVhSeklGQjBlU0JNZEdRd0hoY05NalF3TVRBeU1UWTFOalUyV2hjTk1qVXdNVEF4TVRZMU5qVTJXakE5Ck1Rc3dDUVlEVlFRR0V3SjFjekVMTUFrR0ExVUVDQXdDWTNReElUQWZCZ05WQkFvTUdFbHVkR1Z5Ym1WMElGZHAKWkdkcGRITWdVSFI1SUV4MFpEQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJMVjlmQ0pIRC9rYwpyWHJVSFF3QVp4ME1jMGRQdkxqc0ovb2pFdE1NbjBST2RlT3g4eWd4Z2NRVEZGQXh5Q3RCdWFkaEFkbS9pVkh0CjhnMkVNejVkTzNXalV6QlJNQjBHQTFVZERnUVdCQlFZTmt1aytKSXVSV3luK2JFOHNCaFJ3MjdPVlRBZkJnTlYKSFNNRUdEQVdnQlFZTmt1aytKSXVSV3luK2JFOHNCaFJ3MjdPVlRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvRwpDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ0FCMmppWWU4QVk2TUo0QURQU1FHRTQ3K2Eza1dGTGNHc0pob1pieHRnClV3SWdjZklJdVBmaDRmYmN2OGNUaTJCbEkzazdzV1B1QW1JRlZyaUkyZDNVeDVRPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
     *}
     *}
     *]
     *}
     * </pre>
     */
    public void listKeyAccessServers(com.kasregistry.ListKeyAccessServersRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.ListKeyAccessServersResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListKeyAccessServersMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732"
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public void getKeyAccessServer(com.kasregistry.GetKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.GetKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetKeyAccessServerMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"key_access_server": {
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public void createKeyAccessServer(com.kasregistry.CreateKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.CreateKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateKeyAccessServerMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"key_access_server": {
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public void updateKeyAccessServer(com.kasregistry.UpdateKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.UpdateKeyAccessServerResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateKeyAccessServerMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732"
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public void deleteKeyAccessServer(com.kasregistry.DeleteKeyAccessServerRequest request,
        io.grpc.stub.StreamObserver<com.kasregistry.DeleteKeyAccessServerResponse> responseObserver) {
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
     * <pre>
     *Request Examples:
     *{}
     *Response Examples:
     *{
     *"key_access_servers": [
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *},
     *{
     *"id": "cad1fc87-1193-456b-a217-d5cdae1fa67a",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971990",
     *"nanos": 303386000
     *},
     *"updated_at": {
     *"seconds": "1705971990",
     *"nanos": 303386000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas3",
     *"public_key": {
     *"local": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ6ekNDQVhXZ0F3SUJBZ0lVT1J1VjNhdlU5QUU2enNCNlp4eWxsSHBpNWQ0d0NnWUlLb1pJemowRUF3SXcKUFRFTE1Ba0dBMVVFQmhNQ2RYTXhDekFKQmdOVkJBZ01BbU4wTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWAphV1JuYVhSeklGQjBlU0JNZEdRd0hoY05NalF3TVRBeU1UWTFOalUyV2hjTk1qVXdNVEF4TVRZMU5qVTJXakE5Ck1Rc3dDUVlEVlFRR0V3SjFjekVMTUFrR0ExVUVDQXdDWTNReElUQWZCZ05WQkFvTUdFbHVkR1Z5Ym1WMElGZHAKWkdkcGRITWdVSFI1SUV4MFpEQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJMVjlmQ0pIRC9rYwpyWHJVSFF3QVp4ME1jMGRQdkxqc0ovb2pFdE1NbjBST2RlT3g4eWd4Z2NRVEZGQXh5Q3RCdWFkaEFkbS9pVkh0CjhnMkVNejVkTzNXalV6QlJNQjBHQTFVZERnUVdCQlFZTmt1aytKSXVSV3luK2JFOHNCaFJ3MjdPVlRBZkJnTlYKSFNNRUdEQVdnQlFZTmt1aytKSXVSV3luK2JFOHNCaFJ3MjdPVlRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvRwpDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ0FCMmppWWU4QVk2TUo0QURQU1FHRTQ3K2Eza1dGTGNHc0pob1pieHRnClV3SWdjZklJdVBmaDRmYmN2OGNUaTJCbEkzazdzV1B1QW1JRlZyaUkyZDNVeDVRPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
     *}
     *}
     *]
     *}
     * </pre>
     */
    public com.kasregistry.ListKeyAccessServersResponse listKeyAccessServers(com.kasregistry.ListKeyAccessServersRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListKeyAccessServersMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732"
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public com.kasregistry.GetKeyAccessServerResponse getKeyAccessServer(com.kasregistry.GetKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetKeyAccessServerMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"key_access_server": {
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public com.kasregistry.CreateKeyAccessServerResponse createKeyAccessServer(com.kasregistry.CreateKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateKeyAccessServerMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"key_access_server": {
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public com.kasregistry.UpdateKeyAccessServerResponse updateKeyAccessServer(com.kasregistry.UpdateKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateKeyAccessServerMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732"
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public com.kasregistry.DeleteKeyAccessServerResponse deleteKeyAccessServer(com.kasregistry.DeleteKeyAccessServerRequest request) {
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
     * <pre>
     *Request Examples:
     *{}
     *Response Examples:
     *{
     *"key_access_servers": [
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *},
     *{
     *"id": "cad1fc87-1193-456b-a217-d5cdae1fa67a",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971990",
     *"nanos": 303386000
     *},
     *"updated_at": {
     *"seconds": "1705971990",
     *"nanos": 303386000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas3",
     *"public_key": {
     *"local": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ6ekNDQVhXZ0F3SUJBZ0lVT1J1VjNhdlU5QUU2enNCNlp4eWxsSHBpNWQ0d0NnWUlLb1pJemowRUF3SXcKUFRFTE1Ba0dBMVVFQmhNQ2RYTXhDekFKQmdOVkJBZ01BbU4wTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWAphV1JuYVhSeklGQjBlU0JNZEdRd0hoY05NalF3TVRBeU1UWTFOalUyV2hjTk1qVXdNVEF4TVRZMU5qVTJXakE5Ck1Rc3dDUVlEVlFRR0V3SjFjekVMTUFrR0ExVUVDQXdDWTNReElUQWZCZ05WQkFvTUdFbHVkR1Z5Ym1WMElGZHAKWkdkcGRITWdVSFI1SUV4MFpEQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJMVjlmQ0pIRC9rYwpyWHJVSFF3QVp4ME1jMGRQdkxqc0ovb2pFdE1NbjBST2RlT3g4eWd4Z2NRVEZGQXh5Q3RCdWFkaEFkbS9pVkh0CjhnMkVNejVkTzNXalV6QlJNQjBHQTFVZERnUVdCQlFZTmt1aytKSXVSV3luK2JFOHNCaFJ3MjdPVlRBZkJnTlYKSFNNRUdEQVdnQlFZTmt1aytKSXVSV3luK2JFOHNCaFJ3MjdPVlRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvRwpDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ0FCMmppWWU4QVk2TUo0QURQU1FHRTQ3K2Eza1dGTGNHc0pob1pieHRnClV3SWdjZklJdVBmaDRmYmN2OGNUaTJCbEkzazdzV1B1QW1JRlZyaUkyZDNVeDVRPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
     *}
     *}
     *]
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.kasregistry.ListKeyAccessServersResponse> listKeyAccessServers(
        com.kasregistry.ListKeyAccessServersRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListKeyAccessServersMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732"
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.kasregistry.GetKeyAccessServerResponse> getKeyAccessServer(
        com.kasregistry.GetKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetKeyAccessServerMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"key_access_server": {
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.kasregistry.CreateKeyAccessServerResponse> createKeyAccessServer(
        com.kasregistry.CreateKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateKeyAccessServerMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"key_access_server": {
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.kasregistry.UpdateKeyAccessServerResponse> updateKeyAccessServer(
        com.kasregistry.UpdateKeyAccessServerRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateKeyAccessServerMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Request Examples:
     *{
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732"
     *}
     *Response Examples:
     *{
     *"key_access_server": {
     *"id": "71eae02f-6837-4980-8a2c-70abf6b68732",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"updated_at": {
     *"seconds": "1705971719",
     *"nanos": 534029000
     *},
     *"description": "test kas instance"
     *},
     *"uri": "kas2",
     *"public_key": {
     *"remote": "https://platform.virtru.com/kas1"
     *}
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.kasregistry.DeleteKeyAccessServerResponse> deleteKeyAccessServer(
        com.kasregistry.DeleteKeyAccessServerRequest request) {
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
          serviceImpl.listKeyAccessServers((com.kasregistry.ListKeyAccessServersRequest) request,
              (io.grpc.stub.StreamObserver<com.kasregistry.ListKeyAccessServersResponse>) responseObserver);
          break;
        case METHODID_GET_KEY_ACCESS_SERVER:
          serviceImpl.getKeyAccessServer((com.kasregistry.GetKeyAccessServerRequest) request,
              (io.grpc.stub.StreamObserver<com.kasregistry.GetKeyAccessServerResponse>) responseObserver);
          break;
        case METHODID_CREATE_KEY_ACCESS_SERVER:
          serviceImpl.createKeyAccessServer((com.kasregistry.CreateKeyAccessServerRequest) request,
              (io.grpc.stub.StreamObserver<com.kasregistry.CreateKeyAccessServerResponse>) responseObserver);
          break;
        case METHODID_UPDATE_KEY_ACCESS_SERVER:
          serviceImpl.updateKeyAccessServer((com.kasregistry.UpdateKeyAccessServerRequest) request,
              (io.grpc.stub.StreamObserver<com.kasregistry.UpdateKeyAccessServerResponse>) responseObserver);
          break;
        case METHODID_DELETE_KEY_ACCESS_SERVER:
          serviceImpl.deleteKeyAccessServer((com.kasregistry.DeleteKeyAccessServerRequest) request,
              (io.grpc.stub.StreamObserver<com.kasregistry.DeleteKeyAccessServerResponse>) responseObserver);
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
              com.kasregistry.ListKeyAccessServersRequest,
              com.kasregistry.ListKeyAccessServersResponse>(
                service, METHODID_LIST_KEY_ACCESS_SERVERS)))
        .addMethod(
          getGetKeyAccessServerMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.kasregistry.GetKeyAccessServerRequest,
              com.kasregistry.GetKeyAccessServerResponse>(
                service, METHODID_GET_KEY_ACCESS_SERVER)))
        .addMethod(
          getCreateKeyAccessServerMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.kasregistry.CreateKeyAccessServerRequest,
              com.kasregistry.CreateKeyAccessServerResponse>(
                service, METHODID_CREATE_KEY_ACCESS_SERVER)))
        .addMethod(
          getUpdateKeyAccessServerMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.kasregistry.UpdateKeyAccessServerRequest,
              com.kasregistry.UpdateKeyAccessServerResponse>(
                service, METHODID_UPDATE_KEY_ACCESS_SERVER)))
        .addMethod(
          getDeleteKeyAccessServerMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.kasregistry.DeleteKeyAccessServerRequest,
              com.kasregistry.DeleteKeyAccessServerResponse>(
                service, METHODID_DELETE_KEY_ACCESS_SERVER)))
        .build();
  }

  private static abstract class KeyAccessServerRegistryServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    KeyAccessServerRegistryServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return com.kasregistry.KeyAccessServerRegistryProto.getDescriptor();
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
