package com.policy.resourcemapping;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 * <pre>
 *Resource Mappings
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: policy/resourcemapping/resource_mapping.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class ResourceMappingServiceGrpc {

  private ResourceMappingServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "policy.resourcemapping.ResourceMappingService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<com.policy.resourcemapping.ListResourceMappingsRequest,
      com.policy.resourcemapping.ListResourceMappingsResponse> getListResourceMappingsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListResourceMappings",
      requestType = com.policy.resourcemapping.ListResourceMappingsRequest.class,
      responseType = com.policy.resourcemapping.ListResourceMappingsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.resourcemapping.ListResourceMappingsRequest,
      com.policy.resourcemapping.ListResourceMappingsResponse> getListResourceMappingsMethod() {
    io.grpc.MethodDescriptor<com.policy.resourcemapping.ListResourceMappingsRequest, com.policy.resourcemapping.ListResourceMappingsResponse> getListResourceMappingsMethod;
    if ((getListResourceMappingsMethod = ResourceMappingServiceGrpc.getListResourceMappingsMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getListResourceMappingsMethod = ResourceMappingServiceGrpc.getListResourceMappingsMethod) == null) {
          ResourceMappingServiceGrpc.getListResourceMappingsMethod = getListResourceMappingsMethod =
              io.grpc.MethodDescriptor.<com.policy.resourcemapping.ListResourceMappingsRequest, com.policy.resourcemapping.ListResourceMappingsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListResourceMappings"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.ListResourceMappingsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.ListResourceMappingsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("ListResourceMappings"))
              .build();
        }
      }
    }
    return getListResourceMappingsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.resourcemapping.GetResourceMappingRequest,
      com.policy.resourcemapping.GetResourceMappingResponse> getGetResourceMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetResourceMapping",
      requestType = com.policy.resourcemapping.GetResourceMappingRequest.class,
      responseType = com.policy.resourcemapping.GetResourceMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.resourcemapping.GetResourceMappingRequest,
      com.policy.resourcemapping.GetResourceMappingResponse> getGetResourceMappingMethod() {
    io.grpc.MethodDescriptor<com.policy.resourcemapping.GetResourceMappingRequest, com.policy.resourcemapping.GetResourceMappingResponse> getGetResourceMappingMethod;
    if ((getGetResourceMappingMethod = ResourceMappingServiceGrpc.getGetResourceMappingMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getGetResourceMappingMethod = ResourceMappingServiceGrpc.getGetResourceMappingMethod) == null) {
          ResourceMappingServiceGrpc.getGetResourceMappingMethod = getGetResourceMappingMethod =
              io.grpc.MethodDescriptor.<com.policy.resourcemapping.GetResourceMappingRequest, com.policy.resourcemapping.GetResourceMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetResourceMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.GetResourceMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.GetResourceMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("GetResourceMapping"))
              .build();
        }
      }
    }
    return getGetResourceMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.resourcemapping.CreateResourceMappingRequest,
      com.policy.resourcemapping.CreateResourceMappingResponse> getCreateResourceMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateResourceMapping",
      requestType = com.policy.resourcemapping.CreateResourceMappingRequest.class,
      responseType = com.policy.resourcemapping.CreateResourceMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.resourcemapping.CreateResourceMappingRequest,
      com.policy.resourcemapping.CreateResourceMappingResponse> getCreateResourceMappingMethod() {
    io.grpc.MethodDescriptor<com.policy.resourcemapping.CreateResourceMappingRequest, com.policy.resourcemapping.CreateResourceMappingResponse> getCreateResourceMappingMethod;
    if ((getCreateResourceMappingMethod = ResourceMappingServiceGrpc.getCreateResourceMappingMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getCreateResourceMappingMethod = ResourceMappingServiceGrpc.getCreateResourceMappingMethod) == null) {
          ResourceMappingServiceGrpc.getCreateResourceMappingMethod = getCreateResourceMappingMethod =
              io.grpc.MethodDescriptor.<com.policy.resourcemapping.CreateResourceMappingRequest, com.policy.resourcemapping.CreateResourceMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateResourceMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.CreateResourceMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.CreateResourceMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("CreateResourceMapping"))
              .build();
        }
      }
    }
    return getCreateResourceMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.resourcemapping.UpdateResourceMappingRequest,
      com.policy.resourcemapping.UpdateResourceMappingResponse> getUpdateResourceMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateResourceMapping",
      requestType = com.policy.resourcemapping.UpdateResourceMappingRequest.class,
      responseType = com.policy.resourcemapping.UpdateResourceMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.resourcemapping.UpdateResourceMappingRequest,
      com.policy.resourcemapping.UpdateResourceMappingResponse> getUpdateResourceMappingMethod() {
    io.grpc.MethodDescriptor<com.policy.resourcemapping.UpdateResourceMappingRequest, com.policy.resourcemapping.UpdateResourceMappingResponse> getUpdateResourceMappingMethod;
    if ((getUpdateResourceMappingMethod = ResourceMappingServiceGrpc.getUpdateResourceMappingMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getUpdateResourceMappingMethod = ResourceMappingServiceGrpc.getUpdateResourceMappingMethod) == null) {
          ResourceMappingServiceGrpc.getUpdateResourceMappingMethod = getUpdateResourceMappingMethod =
              io.grpc.MethodDescriptor.<com.policy.resourcemapping.UpdateResourceMappingRequest, com.policy.resourcemapping.UpdateResourceMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateResourceMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.UpdateResourceMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.UpdateResourceMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("UpdateResourceMapping"))
              .build();
        }
      }
    }
    return getUpdateResourceMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.resourcemapping.DeleteResourceMappingRequest,
      com.policy.resourcemapping.DeleteResourceMappingResponse> getDeleteResourceMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeleteResourceMapping",
      requestType = com.policy.resourcemapping.DeleteResourceMappingRequest.class,
      responseType = com.policy.resourcemapping.DeleteResourceMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.resourcemapping.DeleteResourceMappingRequest,
      com.policy.resourcemapping.DeleteResourceMappingResponse> getDeleteResourceMappingMethod() {
    io.grpc.MethodDescriptor<com.policy.resourcemapping.DeleteResourceMappingRequest, com.policy.resourcemapping.DeleteResourceMappingResponse> getDeleteResourceMappingMethod;
    if ((getDeleteResourceMappingMethod = ResourceMappingServiceGrpc.getDeleteResourceMappingMethod) == null) {
      synchronized (ResourceMappingServiceGrpc.class) {
        if ((getDeleteResourceMappingMethod = ResourceMappingServiceGrpc.getDeleteResourceMappingMethod) == null) {
          ResourceMappingServiceGrpc.getDeleteResourceMappingMethod = getDeleteResourceMappingMethod =
              io.grpc.MethodDescriptor.<com.policy.resourcemapping.DeleteResourceMappingRequest, com.policy.resourcemapping.DeleteResourceMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeleteResourceMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.DeleteResourceMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.resourcemapping.DeleteResourceMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ResourceMappingServiceMethodDescriptorSupplier("DeleteResourceMapping"))
              .build();
        }
      }
    }
    return getDeleteResourceMappingMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static ResourceMappingServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceStub>() {
        @java.lang.Override
        public ResourceMappingServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new ResourceMappingServiceStub(channel, callOptions);
        }
      };
    return ResourceMappingServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static ResourceMappingServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceBlockingStub>() {
        @java.lang.Override
        public ResourceMappingServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new ResourceMappingServiceBlockingStub(channel, callOptions);
        }
      };
    return ResourceMappingServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static ResourceMappingServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<ResourceMappingServiceFutureStub>() {
        @java.lang.Override
        public ResourceMappingServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new ResourceMappingServiceFutureStub(channel, callOptions);
        }
      };
    return ResourceMappingServiceFutureStub.newStub(factory, channel);
  }

  /**
   * <pre>
   *Resource Mappings
   * </pre>
   */
  public interface AsyncService {

    /**
     * <pre>
     *Request Example:
     *- empty body
     *Response Example:
     *{
     *"resource_mappings": [
     *{
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *]
     *}
     * </pre>
     */
    default void listResourceMappings(com.policy.resourcemapping.ListResourceMappingsRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.ListResourceMappingsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListResourceMappingsMethod(), responseObserver);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    default void getResourceMapping(com.policy.resourcemapping.GetResourceMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.GetResourceMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetResourceMappingMethod(), responseObserver);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"resource_mapping": {
     *"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *]
     *}
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    default void createResourceMapping(com.policy.resourcemapping.CreateResourceMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.CreateResourceMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateResourceMappingMethod(), responseObserver);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"resource_mapping": {
     *"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *"NEWTERM"
     *]
     *}
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    default void updateResourceMapping(com.policy.resourcemapping.UpdateResourceMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.UpdateResourceMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateResourceMappingMethod(), responseObserver);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    default void deleteResourceMapping(com.policy.resourcemapping.DeleteResourceMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.DeleteResourceMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeleteResourceMappingMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service ResourceMappingService.
   * <pre>
   *Resource Mappings
   * </pre>
   */
  public static abstract class ResourceMappingServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return ResourceMappingServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service ResourceMappingService.
   * <pre>
   *Resource Mappings
   * </pre>
   */
  public static final class ResourceMappingServiceStub
      extends io.grpc.stub.AbstractAsyncStub<ResourceMappingServiceStub> {
    private ResourceMappingServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ResourceMappingServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new ResourceMappingServiceStub(channel, callOptions);
    }

    /**
     * <pre>
     *Request Example:
     *- empty body
     *Response Example:
     *{
     *"resource_mappings": [
     *{
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *]
     *}
     * </pre>
     */
    public void listResourceMappings(com.policy.resourcemapping.ListResourceMappingsRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.ListResourceMappingsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListResourceMappingsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public void getResourceMapping(com.policy.resourcemapping.GetResourceMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.GetResourceMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetResourceMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"resource_mapping": {
     *"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *]
     *}
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public void createResourceMapping(com.policy.resourcemapping.CreateResourceMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.CreateResourceMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateResourceMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"resource_mapping": {
     *"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *"NEWTERM"
     *]
     *}
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public void updateResourceMapping(com.policy.resourcemapping.UpdateResourceMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.UpdateResourceMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateResourceMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public void deleteResourceMapping(com.policy.resourcemapping.DeleteResourceMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.resourcemapping.DeleteResourceMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeleteResourceMappingMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service ResourceMappingService.
   * <pre>
   *Resource Mappings
   * </pre>
   */
  public static final class ResourceMappingServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<ResourceMappingServiceBlockingStub> {
    private ResourceMappingServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ResourceMappingServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new ResourceMappingServiceBlockingStub(channel, callOptions);
    }

    /**
     * <pre>
     *Request Example:
     *- empty body
     *Response Example:
     *{
     *"resource_mappings": [
     *{
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *]
     *}
     * </pre>
     */
    public com.policy.resourcemapping.ListResourceMappingsResponse listResourceMappings(com.policy.resourcemapping.ListResourceMappingsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListResourceMappingsMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public com.policy.resourcemapping.GetResourceMappingResponse getResourceMapping(com.policy.resourcemapping.GetResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetResourceMappingMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"resource_mapping": {
     *"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *]
     *}
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public com.policy.resourcemapping.CreateResourceMappingResponse createResourceMapping(com.policy.resourcemapping.CreateResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateResourceMappingMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"resource_mapping": {
     *"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *"NEWTERM"
     *]
     *}
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public com.policy.resourcemapping.UpdateResourceMappingResponse updateResourceMapping(com.policy.resourcemapping.UpdateResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateResourceMappingMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public com.policy.resourcemapping.DeleteResourceMappingResponse deleteResourceMapping(com.policy.resourcemapping.DeleteResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeleteResourceMappingMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service ResourceMappingService.
   * <pre>
   *Resource Mappings
   * </pre>
   */
  public static final class ResourceMappingServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<ResourceMappingServiceFutureStub> {
    private ResourceMappingServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ResourceMappingServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new ResourceMappingServiceFutureStub(channel, callOptions);
    }

    /**
     * <pre>
     *Request Example:
     *- empty body
     *Response Example:
     *{
     *"resource_mappings": [
     *{
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *]
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.resourcemapping.ListResourceMappingsResponse> listResourceMappings(
        com.policy.resourcemapping.ListResourceMappingsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListResourceMappingsMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.resourcemapping.GetResourceMappingResponse> getResourceMapping(
        com.policy.resourcemapping.GetResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetResourceMappingMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"resource_mapping": {
     *"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *]
     *}
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.resourcemapping.CreateResourceMappingResponse> createResourceMapping(
        com.policy.resourcemapping.CreateResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateResourceMappingMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"resource_mapping": {
     *"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *"NEWTERM"
     *]
     *}
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.resourcemapping.UpdateResourceMappingResponse> updateResourceMapping(
        com.policy.resourcemapping.UpdateResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateResourceMappingMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Request Example:
     *{
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
     *}
     *Response Example:
     *{
     *"resource_mapping": {
     *"terms": [
     *"TOPSECRET",
     *"TS",
     *],
     *"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
     *"metadata": {
     *"labels": [],
     *"created_at": {
     *"seconds": "1706103276",
     *"nanos": 510718000
     *},
     *"updated_at": {
     *"seconds": "1706107873",
     *"nanos": 399786000
     *},
     *"description": ""
     *},
     *"attribute_value": {
     *"members": [],
     *"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
     *"metadata": null,
     *"attribute_id": "",
     *"value": "value1"
     *}
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.resourcemapping.DeleteResourceMappingResponse> deleteResourceMapping(
        com.policy.resourcemapping.DeleteResourceMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeleteResourceMappingMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_LIST_RESOURCE_MAPPINGS = 0;
  private static final int METHODID_GET_RESOURCE_MAPPING = 1;
  private static final int METHODID_CREATE_RESOURCE_MAPPING = 2;
  private static final int METHODID_UPDATE_RESOURCE_MAPPING = 3;
  private static final int METHODID_DELETE_RESOURCE_MAPPING = 4;

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
        case METHODID_LIST_RESOURCE_MAPPINGS:
          serviceImpl.listResourceMappings((com.policy.resourcemapping.ListResourceMappingsRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.resourcemapping.ListResourceMappingsResponse>) responseObserver);
          break;
        case METHODID_GET_RESOURCE_MAPPING:
          serviceImpl.getResourceMapping((com.policy.resourcemapping.GetResourceMappingRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.resourcemapping.GetResourceMappingResponse>) responseObserver);
          break;
        case METHODID_CREATE_RESOURCE_MAPPING:
          serviceImpl.createResourceMapping((com.policy.resourcemapping.CreateResourceMappingRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.resourcemapping.CreateResourceMappingResponse>) responseObserver);
          break;
        case METHODID_UPDATE_RESOURCE_MAPPING:
          serviceImpl.updateResourceMapping((com.policy.resourcemapping.UpdateResourceMappingRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.resourcemapping.UpdateResourceMappingResponse>) responseObserver);
          break;
        case METHODID_DELETE_RESOURCE_MAPPING:
          serviceImpl.deleteResourceMapping((com.policy.resourcemapping.DeleteResourceMappingRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.resourcemapping.DeleteResourceMappingResponse>) responseObserver);
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
          getListResourceMappingsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.resourcemapping.ListResourceMappingsRequest,
              com.policy.resourcemapping.ListResourceMappingsResponse>(
                service, METHODID_LIST_RESOURCE_MAPPINGS)))
        .addMethod(
          getGetResourceMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.resourcemapping.GetResourceMappingRequest,
              com.policy.resourcemapping.GetResourceMappingResponse>(
                service, METHODID_GET_RESOURCE_MAPPING)))
        .addMethod(
          getCreateResourceMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.resourcemapping.CreateResourceMappingRequest,
              com.policy.resourcemapping.CreateResourceMappingResponse>(
                service, METHODID_CREATE_RESOURCE_MAPPING)))
        .addMethod(
          getUpdateResourceMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.resourcemapping.UpdateResourceMappingRequest,
              com.policy.resourcemapping.UpdateResourceMappingResponse>(
                service, METHODID_UPDATE_RESOURCE_MAPPING)))
        .addMethod(
          getDeleteResourceMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.resourcemapping.DeleteResourceMappingRequest,
              com.policy.resourcemapping.DeleteResourceMappingResponse>(
                service, METHODID_DELETE_RESOURCE_MAPPING)))
        .build();
  }

  private static abstract class ResourceMappingServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    ResourceMappingServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return com.policy.resourcemapping.ResourceMappingProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("ResourceMappingService");
    }
  }

  private static final class ResourceMappingServiceFileDescriptorSupplier
      extends ResourceMappingServiceBaseDescriptorSupplier {
    ResourceMappingServiceFileDescriptorSupplier() {}
  }

  private static final class ResourceMappingServiceMethodDescriptorSupplier
      extends ResourceMappingServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    ResourceMappingServiceMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (ResourceMappingServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new ResourceMappingServiceFileDescriptorSupplier())
              .addMethod(getListResourceMappingsMethod())
              .addMethod(getGetResourceMappingMethod())
              .addMethod(getCreateResourceMappingMethod())
              .addMethod(getUpdateResourceMappingMethod())
              .addMethod(getDeleteResourceMappingMethod())
              .build();
        }
      }
    }
    return result;
  }
}
