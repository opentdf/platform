package com.policy.subjectmapping;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: policy/subjectmapping/subject_mapping.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class SubjectMappingServiceGrpc {

  private SubjectMappingServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "policy.subjectmapping.SubjectMappingService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<com.policy.subjectmapping.ListSubjectMappingsRequest,
      com.policy.subjectmapping.ListSubjectMappingsResponse> getListSubjectMappingsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListSubjectMappings",
      requestType = com.policy.subjectmapping.ListSubjectMappingsRequest.class,
      responseType = com.policy.subjectmapping.ListSubjectMappingsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.subjectmapping.ListSubjectMappingsRequest,
      com.policy.subjectmapping.ListSubjectMappingsResponse> getListSubjectMappingsMethod() {
    io.grpc.MethodDescriptor<com.policy.subjectmapping.ListSubjectMappingsRequest, com.policy.subjectmapping.ListSubjectMappingsResponse> getListSubjectMappingsMethod;
    if ((getListSubjectMappingsMethod = SubjectMappingServiceGrpc.getListSubjectMappingsMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getListSubjectMappingsMethod = SubjectMappingServiceGrpc.getListSubjectMappingsMethod) == null) {
          SubjectMappingServiceGrpc.getListSubjectMappingsMethod = getListSubjectMappingsMethod =
              io.grpc.MethodDescriptor.<com.policy.subjectmapping.ListSubjectMappingsRequest, com.policy.subjectmapping.ListSubjectMappingsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListSubjectMappings"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.ListSubjectMappingsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.ListSubjectMappingsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("ListSubjectMappings"))
              .build();
        }
      }
    }
    return getListSubjectMappingsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.subjectmapping.GetSubjectMappingRequest,
      com.policy.subjectmapping.GetSubjectMappingResponse> getGetSubjectMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetSubjectMapping",
      requestType = com.policy.subjectmapping.GetSubjectMappingRequest.class,
      responseType = com.policy.subjectmapping.GetSubjectMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.subjectmapping.GetSubjectMappingRequest,
      com.policy.subjectmapping.GetSubjectMappingResponse> getGetSubjectMappingMethod() {
    io.grpc.MethodDescriptor<com.policy.subjectmapping.GetSubjectMappingRequest, com.policy.subjectmapping.GetSubjectMappingResponse> getGetSubjectMappingMethod;
    if ((getGetSubjectMappingMethod = SubjectMappingServiceGrpc.getGetSubjectMappingMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getGetSubjectMappingMethod = SubjectMappingServiceGrpc.getGetSubjectMappingMethod) == null) {
          SubjectMappingServiceGrpc.getGetSubjectMappingMethod = getGetSubjectMappingMethod =
              io.grpc.MethodDescriptor.<com.policy.subjectmapping.GetSubjectMappingRequest, com.policy.subjectmapping.GetSubjectMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetSubjectMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.GetSubjectMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.GetSubjectMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("GetSubjectMapping"))
              .build();
        }
      }
    }
    return getGetSubjectMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.subjectmapping.CreateSubjectMappingRequest,
      com.policy.subjectmapping.CreateSubjectMappingResponse> getCreateSubjectMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateSubjectMapping",
      requestType = com.policy.subjectmapping.CreateSubjectMappingRequest.class,
      responseType = com.policy.subjectmapping.CreateSubjectMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.subjectmapping.CreateSubjectMappingRequest,
      com.policy.subjectmapping.CreateSubjectMappingResponse> getCreateSubjectMappingMethod() {
    io.grpc.MethodDescriptor<com.policy.subjectmapping.CreateSubjectMappingRequest, com.policy.subjectmapping.CreateSubjectMappingResponse> getCreateSubjectMappingMethod;
    if ((getCreateSubjectMappingMethod = SubjectMappingServiceGrpc.getCreateSubjectMappingMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getCreateSubjectMappingMethod = SubjectMappingServiceGrpc.getCreateSubjectMappingMethod) == null) {
          SubjectMappingServiceGrpc.getCreateSubjectMappingMethod = getCreateSubjectMappingMethod =
              io.grpc.MethodDescriptor.<com.policy.subjectmapping.CreateSubjectMappingRequest, com.policy.subjectmapping.CreateSubjectMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateSubjectMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.CreateSubjectMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.CreateSubjectMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("CreateSubjectMapping"))
              .build();
        }
      }
    }
    return getCreateSubjectMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.subjectmapping.UpdateSubjectMappingRequest,
      com.policy.subjectmapping.UpdateSubjectMappingResponse> getUpdateSubjectMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateSubjectMapping",
      requestType = com.policy.subjectmapping.UpdateSubjectMappingRequest.class,
      responseType = com.policy.subjectmapping.UpdateSubjectMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.subjectmapping.UpdateSubjectMappingRequest,
      com.policy.subjectmapping.UpdateSubjectMappingResponse> getUpdateSubjectMappingMethod() {
    io.grpc.MethodDescriptor<com.policy.subjectmapping.UpdateSubjectMappingRequest, com.policy.subjectmapping.UpdateSubjectMappingResponse> getUpdateSubjectMappingMethod;
    if ((getUpdateSubjectMappingMethod = SubjectMappingServiceGrpc.getUpdateSubjectMappingMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getUpdateSubjectMappingMethod = SubjectMappingServiceGrpc.getUpdateSubjectMappingMethod) == null) {
          SubjectMappingServiceGrpc.getUpdateSubjectMappingMethod = getUpdateSubjectMappingMethod =
              io.grpc.MethodDescriptor.<com.policy.subjectmapping.UpdateSubjectMappingRequest, com.policy.subjectmapping.UpdateSubjectMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateSubjectMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.UpdateSubjectMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.UpdateSubjectMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("UpdateSubjectMapping"))
              .build();
        }
      }
    }
    return getUpdateSubjectMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.subjectmapping.DeleteSubjectMappingRequest,
      com.policy.subjectmapping.DeleteSubjectMappingResponse> getDeleteSubjectMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeleteSubjectMapping",
      requestType = com.policy.subjectmapping.DeleteSubjectMappingRequest.class,
      responseType = com.policy.subjectmapping.DeleteSubjectMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.subjectmapping.DeleteSubjectMappingRequest,
      com.policy.subjectmapping.DeleteSubjectMappingResponse> getDeleteSubjectMappingMethod() {
    io.grpc.MethodDescriptor<com.policy.subjectmapping.DeleteSubjectMappingRequest, com.policy.subjectmapping.DeleteSubjectMappingResponse> getDeleteSubjectMappingMethod;
    if ((getDeleteSubjectMappingMethod = SubjectMappingServiceGrpc.getDeleteSubjectMappingMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getDeleteSubjectMappingMethod = SubjectMappingServiceGrpc.getDeleteSubjectMappingMethod) == null) {
          SubjectMappingServiceGrpc.getDeleteSubjectMappingMethod = getDeleteSubjectMappingMethod =
              io.grpc.MethodDescriptor.<com.policy.subjectmapping.DeleteSubjectMappingRequest, com.policy.subjectmapping.DeleteSubjectMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeleteSubjectMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.DeleteSubjectMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.subjectmapping.DeleteSubjectMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("DeleteSubjectMapping"))
              .build();
        }
      }
    }
    return getDeleteSubjectMappingMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static SubjectMappingServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<SubjectMappingServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<SubjectMappingServiceStub>() {
        @java.lang.Override
        public SubjectMappingServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new SubjectMappingServiceStub(channel, callOptions);
        }
      };
    return SubjectMappingServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static SubjectMappingServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<SubjectMappingServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<SubjectMappingServiceBlockingStub>() {
        @java.lang.Override
        public SubjectMappingServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new SubjectMappingServiceBlockingStub(channel, callOptions);
        }
      };
    return SubjectMappingServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static SubjectMappingServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<SubjectMappingServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<SubjectMappingServiceFutureStub>() {
        @java.lang.Override
        public SubjectMappingServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new SubjectMappingServiceFutureStub(channel, callOptions);
        }
      };
    return SubjectMappingServiceFutureStub.newStub(factory, channel);
  }

  /**
   */
  public interface AsyncService {

    /**
     */
    default void listSubjectMappings(com.policy.subjectmapping.ListSubjectMappingsRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.ListSubjectMappingsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListSubjectMappingsMethod(), responseObserver);
    }

    /**
     */
    default void getSubjectMapping(com.policy.subjectmapping.GetSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.GetSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetSubjectMappingMethod(), responseObserver);
    }

    /**
     */
    default void createSubjectMapping(com.policy.subjectmapping.CreateSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.CreateSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateSubjectMappingMethod(), responseObserver);
    }

    /**
     */
    default void updateSubjectMapping(com.policy.subjectmapping.UpdateSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.UpdateSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateSubjectMappingMethod(), responseObserver);
    }

    /**
     */
    default void deleteSubjectMapping(com.policy.subjectmapping.DeleteSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.DeleteSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeleteSubjectMappingMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service SubjectMappingService.
   */
  public static abstract class SubjectMappingServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return SubjectMappingServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service SubjectMappingService.
   */
  public static final class SubjectMappingServiceStub
      extends io.grpc.stub.AbstractAsyncStub<SubjectMappingServiceStub> {
    private SubjectMappingServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected SubjectMappingServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new SubjectMappingServiceStub(channel, callOptions);
    }

    /**
     */
    public void listSubjectMappings(com.policy.subjectmapping.ListSubjectMappingsRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.ListSubjectMappingsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListSubjectMappingsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getSubjectMapping(com.policy.subjectmapping.GetSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.GetSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetSubjectMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void createSubjectMapping(com.policy.subjectmapping.CreateSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.CreateSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateSubjectMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateSubjectMapping(com.policy.subjectmapping.UpdateSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.UpdateSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateSubjectMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deleteSubjectMapping(com.policy.subjectmapping.DeleteSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<com.policy.subjectmapping.DeleteSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeleteSubjectMappingMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service SubjectMappingService.
   */
  public static final class SubjectMappingServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<SubjectMappingServiceBlockingStub> {
    private SubjectMappingServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected SubjectMappingServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new SubjectMappingServiceBlockingStub(channel, callOptions);
    }

    /**
     */
    public com.policy.subjectmapping.ListSubjectMappingsResponse listSubjectMappings(com.policy.subjectmapping.ListSubjectMappingsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListSubjectMappingsMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.subjectmapping.GetSubjectMappingResponse getSubjectMapping(com.policy.subjectmapping.GetSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetSubjectMappingMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.subjectmapping.CreateSubjectMappingResponse createSubjectMapping(com.policy.subjectmapping.CreateSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateSubjectMappingMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.subjectmapping.UpdateSubjectMappingResponse updateSubjectMapping(com.policy.subjectmapping.UpdateSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateSubjectMappingMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.subjectmapping.DeleteSubjectMappingResponse deleteSubjectMapping(com.policy.subjectmapping.DeleteSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeleteSubjectMappingMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service SubjectMappingService.
   */
  public static final class SubjectMappingServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<SubjectMappingServiceFutureStub> {
    private SubjectMappingServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected SubjectMappingServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new SubjectMappingServiceFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.subjectmapping.ListSubjectMappingsResponse> listSubjectMappings(
        com.policy.subjectmapping.ListSubjectMappingsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListSubjectMappingsMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.subjectmapping.GetSubjectMappingResponse> getSubjectMapping(
        com.policy.subjectmapping.GetSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetSubjectMappingMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.subjectmapping.CreateSubjectMappingResponse> createSubjectMapping(
        com.policy.subjectmapping.CreateSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateSubjectMappingMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.subjectmapping.UpdateSubjectMappingResponse> updateSubjectMapping(
        com.policy.subjectmapping.UpdateSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateSubjectMappingMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.subjectmapping.DeleteSubjectMappingResponse> deleteSubjectMapping(
        com.policy.subjectmapping.DeleteSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeleteSubjectMappingMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_LIST_SUBJECT_MAPPINGS = 0;
  private static final int METHODID_GET_SUBJECT_MAPPING = 1;
  private static final int METHODID_CREATE_SUBJECT_MAPPING = 2;
  private static final int METHODID_UPDATE_SUBJECT_MAPPING = 3;
  private static final int METHODID_DELETE_SUBJECT_MAPPING = 4;

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
        case METHODID_LIST_SUBJECT_MAPPINGS:
          serviceImpl.listSubjectMappings((com.policy.subjectmapping.ListSubjectMappingsRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.subjectmapping.ListSubjectMappingsResponse>) responseObserver);
          break;
        case METHODID_GET_SUBJECT_MAPPING:
          serviceImpl.getSubjectMapping((com.policy.subjectmapping.GetSubjectMappingRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.subjectmapping.GetSubjectMappingResponse>) responseObserver);
          break;
        case METHODID_CREATE_SUBJECT_MAPPING:
          serviceImpl.createSubjectMapping((com.policy.subjectmapping.CreateSubjectMappingRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.subjectmapping.CreateSubjectMappingResponse>) responseObserver);
          break;
        case METHODID_UPDATE_SUBJECT_MAPPING:
          serviceImpl.updateSubjectMapping((com.policy.subjectmapping.UpdateSubjectMappingRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.subjectmapping.UpdateSubjectMappingResponse>) responseObserver);
          break;
        case METHODID_DELETE_SUBJECT_MAPPING:
          serviceImpl.deleteSubjectMapping((com.policy.subjectmapping.DeleteSubjectMappingRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.subjectmapping.DeleteSubjectMappingResponse>) responseObserver);
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
          getListSubjectMappingsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.subjectmapping.ListSubjectMappingsRequest,
              com.policy.subjectmapping.ListSubjectMappingsResponse>(
                service, METHODID_LIST_SUBJECT_MAPPINGS)))
        .addMethod(
          getGetSubjectMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.subjectmapping.GetSubjectMappingRequest,
              com.policy.subjectmapping.GetSubjectMappingResponse>(
                service, METHODID_GET_SUBJECT_MAPPING)))
        .addMethod(
          getCreateSubjectMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.subjectmapping.CreateSubjectMappingRequest,
              com.policy.subjectmapping.CreateSubjectMappingResponse>(
                service, METHODID_CREATE_SUBJECT_MAPPING)))
        .addMethod(
          getUpdateSubjectMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.subjectmapping.UpdateSubjectMappingRequest,
              com.policy.subjectmapping.UpdateSubjectMappingResponse>(
                service, METHODID_UPDATE_SUBJECT_MAPPING)))
        .addMethod(
          getDeleteSubjectMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.subjectmapping.DeleteSubjectMappingRequest,
              com.policy.subjectmapping.DeleteSubjectMappingResponse>(
                service, METHODID_DELETE_SUBJECT_MAPPING)))
        .build();
  }

  private static abstract class SubjectMappingServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    SubjectMappingServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return com.policy.subjectmapping.SubjectMappingProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("SubjectMappingService");
    }
  }

  private static final class SubjectMappingServiceFileDescriptorSupplier
      extends SubjectMappingServiceBaseDescriptorSupplier {
    SubjectMappingServiceFileDescriptorSupplier() {}
  }

  private static final class SubjectMappingServiceMethodDescriptorSupplier
      extends SubjectMappingServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    SubjectMappingServiceMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (SubjectMappingServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new SubjectMappingServiceFileDescriptorSupplier())
              .addMethod(getListSubjectMappingsMethod())
              .addMethod(getGetSubjectMappingMethod())
              .addMethod(getCreateSubjectMappingMethod())
              .addMethod(getUpdateSubjectMappingMethod())
              .addMethod(getDeleteSubjectMappingMethod())
              .build();
        }
      }
    }
    return result;
  }
}
