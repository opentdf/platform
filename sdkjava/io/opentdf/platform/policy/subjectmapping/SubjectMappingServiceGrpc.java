package io.opentdf.platform.policy.subjectmapping;

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
  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest,
      io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse> getGetSubjectSetMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetSubjectSet",
      requestType = io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest,
      io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse> getGetSubjectSetMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest, io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse> getGetSubjectSetMethod;
    if ((getGetSubjectSetMethod = SubjectMappingServiceGrpc.getGetSubjectSetMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getGetSubjectSetMethod = SubjectMappingServiceGrpc.getGetSubjectSetMethod) == null) {
          SubjectMappingServiceGrpc.getGetSubjectSetMethod = getGetSubjectSetMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest, io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetSubjectSet"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("GetSubjectSet"))
              .build();
        }
      }
    }
    return getGetSubjectSetMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest,
      io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse> getCreateSubjectSetMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateSubjectSet",
      requestType = io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest,
      io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse> getCreateSubjectSetMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest, io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse> getCreateSubjectSetMethod;
    if ((getCreateSubjectSetMethod = SubjectMappingServiceGrpc.getCreateSubjectSetMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getCreateSubjectSetMethod = SubjectMappingServiceGrpc.getCreateSubjectSetMethod) == null) {
          SubjectMappingServiceGrpc.getCreateSubjectSetMethod = getCreateSubjectSetMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest, io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateSubjectSet"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("CreateSubjectSet"))
              .build();
        }
      }
    }
    return getCreateSubjectSetMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest,
      io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse> getUpdateSubjectSetMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateSubjectSet",
      requestType = io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest,
      io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse> getUpdateSubjectSetMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest, io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse> getUpdateSubjectSetMethod;
    if ((getUpdateSubjectSetMethod = SubjectMappingServiceGrpc.getUpdateSubjectSetMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getUpdateSubjectSetMethod = SubjectMappingServiceGrpc.getUpdateSubjectSetMethod) == null) {
          SubjectMappingServiceGrpc.getUpdateSubjectSetMethod = getUpdateSubjectSetMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest, io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateSubjectSet"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("UpdateSubjectSet"))
              .build();
        }
      }
    }
    return getUpdateSubjectSetMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest,
      io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse> getDeleteSubjectSetMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeleteSubjectSet",
      requestType = io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest,
      io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse> getDeleteSubjectSetMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest, io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse> getDeleteSubjectSetMethod;
    if ((getDeleteSubjectSetMethod = SubjectMappingServiceGrpc.getDeleteSubjectSetMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getDeleteSubjectSetMethod = SubjectMappingServiceGrpc.getDeleteSubjectSetMethod) == null) {
          SubjectMappingServiceGrpc.getDeleteSubjectSetMethod = getDeleteSubjectSetMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest, io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeleteSubjectSet"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("DeleteSubjectSet"))
              .build();
        }
      }
    }
    return getDeleteSubjectSetMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest,
      io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse> getListSubjectSetsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListSubjectSets",
      requestType = io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest,
      io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse> getListSubjectSetsMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest, io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse> getListSubjectSetsMethod;
    if ((getListSubjectSetsMethod = SubjectMappingServiceGrpc.getListSubjectSetsMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getListSubjectSetsMethod = SubjectMappingServiceGrpc.getListSubjectSetsMethod) == null) {
          SubjectMappingServiceGrpc.getListSubjectSetsMethod = getListSubjectSetsMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest, io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListSubjectSets"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("ListSubjectSets"))
              .build();
        }
      }
    }
    return getListSubjectSetsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest,
      io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse> getMatchSubjectMappingsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "MatchSubjectMappings",
      requestType = io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest,
      io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse> getMatchSubjectMappingsMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest, io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse> getMatchSubjectMappingsMethod;
    if ((getMatchSubjectMappingsMethod = SubjectMappingServiceGrpc.getMatchSubjectMappingsMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getMatchSubjectMappingsMethod = SubjectMappingServiceGrpc.getMatchSubjectMappingsMethod) == null) {
          SubjectMappingServiceGrpc.getMatchSubjectMappingsMethod = getMatchSubjectMappingsMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest, io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "MatchSubjectMappings"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("MatchSubjectMappings"))
              .build();
        }
      }
    }
    return getMatchSubjectMappingsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest,
      io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse> getListSubjectMappingsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListSubjectMappings",
      requestType = io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest,
      io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse> getListSubjectMappingsMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest, io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse> getListSubjectMappingsMethod;
    if ((getListSubjectMappingsMethod = SubjectMappingServiceGrpc.getListSubjectMappingsMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getListSubjectMappingsMethod = SubjectMappingServiceGrpc.getListSubjectMappingsMethod) == null) {
          SubjectMappingServiceGrpc.getListSubjectMappingsMethod = getListSubjectMappingsMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest, io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListSubjectMappings"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("ListSubjectMappings"))
              .build();
        }
      }
    }
    return getListSubjectMappingsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest,
      io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse> getGetSubjectMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetSubjectMapping",
      requestType = io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest,
      io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse> getGetSubjectMappingMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest, io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse> getGetSubjectMappingMethod;
    if ((getGetSubjectMappingMethod = SubjectMappingServiceGrpc.getGetSubjectMappingMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getGetSubjectMappingMethod = SubjectMappingServiceGrpc.getGetSubjectMappingMethod) == null) {
          SubjectMappingServiceGrpc.getGetSubjectMappingMethod = getGetSubjectMappingMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest, io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetSubjectMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("GetSubjectMapping"))
              .build();
        }
      }
    }
    return getGetSubjectMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest,
      io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse> getCreateSubjectMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateSubjectMapping",
      requestType = io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest,
      io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse> getCreateSubjectMappingMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest, io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse> getCreateSubjectMappingMethod;
    if ((getCreateSubjectMappingMethod = SubjectMappingServiceGrpc.getCreateSubjectMappingMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getCreateSubjectMappingMethod = SubjectMappingServiceGrpc.getCreateSubjectMappingMethod) == null) {
          SubjectMappingServiceGrpc.getCreateSubjectMappingMethod = getCreateSubjectMappingMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest, io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateSubjectMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("CreateSubjectMapping"))
              .build();
        }
      }
    }
    return getCreateSubjectMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest,
      io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse> getUpdateSubjectMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateSubjectMapping",
      requestType = io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest,
      io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse> getUpdateSubjectMappingMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest, io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse> getUpdateSubjectMappingMethod;
    if ((getUpdateSubjectMappingMethod = SubjectMappingServiceGrpc.getUpdateSubjectMappingMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getUpdateSubjectMappingMethod = SubjectMappingServiceGrpc.getUpdateSubjectMappingMethod) == null) {
          SubjectMappingServiceGrpc.getUpdateSubjectMappingMethod = getUpdateSubjectMappingMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest, io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateSubjectMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse.getDefaultInstance()))
              .setSchemaDescriptor(new SubjectMappingServiceMethodDescriptorSupplier("UpdateSubjectMapping"))
              .build();
        }
      }
    }
    return getUpdateSubjectMappingMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest,
      io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse> getDeleteSubjectMappingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeleteSubjectMapping",
      requestType = io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest.class,
      responseType = io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest,
      io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse> getDeleteSubjectMappingMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest, io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse> getDeleteSubjectMappingMethod;
    if ((getDeleteSubjectMappingMethod = SubjectMappingServiceGrpc.getDeleteSubjectMappingMethod) == null) {
      synchronized (SubjectMappingServiceGrpc.class) {
        if ((getDeleteSubjectMappingMethod = SubjectMappingServiceGrpc.getDeleteSubjectMappingMethod) == null) {
          SubjectMappingServiceGrpc.getDeleteSubjectMappingMethod = getDeleteSubjectMappingMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest, io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeleteSubjectMapping"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse.getDefaultInstance()))
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
    default void getSubjectSet(io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetSubjectSetMethod(), responseObserver);
    }

    /**
     */
    default void createSubjectSet(io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateSubjectSetMethod(), responseObserver);
    }

    /**
     */
    default void updateSubjectSet(io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateSubjectSetMethod(), responseObserver);
    }

    /**
     */
    default void deleteSubjectSet(io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeleteSubjectSetMethod(), responseObserver);
    }

    /**
     */
    default void listSubjectSets(io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListSubjectSetsMethod(), responseObserver);
    }

    /**
     * <pre>
     * Find matching Subject Mappings for a given Subject
     * </pre>
     */
    default void matchSubjectMappings(io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getMatchSubjectMappingsMethod(), responseObserver);
    }

    /**
     */
    default void listSubjectMappings(io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListSubjectMappingsMethod(), responseObserver);
    }

    /**
     */
    default void getSubjectMapping(io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetSubjectMappingMethod(), responseObserver);
    }

    /**
     */
    default void createSubjectMapping(io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateSubjectMappingMethod(), responseObserver);
    }

    /**
     */
    default void updateSubjectMapping(io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateSubjectMappingMethod(), responseObserver);
    }

    /**
     */
    default void deleteSubjectMapping(io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse> responseObserver) {
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
    public void getSubjectSet(io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetSubjectSetMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void createSubjectSet(io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateSubjectSetMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateSubjectSet(io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateSubjectSetMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deleteSubjectSet(io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeleteSubjectSetMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void listSubjectSets(io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListSubjectSetsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Find matching Subject Mappings for a given Subject
     * </pre>
     */
    public void matchSubjectMappings(io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getMatchSubjectMappingsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void listSubjectMappings(io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListSubjectMappingsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getSubjectMapping(io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetSubjectMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void createSubjectMapping(io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateSubjectMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateSubjectMapping(io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateSubjectMappingMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deleteSubjectMapping(io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse> responseObserver) {
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
    public io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse getSubjectSet(io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetSubjectSetMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse createSubjectSet(io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateSubjectSetMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse updateSubjectSet(io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateSubjectSetMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse deleteSubjectSet(io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeleteSubjectSetMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse listSubjectSets(io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListSubjectSetsMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Find matching Subject Mappings for a given Subject
     * </pre>
     */
    public io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse matchSubjectMappings(io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getMatchSubjectMappingsMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse listSubjectMappings(io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListSubjectMappingsMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse getSubjectMapping(io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetSubjectMappingMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse createSubjectMapping(io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateSubjectMappingMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse updateSubjectMapping(io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateSubjectMappingMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse deleteSubjectMapping(io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest request) {
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
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse> getSubjectSet(
        io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetSubjectSetMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse> createSubjectSet(
        io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateSubjectSetMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse> updateSubjectSet(
        io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateSubjectSetMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse> deleteSubjectSet(
        io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeleteSubjectSetMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse> listSubjectSets(
        io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListSubjectSetsMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Find matching Subject Mappings for a given Subject
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse> matchSubjectMappings(
        io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getMatchSubjectMappingsMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse> listSubjectMappings(
        io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListSubjectMappingsMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse> getSubjectMapping(
        io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetSubjectMappingMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse> createSubjectMapping(
        io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateSubjectMappingMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse> updateSubjectMapping(
        io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateSubjectMappingMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse> deleteSubjectMapping(
        io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeleteSubjectMappingMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_GET_SUBJECT_SET = 0;
  private static final int METHODID_CREATE_SUBJECT_SET = 1;
  private static final int METHODID_UPDATE_SUBJECT_SET = 2;
  private static final int METHODID_DELETE_SUBJECT_SET = 3;
  private static final int METHODID_LIST_SUBJECT_SETS = 4;
  private static final int METHODID_MATCH_SUBJECT_MAPPINGS = 5;
  private static final int METHODID_LIST_SUBJECT_MAPPINGS = 6;
  private static final int METHODID_GET_SUBJECT_MAPPING = 7;
  private static final int METHODID_CREATE_SUBJECT_MAPPING = 8;
  private static final int METHODID_UPDATE_SUBJECT_MAPPING = 9;
  private static final int METHODID_DELETE_SUBJECT_MAPPING = 10;

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
        case METHODID_GET_SUBJECT_SET:
          serviceImpl.getSubjectSet((io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse>) responseObserver);
          break;
        case METHODID_CREATE_SUBJECT_SET:
          serviceImpl.createSubjectSet((io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse>) responseObserver);
          break;
        case METHODID_UPDATE_SUBJECT_SET:
          serviceImpl.updateSubjectSet((io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse>) responseObserver);
          break;
        case METHODID_DELETE_SUBJECT_SET:
          serviceImpl.deleteSubjectSet((io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse>) responseObserver);
          break;
        case METHODID_LIST_SUBJECT_SETS:
          serviceImpl.listSubjectSets((io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse>) responseObserver);
          break;
        case METHODID_MATCH_SUBJECT_MAPPINGS:
          serviceImpl.matchSubjectMappings((io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse>) responseObserver);
          break;
        case METHODID_LIST_SUBJECT_MAPPINGS:
          serviceImpl.listSubjectMappings((io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse>) responseObserver);
          break;
        case METHODID_GET_SUBJECT_MAPPING:
          serviceImpl.getSubjectMapping((io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse>) responseObserver);
          break;
        case METHODID_CREATE_SUBJECT_MAPPING:
          serviceImpl.createSubjectMapping((io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse>) responseObserver);
          break;
        case METHODID_UPDATE_SUBJECT_MAPPING:
          serviceImpl.updateSubjectMapping((io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse>) responseObserver);
          break;
        case METHODID_DELETE_SUBJECT_MAPPING:
          serviceImpl.deleteSubjectMapping((io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse>) responseObserver);
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
          getGetSubjectSetMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.GetSubjectSetRequest,
              io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse>(
                service, METHODID_GET_SUBJECT_SET)))
        .addMethod(
          getCreateSubjectSetMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.CreateSubjectSetRequest,
              io.opentdf.platform.policy.subjectmapping.CreateSubjectSetResponse>(
                service, METHODID_CREATE_SUBJECT_SET)))
        .addMethod(
          getUpdateSubjectSetMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetRequest,
              io.opentdf.platform.policy.subjectmapping.UpdateSubjectSetResponse>(
                service, METHODID_UPDATE_SUBJECT_SET)))
        .addMethod(
          getDeleteSubjectSetMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetRequest,
              io.opentdf.platform.policy.subjectmapping.DeleteSubjectSetResponse>(
                service, METHODID_DELETE_SUBJECT_SET)))
        .addMethod(
          getListSubjectSetsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.ListSubjectSetsRequest,
              io.opentdf.platform.policy.subjectmapping.ListSubjectSetsResponse>(
                service, METHODID_LIST_SUBJECT_SETS)))
        .addMethod(
          getMatchSubjectMappingsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsRequest,
              io.opentdf.platform.policy.subjectmapping.MatchSubjectMappingsResponse>(
                service, METHODID_MATCH_SUBJECT_MAPPINGS)))
        .addMethod(
          getListSubjectMappingsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsRequest,
              io.opentdf.platform.policy.subjectmapping.ListSubjectMappingsResponse>(
                service, METHODID_LIST_SUBJECT_MAPPINGS)))
        .addMethod(
          getGetSubjectMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.GetSubjectMappingRequest,
              io.opentdf.platform.policy.subjectmapping.GetSubjectMappingResponse>(
                service, METHODID_GET_SUBJECT_MAPPING)))
        .addMethod(
          getCreateSubjectMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingRequest,
              io.opentdf.platform.policy.subjectmapping.CreateSubjectMappingResponse>(
                service, METHODID_CREATE_SUBJECT_MAPPING)))
        .addMethod(
          getUpdateSubjectMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingRequest,
              io.opentdf.platform.policy.subjectmapping.UpdateSubjectMappingResponse>(
                service, METHODID_UPDATE_SUBJECT_MAPPING)))
        .addMethod(
          getDeleteSubjectMappingMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingRequest,
              io.opentdf.platform.policy.subjectmapping.DeleteSubjectMappingResponse>(
                service, METHODID_DELETE_SUBJECT_MAPPING)))
        .build();
  }

  private static abstract class SubjectMappingServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    SubjectMappingServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.getDescriptor();
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
              .addMethod(getGetSubjectSetMethod())
              .addMethod(getCreateSubjectSetMethod())
              .addMethod(getUpdateSubjectSetMethod())
              .addMethod(getDeleteSubjectSetMethod())
              .addMethod(getListSubjectSetsMethod())
              .addMethod(getMatchSubjectMappingsMethod())
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
