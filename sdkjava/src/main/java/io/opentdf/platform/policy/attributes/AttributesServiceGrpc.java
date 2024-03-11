package io.opentdf.platform.policy.attributes;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 * <pre>
 *&#47;
 * / Attribute Service
 * /
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.61.1)",
    comments = "Source: policy/attributes/attributes.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class AttributesServiceGrpc {

  private AttributesServiceGrpc() {}

  public static final java.lang.String SERVICE_NAME = "policy.attributes.AttributesService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.ListAttributesRequest,
      io.opentdf.platform.policy.attributes.ListAttributesResponse> getListAttributesMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListAttributes",
      requestType = io.opentdf.platform.policy.attributes.ListAttributesRequest.class,
      responseType = io.opentdf.platform.policy.attributes.ListAttributesResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.ListAttributesRequest,
      io.opentdf.platform.policy.attributes.ListAttributesResponse> getListAttributesMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.ListAttributesRequest, io.opentdf.platform.policy.attributes.ListAttributesResponse> getListAttributesMethod;
    if ((getListAttributesMethod = AttributesServiceGrpc.getListAttributesMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getListAttributesMethod = AttributesServiceGrpc.getListAttributesMethod) == null) {
          AttributesServiceGrpc.getListAttributesMethod = getListAttributesMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.ListAttributesRequest, io.opentdf.platform.policy.attributes.ListAttributesResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListAttributes"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.ListAttributesRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.ListAttributesResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("ListAttributes"))
              .build();
        }
      }
    }
    return getListAttributesMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.ListAttributeValuesRequest,
      io.opentdf.platform.policy.attributes.ListAttributeValuesResponse> getListAttributeValuesMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListAttributeValues",
      requestType = io.opentdf.platform.policy.attributes.ListAttributeValuesRequest.class,
      responseType = io.opentdf.platform.policy.attributes.ListAttributeValuesResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.ListAttributeValuesRequest,
      io.opentdf.platform.policy.attributes.ListAttributeValuesResponse> getListAttributeValuesMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.ListAttributeValuesRequest, io.opentdf.platform.policy.attributes.ListAttributeValuesResponse> getListAttributeValuesMethod;
    if ((getListAttributeValuesMethod = AttributesServiceGrpc.getListAttributeValuesMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getListAttributeValuesMethod = AttributesServiceGrpc.getListAttributeValuesMethod) == null) {
          AttributesServiceGrpc.getListAttributeValuesMethod = getListAttributeValuesMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.ListAttributeValuesRequest, io.opentdf.platform.policy.attributes.ListAttributeValuesResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListAttributeValues"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.ListAttributeValuesRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.ListAttributeValuesResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("ListAttributeValues"))
              .build();
        }
      }
    }
    return getListAttributeValuesMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.GetAttributeRequest,
      io.opentdf.platform.policy.attributes.GetAttributeResponse> getGetAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetAttribute",
      requestType = io.opentdf.platform.policy.attributes.GetAttributeRequest.class,
      responseType = io.opentdf.platform.policy.attributes.GetAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.GetAttributeRequest,
      io.opentdf.platform.policy.attributes.GetAttributeResponse> getGetAttributeMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.GetAttributeRequest, io.opentdf.platform.policy.attributes.GetAttributeResponse> getGetAttributeMethod;
    if ((getGetAttributeMethod = AttributesServiceGrpc.getGetAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getGetAttributeMethod = AttributesServiceGrpc.getGetAttributeMethod) == null) {
          AttributesServiceGrpc.getGetAttributeMethod = getGetAttributeMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.GetAttributeRequest, io.opentdf.platform.policy.attributes.GetAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.GetAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.GetAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("GetAttribute"))
              .build();
        }
      }
    }
    return getGetAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest,
      io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse> getGetAttributesByValueFqnsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetAttributesByValueFqns",
      requestType = io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest.class,
      responseType = io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest,
      io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse> getGetAttributesByValueFqnsMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest, io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse> getGetAttributesByValueFqnsMethod;
    if ((getGetAttributesByValueFqnsMethod = AttributesServiceGrpc.getGetAttributesByValueFqnsMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getGetAttributesByValueFqnsMethod = AttributesServiceGrpc.getGetAttributesByValueFqnsMethod) == null) {
          AttributesServiceGrpc.getGetAttributesByValueFqnsMethod = getGetAttributesByValueFqnsMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest, io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetAttributesByValueFqns"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("GetAttributesByValueFqns"))
              .build();
        }
      }
    }
    return getGetAttributesByValueFqnsMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.CreateAttributeRequest,
      io.opentdf.platform.policy.attributes.CreateAttributeResponse> getCreateAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateAttribute",
      requestType = io.opentdf.platform.policy.attributes.CreateAttributeRequest.class,
      responseType = io.opentdf.platform.policy.attributes.CreateAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.CreateAttributeRequest,
      io.opentdf.platform.policy.attributes.CreateAttributeResponse> getCreateAttributeMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.CreateAttributeRequest, io.opentdf.platform.policy.attributes.CreateAttributeResponse> getCreateAttributeMethod;
    if ((getCreateAttributeMethod = AttributesServiceGrpc.getCreateAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getCreateAttributeMethod = AttributesServiceGrpc.getCreateAttributeMethod) == null) {
          AttributesServiceGrpc.getCreateAttributeMethod = getCreateAttributeMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.CreateAttributeRequest, io.opentdf.platform.policy.attributes.CreateAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.CreateAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.CreateAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("CreateAttribute"))
              .build();
        }
      }
    }
    return getCreateAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.UpdateAttributeRequest,
      io.opentdf.platform.policy.attributes.UpdateAttributeResponse> getUpdateAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateAttribute",
      requestType = io.opentdf.platform.policy.attributes.UpdateAttributeRequest.class,
      responseType = io.opentdf.platform.policy.attributes.UpdateAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.UpdateAttributeRequest,
      io.opentdf.platform.policy.attributes.UpdateAttributeResponse> getUpdateAttributeMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.UpdateAttributeRequest, io.opentdf.platform.policy.attributes.UpdateAttributeResponse> getUpdateAttributeMethod;
    if ((getUpdateAttributeMethod = AttributesServiceGrpc.getUpdateAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getUpdateAttributeMethod = AttributesServiceGrpc.getUpdateAttributeMethod) == null) {
          AttributesServiceGrpc.getUpdateAttributeMethod = getUpdateAttributeMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.UpdateAttributeRequest, io.opentdf.platform.policy.attributes.UpdateAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.UpdateAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.UpdateAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("UpdateAttribute"))
              .build();
        }
      }
    }
    return getUpdateAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.DeactivateAttributeRequest,
      io.opentdf.platform.policy.attributes.DeactivateAttributeResponse> getDeactivateAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeactivateAttribute",
      requestType = io.opentdf.platform.policy.attributes.DeactivateAttributeRequest.class,
      responseType = io.opentdf.platform.policy.attributes.DeactivateAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.DeactivateAttributeRequest,
      io.opentdf.platform.policy.attributes.DeactivateAttributeResponse> getDeactivateAttributeMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.DeactivateAttributeRequest, io.opentdf.platform.policy.attributes.DeactivateAttributeResponse> getDeactivateAttributeMethod;
    if ((getDeactivateAttributeMethod = AttributesServiceGrpc.getDeactivateAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getDeactivateAttributeMethod = AttributesServiceGrpc.getDeactivateAttributeMethod) == null) {
          AttributesServiceGrpc.getDeactivateAttributeMethod = getDeactivateAttributeMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.DeactivateAttributeRequest, io.opentdf.platform.policy.attributes.DeactivateAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeactivateAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.DeactivateAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.DeactivateAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("DeactivateAttribute"))
              .build();
        }
      }
    }
    return getDeactivateAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.GetAttributeValueRequest,
      io.opentdf.platform.policy.attributes.GetAttributeValueResponse> getGetAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetAttributeValue",
      requestType = io.opentdf.platform.policy.attributes.GetAttributeValueRequest.class,
      responseType = io.opentdf.platform.policy.attributes.GetAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.GetAttributeValueRequest,
      io.opentdf.platform.policy.attributes.GetAttributeValueResponse> getGetAttributeValueMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.GetAttributeValueRequest, io.opentdf.platform.policy.attributes.GetAttributeValueResponse> getGetAttributeValueMethod;
    if ((getGetAttributeValueMethod = AttributesServiceGrpc.getGetAttributeValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getGetAttributeValueMethod = AttributesServiceGrpc.getGetAttributeValueMethod) == null) {
          AttributesServiceGrpc.getGetAttributeValueMethod = getGetAttributeValueMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.GetAttributeValueRequest, io.opentdf.platform.policy.attributes.GetAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.GetAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.GetAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("GetAttributeValue"))
              .build();
        }
      }
    }
    return getGetAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.CreateAttributeValueRequest,
      io.opentdf.platform.policy.attributes.CreateAttributeValueResponse> getCreateAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateAttributeValue",
      requestType = io.opentdf.platform.policy.attributes.CreateAttributeValueRequest.class,
      responseType = io.opentdf.platform.policy.attributes.CreateAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.CreateAttributeValueRequest,
      io.opentdf.platform.policy.attributes.CreateAttributeValueResponse> getCreateAttributeValueMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.CreateAttributeValueRequest, io.opentdf.platform.policy.attributes.CreateAttributeValueResponse> getCreateAttributeValueMethod;
    if ((getCreateAttributeValueMethod = AttributesServiceGrpc.getCreateAttributeValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getCreateAttributeValueMethod = AttributesServiceGrpc.getCreateAttributeValueMethod) == null) {
          AttributesServiceGrpc.getCreateAttributeValueMethod = getCreateAttributeValueMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.CreateAttributeValueRequest, io.opentdf.platform.policy.attributes.CreateAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.CreateAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.CreateAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("CreateAttributeValue"))
              .build();
        }
      }
    }
    return getCreateAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest,
      io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse> getUpdateAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateAttributeValue",
      requestType = io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest.class,
      responseType = io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest,
      io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse> getUpdateAttributeValueMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest, io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse> getUpdateAttributeValueMethod;
    if ((getUpdateAttributeValueMethod = AttributesServiceGrpc.getUpdateAttributeValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getUpdateAttributeValueMethod = AttributesServiceGrpc.getUpdateAttributeValueMethod) == null) {
          AttributesServiceGrpc.getUpdateAttributeValueMethod = getUpdateAttributeValueMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest, io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("UpdateAttributeValue"))
              .build();
        }
      }
    }
    return getUpdateAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest,
      io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse> getDeactivateAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeactivateAttributeValue",
      requestType = io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest.class,
      responseType = io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest,
      io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse> getDeactivateAttributeValueMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest, io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse> getDeactivateAttributeValueMethod;
    if ((getDeactivateAttributeValueMethod = AttributesServiceGrpc.getDeactivateAttributeValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getDeactivateAttributeValueMethod = AttributesServiceGrpc.getDeactivateAttributeValueMethod) == null) {
          AttributesServiceGrpc.getDeactivateAttributeValueMethod = getDeactivateAttributeValueMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest, io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeactivateAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("DeactivateAttributeValue"))
              .build();
        }
      }
    }
    return getDeactivateAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest,
      io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse> getAssignKeyAccessServerToAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "AssignKeyAccessServerToAttribute",
      requestType = io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest.class,
      responseType = io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest,
      io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse> getAssignKeyAccessServerToAttributeMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest, io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse> getAssignKeyAccessServerToAttributeMethod;
    if ((getAssignKeyAccessServerToAttributeMethod = AttributesServiceGrpc.getAssignKeyAccessServerToAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getAssignKeyAccessServerToAttributeMethod = AttributesServiceGrpc.getAssignKeyAccessServerToAttributeMethod) == null) {
          AttributesServiceGrpc.getAssignKeyAccessServerToAttributeMethod = getAssignKeyAccessServerToAttributeMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest, io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "AssignKeyAccessServerToAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("AssignKeyAccessServerToAttribute"))
              .build();
        }
      }
    }
    return getAssignKeyAccessServerToAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest,
      io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> getRemoveKeyAccessServerFromAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "RemoveKeyAccessServerFromAttribute",
      requestType = io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest.class,
      responseType = io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest,
      io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> getRemoveKeyAccessServerFromAttributeMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest, io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> getRemoveKeyAccessServerFromAttributeMethod;
    if ((getRemoveKeyAccessServerFromAttributeMethod = AttributesServiceGrpc.getRemoveKeyAccessServerFromAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getRemoveKeyAccessServerFromAttributeMethod = AttributesServiceGrpc.getRemoveKeyAccessServerFromAttributeMethod) == null) {
          AttributesServiceGrpc.getRemoveKeyAccessServerFromAttributeMethod = getRemoveKeyAccessServerFromAttributeMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest, io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "RemoveKeyAccessServerFromAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("RemoveKeyAccessServerFromAttribute"))
              .build();
        }
      }
    }
    return getRemoveKeyAccessServerFromAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest,
      io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse> getAssignKeyAccessServerToValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "AssignKeyAccessServerToValue",
      requestType = io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest.class,
      responseType = io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest,
      io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse> getAssignKeyAccessServerToValueMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest, io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse> getAssignKeyAccessServerToValueMethod;
    if ((getAssignKeyAccessServerToValueMethod = AttributesServiceGrpc.getAssignKeyAccessServerToValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getAssignKeyAccessServerToValueMethod = AttributesServiceGrpc.getAssignKeyAccessServerToValueMethod) == null) {
          AttributesServiceGrpc.getAssignKeyAccessServerToValueMethod = getAssignKeyAccessServerToValueMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest, io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "AssignKeyAccessServerToValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("AssignKeyAccessServerToValue"))
              .build();
        }
      }
    }
    return getAssignKeyAccessServerToValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest,
      io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse> getRemoveKeyAccessServerFromValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "RemoveKeyAccessServerFromValue",
      requestType = io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest.class,
      responseType = io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest,
      io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse> getRemoveKeyAccessServerFromValueMethod() {
    io.grpc.MethodDescriptor<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest, io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse> getRemoveKeyAccessServerFromValueMethod;
    if ((getRemoveKeyAccessServerFromValueMethod = AttributesServiceGrpc.getRemoveKeyAccessServerFromValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getRemoveKeyAccessServerFromValueMethod = AttributesServiceGrpc.getRemoveKeyAccessServerFromValueMethod) == null) {
          AttributesServiceGrpc.getRemoveKeyAccessServerFromValueMethod = getRemoveKeyAccessServerFromValueMethod =
              io.grpc.MethodDescriptor.<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest, io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "RemoveKeyAccessServerFromValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("RemoveKeyAccessServerFromValue"))
              .build();
        }
      }
    }
    return getRemoveKeyAccessServerFromValueMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static AttributesServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<AttributesServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<AttributesServiceStub>() {
        @java.lang.Override
        public AttributesServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new AttributesServiceStub(channel, callOptions);
        }
      };
    return AttributesServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static AttributesServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<AttributesServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<AttributesServiceBlockingStub>() {
        @java.lang.Override
        public AttributesServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new AttributesServiceBlockingStub(channel, callOptions);
        }
      };
    return AttributesServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static AttributesServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<AttributesServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<AttributesServiceFutureStub>() {
        @java.lang.Override
        public AttributesServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new AttributesServiceFutureStub(channel, callOptions);
        }
      };
    return AttributesServiceFutureStub.newStub(factory, channel);
  }

  /**
   * <pre>
   *&#47;
   * / Attribute Service
   * /
   * </pre>
   */
  public interface AsyncService {

    /**
     * <pre>
     *--------------------------------------*
     * Attribute RPCs
     *---------------------------------------
     * </pre>
     */
    default void listAttributes(io.opentdf.platform.policy.attributes.ListAttributesRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.ListAttributesResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListAttributesMethod(), responseObserver);
    }

    /**
     */
    default void listAttributeValues(io.opentdf.platform.policy.attributes.ListAttributeValuesRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.ListAttributeValuesResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListAttributeValuesMethod(), responseObserver);
    }

    /**
     */
    default void getAttribute(io.opentdf.platform.policy.attributes.GetAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.GetAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetAttributeMethod(), responseObserver);
    }

    /**
     */
    default void getAttributesByValueFqns(io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetAttributesByValueFqnsMethod(), responseObserver);
    }

    /**
     */
    default void createAttribute(io.opentdf.platform.policy.attributes.CreateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.CreateAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateAttributeMethod(), responseObserver);
    }

    /**
     */
    default void updateAttribute(io.opentdf.platform.policy.attributes.UpdateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.UpdateAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateAttributeMethod(), responseObserver);
    }

    /**
     */
    default void deactivateAttribute(io.opentdf.platform.policy.attributes.DeactivateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.DeactivateAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeactivateAttributeMethod(), responseObserver);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Value RPCs
     *---------------------------------------
     * </pre>
     */
    default void getAttributeValue(io.opentdf.platform.policy.attributes.GetAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.GetAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetAttributeValueMethod(), responseObserver);
    }

    /**
     */
    default void createAttributeValue(io.opentdf.platform.policy.attributes.CreateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.CreateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateAttributeValueMethod(), responseObserver);
    }

    /**
     */
    default void updateAttributeValue(io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateAttributeValueMethod(), responseObserver);
    }

    /**
     */
    default void deactivateAttributeValue(io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeactivateAttributeValueMethod(), responseObserver);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute &lt;&gt; Key Access Server RPCs
     *---------------------------------------
     * </pre>
     */
    default void assignKeyAccessServerToAttribute(io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getAssignKeyAccessServerToAttributeMethod(), responseObserver);
    }

    /**
     */
    default void removeKeyAccessServerFromAttribute(io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getRemoveKeyAccessServerFromAttributeMethod(), responseObserver);
    }

    /**
     */
    default void assignKeyAccessServerToValue(io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getAssignKeyAccessServerToValueMethod(), responseObserver);
    }

    /**
     */
    default void removeKeyAccessServerFromValue(io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getRemoveKeyAccessServerFromValueMethod(), responseObserver);
    }
  }

  /**
   * Base class for the server implementation of the service AttributesService.
   * <pre>
   *&#47;
   * / Attribute Service
   * /
   * </pre>
   */
  public static abstract class AttributesServiceImplBase
      implements io.grpc.BindableService, AsyncService {

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return AttributesServiceGrpc.bindService(this);
    }
  }

  /**
   * A stub to allow clients to do asynchronous rpc calls to service AttributesService.
   * <pre>
   *&#47;
   * / Attribute Service
   * /
   * </pre>
   */
  public static final class AttributesServiceStub
      extends io.grpc.stub.AbstractAsyncStub<AttributesServiceStub> {
    private AttributesServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AttributesServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new AttributesServiceStub(channel, callOptions);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute RPCs
     *---------------------------------------
     * </pre>
     */
    public void listAttributes(io.opentdf.platform.policy.attributes.ListAttributesRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.ListAttributesResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListAttributesMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void listAttributeValues(io.opentdf.platform.policy.attributes.ListAttributeValuesRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.ListAttributeValuesResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListAttributeValuesMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getAttribute(io.opentdf.platform.policy.attributes.GetAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.GetAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getAttributesByValueFqns(io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetAttributesByValueFqnsMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void createAttribute(io.opentdf.platform.policy.attributes.CreateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.CreateAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateAttribute(io.opentdf.platform.policy.attributes.UpdateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.UpdateAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deactivateAttribute(io.opentdf.platform.policy.attributes.DeactivateAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.DeactivateAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeactivateAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Value RPCs
     *---------------------------------------
     * </pre>
     */
    public void getAttributeValue(io.opentdf.platform.policy.attributes.GetAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.GetAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void createAttributeValue(io.opentdf.platform.policy.attributes.CreateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.CreateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateAttributeValue(io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deactivateAttributeValue(io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeactivateAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute &lt;&gt; Key Access Server RPCs
     *---------------------------------------
     * </pre>
     */
    public void assignKeyAccessServerToAttribute(io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getAssignKeyAccessServerToAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void removeKeyAccessServerFromAttribute(io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getRemoveKeyAccessServerFromAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void assignKeyAccessServerToValue(io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getAssignKeyAccessServerToValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void removeKeyAccessServerFromValue(io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest request,
        io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getRemoveKeyAccessServerFromValueMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * A stub to allow clients to do synchronous rpc calls to service AttributesService.
   * <pre>
   *&#47;
   * / Attribute Service
   * /
   * </pre>
   */
  public static final class AttributesServiceBlockingStub
      extends io.grpc.stub.AbstractBlockingStub<AttributesServiceBlockingStub> {
    private AttributesServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AttributesServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new AttributesServiceBlockingStub(channel, callOptions);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute RPCs
     *---------------------------------------
     * </pre>
     */
    public io.opentdf.platform.policy.attributes.ListAttributesResponse listAttributes(io.opentdf.platform.policy.attributes.ListAttributesRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListAttributesMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.ListAttributeValuesResponse listAttributeValues(io.opentdf.platform.policy.attributes.ListAttributeValuesRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListAttributeValuesMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.GetAttributeResponse getAttribute(io.opentdf.platform.policy.attributes.GetAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetAttributeMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse getAttributesByValueFqns(io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetAttributesByValueFqnsMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.CreateAttributeResponse createAttribute(io.opentdf.platform.policy.attributes.CreateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateAttributeMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.UpdateAttributeResponse updateAttribute(io.opentdf.platform.policy.attributes.UpdateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateAttributeMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.DeactivateAttributeResponse deactivateAttribute(io.opentdf.platform.policy.attributes.DeactivateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeactivateAttributeMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Value RPCs
     *---------------------------------------
     * </pre>
     */
    public io.opentdf.platform.policy.attributes.GetAttributeValueResponse getAttributeValue(io.opentdf.platform.policy.attributes.GetAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.CreateAttributeValueResponse createAttributeValue(io.opentdf.platform.policy.attributes.CreateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse updateAttributeValue(io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse deactivateAttributeValue(io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeactivateAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute &lt;&gt; Key Access Server RPCs
     *---------------------------------------
     * </pre>
     */
    public io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse assignKeyAccessServerToAttribute(io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getAssignKeyAccessServerToAttributeMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse removeKeyAccessServerFromAttribute(io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getRemoveKeyAccessServerFromAttributeMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse assignKeyAccessServerToValue(io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getAssignKeyAccessServerToValueMethod(), getCallOptions(), request);
    }

    /**
     */
    public io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse removeKeyAccessServerFromValue(io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getRemoveKeyAccessServerFromValueMethod(), getCallOptions(), request);
    }
  }

  /**
   * A stub to allow clients to do ListenableFuture-style rpc calls to service AttributesService.
   * <pre>
   *&#47;
   * / Attribute Service
   * /
   * </pre>
   */
  public static final class AttributesServiceFutureStub
      extends io.grpc.stub.AbstractFutureStub<AttributesServiceFutureStub> {
    private AttributesServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AttributesServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new AttributesServiceFutureStub(channel, callOptions);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute RPCs
     *---------------------------------------
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.ListAttributesResponse> listAttributes(
        io.opentdf.platform.policy.attributes.ListAttributesRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListAttributesMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.ListAttributeValuesResponse> listAttributeValues(
        io.opentdf.platform.policy.attributes.ListAttributeValuesRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListAttributeValuesMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.GetAttributeResponse> getAttribute(
        io.opentdf.platform.policy.attributes.GetAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetAttributeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse> getAttributesByValueFqns(
        io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetAttributesByValueFqnsMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.CreateAttributeResponse> createAttribute(
        io.opentdf.platform.policy.attributes.CreateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateAttributeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.UpdateAttributeResponse> updateAttribute(
        io.opentdf.platform.policy.attributes.UpdateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateAttributeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.DeactivateAttributeResponse> deactivateAttribute(
        io.opentdf.platform.policy.attributes.DeactivateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeactivateAttributeMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Value RPCs
     *---------------------------------------
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.GetAttributeValueResponse> getAttributeValue(
        io.opentdf.platform.policy.attributes.GetAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.CreateAttributeValueResponse> createAttributeValue(
        io.opentdf.platform.policy.attributes.CreateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse> updateAttributeValue(
        io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse> deactivateAttributeValue(
        io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeactivateAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *--------------------------------------*
     * Attribute &lt;&gt; Key Access Server RPCs
     *---------------------------------------
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse> assignKeyAccessServerToAttribute(
        io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getAssignKeyAccessServerToAttributeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> removeKeyAccessServerFromAttribute(
        io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getRemoveKeyAccessServerFromAttributeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse> assignKeyAccessServerToValue(
        io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getAssignKeyAccessServerToValueMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse> removeKeyAccessServerFromValue(
        io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getRemoveKeyAccessServerFromValueMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_LIST_ATTRIBUTES = 0;
  private static final int METHODID_LIST_ATTRIBUTE_VALUES = 1;
  private static final int METHODID_GET_ATTRIBUTE = 2;
  private static final int METHODID_GET_ATTRIBUTES_BY_VALUE_FQNS = 3;
  private static final int METHODID_CREATE_ATTRIBUTE = 4;
  private static final int METHODID_UPDATE_ATTRIBUTE = 5;
  private static final int METHODID_DEACTIVATE_ATTRIBUTE = 6;
  private static final int METHODID_GET_ATTRIBUTE_VALUE = 7;
  private static final int METHODID_CREATE_ATTRIBUTE_VALUE = 8;
  private static final int METHODID_UPDATE_ATTRIBUTE_VALUE = 9;
  private static final int METHODID_DEACTIVATE_ATTRIBUTE_VALUE = 10;
  private static final int METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_ATTRIBUTE = 11;
  private static final int METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_ATTRIBUTE = 12;
  private static final int METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_VALUE = 13;
  private static final int METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_VALUE = 14;

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
        case METHODID_LIST_ATTRIBUTES:
          serviceImpl.listAttributes((io.opentdf.platform.policy.attributes.ListAttributesRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.ListAttributesResponse>) responseObserver);
          break;
        case METHODID_LIST_ATTRIBUTE_VALUES:
          serviceImpl.listAttributeValues((io.opentdf.platform.policy.attributes.ListAttributeValuesRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.ListAttributeValuesResponse>) responseObserver);
          break;
        case METHODID_GET_ATTRIBUTE:
          serviceImpl.getAttribute((io.opentdf.platform.policy.attributes.GetAttributeRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.GetAttributeResponse>) responseObserver);
          break;
        case METHODID_GET_ATTRIBUTES_BY_VALUE_FQNS:
          serviceImpl.getAttributesByValueFqns((io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse>) responseObserver);
          break;
        case METHODID_CREATE_ATTRIBUTE:
          serviceImpl.createAttribute((io.opentdf.platform.policy.attributes.CreateAttributeRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.CreateAttributeResponse>) responseObserver);
          break;
        case METHODID_UPDATE_ATTRIBUTE:
          serviceImpl.updateAttribute((io.opentdf.platform.policy.attributes.UpdateAttributeRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.UpdateAttributeResponse>) responseObserver);
          break;
        case METHODID_DEACTIVATE_ATTRIBUTE:
          serviceImpl.deactivateAttribute((io.opentdf.platform.policy.attributes.DeactivateAttributeRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.DeactivateAttributeResponse>) responseObserver);
          break;
        case METHODID_GET_ATTRIBUTE_VALUE:
          serviceImpl.getAttributeValue((io.opentdf.platform.policy.attributes.GetAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.GetAttributeValueResponse>) responseObserver);
          break;
        case METHODID_CREATE_ATTRIBUTE_VALUE:
          serviceImpl.createAttributeValue((io.opentdf.platform.policy.attributes.CreateAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.CreateAttributeValueResponse>) responseObserver);
          break;
        case METHODID_UPDATE_ATTRIBUTE_VALUE:
          serviceImpl.updateAttributeValue((io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse>) responseObserver);
          break;
        case METHODID_DEACTIVATE_ATTRIBUTE_VALUE:
          serviceImpl.deactivateAttributeValue((io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse>) responseObserver);
          break;
        case METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_ATTRIBUTE:
          serviceImpl.assignKeyAccessServerToAttribute((io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse>) responseObserver);
          break;
        case METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_ATTRIBUTE:
          serviceImpl.removeKeyAccessServerFromAttribute((io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse>) responseObserver);
          break;
        case METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_VALUE:
          serviceImpl.assignKeyAccessServerToValue((io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse>) responseObserver);
          break;
        case METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_VALUE:
          serviceImpl.removeKeyAccessServerFromValue((io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest) request,
              (io.grpc.stub.StreamObserver<io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse>) responseObserver);
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
          getListAttributesMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.ListAttributesRequest,
              io.opentdf.platform.policy.attributes.ListAttributesResponse>(
                service, METHODID_LIST_ATTRIBUTES)))
        .addMethod(
          getListAttributeValuesMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.ListAttributeValuesRequest,
              io.opentdf.platform.policy.attributes.ListAttributeValuesResponse>(
                service, METHODID_LIST_ATTRIBUTE_VALUES)))
        .addMethod(
          getGetAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.GetAttributeRequest,
              io.opentdf.platform.policy.attributes.GetAttributeResponse>(
                service, METHODID_GET_ATTRIBUTE)))
        .addMethod(
          getGetAttributesByValueFqnsMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsRequest,
              io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse>(
                service, METHODID_GET_ATTRIBUTES_BY_VALUE_FQNS)))
        .addMethod(
          getCreateAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.CreateAttributeRequest,
              io.opentdf.platform.policy.attributes.CreateAttributeResponse>(
                service, METHODID_CREATE_ATTRIBUTE)))
        .addMethod(
          getUpdateAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.UpdateAttributeRequest,
              io.opentdf.platform.policy.attributes.UpdateAttributeResponse>(
                service, METHODID_UPDATE_ATTRIBUTE)))
        .addMethod(
          getDeactivateAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.DeactivateAttributeRequest,
              io.opentdf.platform.policy.attributes.DeactivateAttributeResponse>(
                service, METHODID_DEACTIVATE_ATTRIBUTE)))
        .addMethod(
          getGetAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.GetAttributeValueRequest,
              io.opentdf.platform.policy.attributes.GetAttributeValueResponse>(
                service, METHODID_GET_ATTRIBUTE_VALUE)))
        .addMethod(
          getCreateAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.CreateAttributeValueRequest,
              io.opentdf.platform.policy.attributes.CreateAttributeValueResponse>(
                service, METHODID_CREATE_ATTRIBUTE_VALUE)))
        .addMethod(
          getUpdateAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest,
              io.opentdf.platform.policy.attributes.UpdateAttributeValueResponse>(
                service, METHODID_UPDATE_ATTRIBUTE_VALUE)))
        .addMethod(
          getDeactivateAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.DeactivateAttributeValueRequest,
              io.opentdf.platform.policy.attributes.DeactivateAttributeValueResponse>(
                service, METHODID_DEACTIVATE_ATTRIBUTE_VALUE)))
        .addMethod(
          getAssignKeyAccessServerToAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeRequest,
              io.opentdf.platform.policy.attributes.AssignKeyAccessServerToAttributeResponse>(
                service, METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_ATTRIBUTE)))
        .addMethod(
          getRemoveKeyAccessServerFromAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeRequest,
              io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromAttributeResponse>(
                service, METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_ATTRIBUTE)))
        .addMethod(
          getAssignKeyAccessServerToValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueRequest,
              io.opentdf.platform.policy.attributes.AssignKeyAccessServerToValueResponse>(
                service, METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_VALUE)))
        .addMethod(
          getRemoveKeyAccessServerFromValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueRequest,
              io.opentdf.platform.policy.attributes.RemoveKeyAccessServerFromValueResponse>(
                service, METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_VALUE)))
        .build();
  }

  private static abstract class AttributesServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    AttributesServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return io.opentdf.platform.policy.attributes.AttributesProto.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("AttributesService");
    }
  }

  private static final class AttributesServiceFileDescriptorSupplier
      extends AttributesServiceBaseDescriptorSupplier {
    AttributesServiceFileDescriptorSupplier() {}
  }

  private static final class AttributesServiceMethodDescriptorSupplier
      extends AttributesServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final java.lang.String methodName;

    AttributesServiceMethodDescriptorSupplier(java.lang.String methodName) {
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
      synchronized (AttributesServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new AttributesServiceFileDescriptorSupplier())
              .addMethod(getListAttributesMethod())
              .addMethod(getListAttributeValuesMethod())
              .addMethod(getGetAttributeMethod())
              .addMethod(getGetAttributesByValueFqnsMethod())
              .addMethod(getCreateAttributeMethod())
              .addMethod(getUpdateAttributeMethod())
              .addMethod(getDeactivateAttributeMethod())
              .addMethod(getGetAttributeValueMethod())
              .addMethod(getCreateAttributeValueMethod())
              .addMethod(getUpdateAttributeValueMethod())
              .addMethod(getDeactivateAttributeValueMethod())
              .addMethod(getAssignKeyAccessServerToAttributeMethod())
              .addMethod(getRemoveKeyAccessServerFromAttributeMethod())
              .addMethod(getAssignKeyAccessServerToValueMethod())
              .addMethod(getRemoveKeyAccessServerFromValueMethod())
              .build();
        }
      }
    }
    return result;
  }
}
