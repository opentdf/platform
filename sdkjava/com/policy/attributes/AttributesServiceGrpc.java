package com.policy.attributes;

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
  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.ListAttributesRequest,
      com.policy.attributes.ListAttributesResponse> getListAttributesMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListAttributes",
      requestType = com.policy.attributes.ListAttributesRequest.class,
      responseType = com.policy.attributes.ListAttributesResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.ListAttributesRequest,
      com.policy.attributes.ListAttributesResponse> getListAttributesMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.ListAttributesRequest, com.policy.attributes.ListAttributesResponse> getListAttributesMethod;
    if ((getListAttributesMethod = AttributesServiceGrpc.getListAttributesMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getListAttributesMethod = AttributesServiceGrpc.getListAttributesMethod) == null) {
          AttributesServiceGrpc.getListAttributesMethod = getListAttributesMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.ListAttributesRequest, com.policy.attributes.ListAttributesResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListAttributes"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.ListAttributesRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.ListAttributesResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("ListAttributes"))
              .build();
        }
      }
    }
    return getListAttributesMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.ListAttributeValuesRequest,
      com.policy.attributes.ListAttributeValuesResponse> getListAttributeValuesMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ListAttributeValues",
      requestType = com.policy.attributes.ListAttributeValuesRequest.class,
      responseType = com.policy.attributes.ListAttributeValuesResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.ListAttributeValuesRequest,
      com.policy.attributes.ListAttributeValuesResponse> getListAttributeValuesMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.ListAttributeValuesRequest, com.policy.attributes.ListAttributeValuesResponse> getListAttributeValuesMethod;
    if ((getListAttributeValuesMethod = AttributesServiceGrpc.getListAttributeValuesMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getListAttributeValuesMethod = AttributesServiceGrpc.getListAttributeValuesMethod) == null) {
          AttributesServiceGrpc.getListAttributeValuesMethod = getListAttributeValuesMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.ListAttributeValuesRequest, com.policy.attributes.ListAttributeValuesResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ListAttributeValues"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.ListAttributeValuesRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.ListAttributeValuesResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("ListAttributeValues"))
              .build();
        }
      }
    }
    return getListAttributeValuesMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.GetAttributeRequest,
      com.policy.attributes.GetAttributeResponse> getGetAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetAttribute",
      requestType = com.policy.attributes.GetAttributeRequest.class,
      responseType = com.policy.attributes.GetAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.GetAttributeRequest,
      com.policy.attributes.GetAttributeResponse> getGetAttributeMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.GetAttributeRequest, com.policy.attributes.GetAttributeResponse> getGetAttributeMethod;
    if ((getGetAttributeMethod = AttributesServiceGrpc.getGetAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getGetAttributeMethod = AttributesServiceGrpc.getGetAttributeMethod) == null) {
          AttributesServiceGrpc.getGetAttributeMethod = getGetAttributeMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.GetAttributeRequest, com.policy.attributes.GetAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.GetAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.GetAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("GetAttribute"))
              .build();
        }
      }
    }
    return getGetAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.CreateAttributeRequest,
      com.policy.attributes.CreateAttributeResponse> getCreateAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateAttribute",
      requestType = com.policy.attributes.CreateAttributeRequest.class,
      responseType = com.policy.attributes.CreateAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.CreateAttributeRequest,
      com.policy.attributes.CreateAttributeResponse> getCreateAttributeMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.CreateAttributeRequest, com.policy.attributes.CreateAttributeResponse> getCreateAttributeMethod;
    if ((getCreateAttributeMethod = AttributesServiceGrpc.getCreateAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getCreateAttributeMethod = AttributesServiceGrpc.getCreateAttributeMethod) == null) {
          AttributesServiceGrpc.getCreateAttributeMethod = getCreateAttributeMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.CreateAttributeRequest, com.policy.attributes.CreateAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.CreateAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.CreateAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("CreateAttribute"))
              .build();
        }
      }
    }
    return getCreateAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.UpdateAttributeRequest,
      com.policy.attributes.UpdateAttributeResponse> getUpdateAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateAttribute",
      requestType = com.policy.attributes.UpdateAttributeRequest.class,
      responseType = com.policy.attributes.UpdateAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.UpdateAttributeRequest,
      com.policy.attributes.UpdateAttributeResponse> getUpdateAttributeMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.UpdateAttributeRequest, com.policy.attributes.UpdateAttributeResponse> getUpdateAttributeMethod;
    if ((getUpdateAttributeMethod = AttributesServiceGrpc.getUpdateAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getUpdateAttributeMethod = AttributesServiceGrpc.getUpdateAttributeMethod) == null) {
          AttributesServiceGrpc.getUpdateAttributeMethod = getUpdateAttributeMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.UpdateAttributeRequest, com.policy.attributes.UpdateAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.UpdateAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.UpdateAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("UpdateAttribute"))
              .build();
        }
      }
    }
    return getUpdateAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.DeactivateAttributeRequest,
      com.policy.attributes.DeactivateAttributeResponse> getDeactivateAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeactivateAttribute",
      requestType = com.policy.attributes.DeactivateAttributeRequest.class,
      responseType = com.policy.attributes.DeactivateAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.DeactivateAttributeRequest,
      com.policy.attributes.DeactivateAttributeResponse> getDeactivateAttributeMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.DeactivateAttributeRequest, com.policy.attributes.DeactivateAttributeResponse> getDeactivateAttributeMethod;
    if ((getDeactivateAttributeMethod = AttributesServiceGrpc.getDeactivateAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getDeactivateAttributeMethod = AttributesServiceGrpc.getDeactivateAttributeMethod) == null) {
          AttributesServiceGrpc.getDeactivateAttributeMethod = getDeactivateAttributeMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.DeactivateAttributeRequest, com.policy.attributes.DeactivateAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeactivateAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.DeactivateAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.DeactivateAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("DeactivateAttribute"))
              .build();
        }
      }
    }
    return getDeactivateAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.GetAttributeValueRequest,
      com.policy.attributes.GetAttributeValueResponse> getGetAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetAttributeValue",
      requestType = com.policy.attributes.GetAttributeValueRequest.class,
      responseType = com.policy.attributes.GetAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.GetAttributeValueRequest,
      com.policy.attributes.GetAttributeValueResponse> getGetAttributeValueMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.GetAttributeValueRequest, com.policy.attributes.GetAttributeValueResponse> getGetAttributeValueMethod;
    if ((getGetAttributeValueMethod = AttributesServiceGrpc.getGetAttributeValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getGetAttributeValueMethod = AttributesServiceGrpc.getGetAttributeValueMethod) == null) {
          AttributesServiceGrpc.getGetAttributeValueMethod = getGetAttributeValueMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.GetAttributeValueRequest, com.policy.attributes.GetAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.GetAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.GetAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("GetAttributeValue"))
              .build();
        }
      }
    }
    return getGetAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.CreateAttributeValueRequest,
      com.policy.attributes.CreateAttributeValueResponse> getCreateAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CreateAttributeValue",
      requestType = com.policy.attributes.CreateAttributeValueRequest.class,
      responseType = com.policy.attributes.CreateAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.CreateAttributeValueRequest,
      com.policy.attributes.CreateAttributeValueResponse> getCreateAttributeValueMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.CreateAttributeValueRequest, com.policy.attributes.CreateAttributeValueResponse> getCreateAttributeValueMethod;
    if ((getCreateAttributeValueMethod = AttributesServiceGrpc.getCreateAttributeValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getCreateAttributeValueMethod = AttributesServiceGrpc.getCreateAttributeValueMethod) == null) {
          AttributesServiceGrpc.getCreateAttributeValueMethod = getCreateAttributeValueMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.CreateAttributeValueRequest, com.policy.attributes.CreateAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CreateAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.CreateAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.CreateAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("CreateAttributeValue"))
              .build();
        }
      }
    }
    return getCreateAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.UpdateAttributeValueRequest,
      com.policy.attributes.UpdateAttributeValueResponse> getUpdateAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "UpdateAttributeValue",
      requestType = com.policy.attributes.UpdateAttributeValueRequest.class,
      responseType = com.policy.attributes.UpdateAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.UpdateAttributeValueRequest,
      com.policy.attributes.UpdateAttributeValueResponse> getUpdateAttributeValueMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.UpdateAttributeValueRequest, com.policy.attributes.UpdateAttributeValueResponse> getUpdateAttributeValueMethod;
    if ((getUpdateAttributeValueMethod = AttributesServiceGrpc.getUpdateAttributeValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getUpdateAttributeValueMethod = AttributesServiceGrpc.getUpdateAttributeValueMethod) == null) {
          AttributesServiceGrpc.getUpdateAttributeValueMethod = getUpdateAttributeValueMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.UpdateAttributeValueRequest, com.policy.attributes.UpdateAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "UpdateAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.UpdateAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.UpdateAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("UpdateAttributeValue"))
              .build();
        }
      }
    }
    return getUpdateAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.DeactivateAttributeValueRequest,
      com.policy.attributes.DeactivateAttributeValueResponse> getDeactivateAttributeValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "DeactivateAttributeValue",
      requestType = com.policy.attributes.DeactivateAttributeValueRequest.class,
      responseType = com.policy.attributes.DeactivateAttributeValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.DeactivateAttributeValueRequest,
      com.policy.attributes.DeactivateAttributeValueResponse> getDeactivateAttributeValueMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.DeactivateAttributeValueRequest, com.policy.attributes.DeactivateAttributeValueResponse> getDeactivateAttributeValueMethod;
    if ((getDeactivateAttributeValueMethod = AttributesServiceGrpc.getDeactivateAttributeValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getDeactivateAttributeValueMethod = AttributesServiceGrpc.getDeactivateAttributeValueMethod) == null) {
          AttributesServiceGrpc.getDeactivateAttributeValueMethod = getDeactivateAttributeValueMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.DeactivateAttributeValueRequest, com.policy.attributes.DeactivateAttributeValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "DeactivateAttributeValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.DeactivateAttributeValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.DeactivateAttributeValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("DeactivateAttributeValue"))
              .build();
        }
      }
    }
    return getDeactivateAttributeValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.AssignKeyAccessServerToAttributeRequest,
      com.policy.attributes.AssignKeyAccessServerToAttributeResponse> getAssignKeyAccessServerToAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "AssignKeyAccessServerToAttribute",
      requestType = com.policy.attributes.AssignKeyAccessServerToAttributeRequest.class,
      responseType = com.policy.attributes.AssignKeyAccessServerToAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.AssignKeyAccessServerToAttributeRequest,
      com.policy.attributes.AssignKeyAccessServerToAttributeResponse> getAssignKeyAccessServerToAttributeMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.AssignKeyAccessServerToAttributeRequest, com.policy.attributes.AssignKeyAccessServerToAttributeResponse> getAssignKeyAccessServerToAttributeMethod;
    if ((getAssignKeyAccessServerToAttributeMethod = AttributesServiceGrpc.getAssignKeyAccessServerToAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getAssignKeyAccessServerToAttributeMethod = AttributesServiceGrpc.getAssignKeyAccessServerToAttributeMethod) == null) {
          AttributesServiceGrpc.getAssignKeyAccessServerToAttributeMethod = getAssignKeyAccessServerToAttributeMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.AssignKeyAccessServerToAttributeRequest, com.policy.attributes.AssignKeyAccessServerToAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "AssignKeyAccessServerToAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.AssignKeyAccessServerToAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.AssignKeyAccessServerToAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("AssignKeyAccessServerToAttribute"))
              .build();
        }
      }
    }
    return getAssignKeyAccessServerToAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest,
      com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> getRemoveKeyAccessServerFromAttributeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "RemoveKeyAccessServerFromAttribute",
      requestType = com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest.class,
      responseType = com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest,
      com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> getRemoveKeyAccessServerFromAttributeMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest, com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> getRemoveKeyAccessServerFromAttributeMethod;
    if ((getRemoveKeyAccessServerFromAttributeMethod = AttributesServiceGrpc.getRemoveKeyAccessServerFromAttributeMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getRemoveKeyAccessServerFromAttributeMethod = AttributesServiceGrpc.getRemoveKeyAccessServerFromAttributeMethod) == null) {
          AttributesServiceGrpc.getRemoveKeyAccessServerFromAttributeMethod = getRemoveKeyAccessServerFromAttributeMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest, com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "RemoveKeyAccessServerFromAttribute"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("RemoveKeyAccessServerFromAttribute"))
              .build();
        }
      }
    }
    return getRemoveKeyAccessServerFromAttributeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.AssignKeyAccessServerToValueRequest,
      com.policy.attributes.AssignKeyAccessServerToValueResponse> getAssignKeyAccessServerToValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "AssignKeyAccessServerToValue",
      requestType = com.policy.attributes.AssignKeyAccessServerToValueRequest.class,
      responseType = com.policy.attributes.AssignKeyAccessServerToValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.AssignKeyAccessServerToValueRequest,
      com.policy.attributes.AssignKeyAccessServerToValueResponse> getAssignKeyAccessServerToValueMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.AssignKeyAccessServerToValueRequest, com.policy.attributes.AssignKeyAccessServerToValueResponse> getAssignKeyAccessServerToValueMethod;
    if ((getAssignKeyAccessServerToValueMethod = AttributesServiceGrpc.getAssignKeyAccessServerToValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getAssignKeyAccessServerToValueMethod = AttributesServiceGrpc.getAssignKeyAccessServerToValueMethod) == null) {
          AttributesServiceGrpc.getAssignKeyAccessServerToValueMethod = getAssignKeyAccessServerToValueMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.AssignKeyAccessServerToValueRequest, com.policy.attributes.AssignKeyAccessServerToValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "AssignKeyAccessServerToValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.AssignKeyAccessServerToValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.AssignKeyAccessServerToValueResponse.getDefaultInstance()))
              .setSchemaDescriptor(new AttributesServiceMethodDescriptorSupplier("AssignKeyAccessServerToValue"))
              .build();
        }
      }
    }
    return getAssignKeyAccessServerToValueMethod;
  }

  private static volatile io.grpc.MethodDescriptor<com.policy.attributes.RemoveKeyAccessServerFromValueRequest,
      com.policy.attributes.RemoveKeyAccessServerFromValueResponse> getRemoveKeyAccessServerFromValueMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "RemoveKeyAccessServerFromValue",
      requestType = com.policy.attributes.RemoveKeyAccessServerFromValueRequest.class,
      responseType = com.policy.attributes.RemoveKeyAccessServerFromValueResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<com.policy.attributes.RemoveKeyAccessServerFromValueRequest,
      com.policy.attributes.RemoveKeyAccessServerFromValueResponse> getRemoveKeyAccessServerFromValueMethod() {
    io.grpc.MethodDescriptor<com.policy.attributes.RemoveKeyAccessServerFromValueRequest, com.policy.attributes.RemoveKeyAccessServerFromValueResponse> getRemoveKeyAccessServerFromValueMethod;
    if ((getRemoveKeyAccessServerFromValueMethod = AttributesServiceGrpc.getRemoveKeyAccessServerFromValueMethod) == null) {
      synchronized (AttributesServiceGrpc.class) {
        if ((getRemoveKeyAccessServerFromValueMethod = AttributesServiceGrpc.getRemoveKeyAccessServerFromValueMethod) == null) {
          AttributesServiceGrpc.getRemoveKeyAccessServerFromValueMethod = getRemoveKeyAccessServerFromValueMethod =
              io.grpc.MethodDescriptor.<com.policy.attributes.RemoveKeyAccessServerFromValueRequest, com.policy.attributes.RemoveKeyAccessServerFromValueResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "RemoveKeyAccessServerFromValue"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.RemoveKeyAccessServerFromValueRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  com.policy.attributes.RemoveKeyAccessServerFromValueResponse.getDefaultInstance()))
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
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *Request:
     *grpcurl -plaintext localhost:9000 policy.attributes.AttributesService/ListAttributes
     *OR (for inactive)
     *grpcurl -plaintext -d '{"state": "STATE_TYPE_ENUM_INACTIVE"}' localhost:9000 policy.attributes.AttributesService/ListAttributes
     *Response:
     *{
     *"attributes": [
     *{
     *"id": "attribute_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"namespace": {
     *"id": "namespace_id",
     *"name": "namespace_name"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"values": [
     *{
     *"id": "value_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"attribute_id": "attribute_id",
     *"value": "value",
     *"members": ["value_id"],
     *"grants": [
     *{
     *"id": "key_access_server_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"name": "key_access_server_name",
     *"description": "key_access_server_description",
     *}
     *],
     *}
     *],
     *"grants": [
     *{
     *"id": "key_access_server_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"name": "key_access_server_name",
     *"description": "key_access_server_description",
     *}
     *],
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    default void listAttributes(com.policy.attributes.ListAttributesRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.ListAttributesResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListAttributesMethod(), responseObserver);
    }

    /**
     * <pre>
     *List Values
     *Request:
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *grpcurl -plaintext -d '{"state": "STATE_TYPE_ENUM_INACTIVE"}' localhost:9000 policy.attributes.AttributesService/ListAttributes
     *Response:
     *{
     *"attributes": [
     *{
     *"id": "attribute_id",
     *"metadata": {
     *"createdAt": "2024-02-14T20:24:23.057404Z",
     *"updatedAt": "2024-02-14T20:24:23.057404Z"
     *},
     *"namespace": {
     *"id": "namespace_id",
     *"name": "namespace_name"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"values": [
     *{
     *... VALUES ...
     *}
     *],
     *"grants": [
     *{
     *... GRANTS ...
     *}
     *],
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    default void listAttributeValues(com.policy.attributes.ListAttributeValuesRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.ListAttributeValuesResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getListAttributeValuesMethod(), responseObserver);
    }

    /**
     */
    default void getAttribute(com.policy.attributes.GetAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.GetAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetAttributeMethod(), responseObserver);
    }

    /**
     * <pre>
     * Create Attribute
     *Request:
     *grpcurl -plaintext -d '{"attribute": {"namespace_id": "namespace_id", "name": "attribute_name", "rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF"}}' localhost:9000 policy.attributes.AttributesService/CreateAttribute
     *Response
     *{
     *"attribute": {
     *"id": "e06f067b-d158-44bc-a814-1aa3f968dcf0",
     *"metadata": {
     *"createdAt": "2024-02-14T20:24:23.057404Z",
     *"updatedAt": "2024-02-14T20:24:23.057404Z"
     *},
     *"namespace": {
     *"id": "namespace_id"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"active": true
     *}
     *}
     * </pre>
     */
    default void createAttribute(com.policy.attributes.CreateAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.CreateAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateAttributeMethod(), responseObserver);
    }

    /**
     */
    default void updateAttribute(com.policy.attributes.UpdateAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.UpdateAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateAttributeMethod(), responseObserver);
    }

    /**
     */
    default void deactivateAttribute(com.policy.attributes.DeactivateAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.DeactivateAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeactivateAttributeMethod(), responseObserver);
    }

    /**
     * <pre>
     ** Attribute Value *
     * </pre>
     */
    default void getAttributeValue(com.policy.attributes.GetAttributeValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.GetAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetAttributeValueMethod(), responseObserver);
    }

    /**
     * <pre>
     * Create Attribute Value
     * Example:
     *  grpcurl -plaintext -d '{"attribute_id": "attribute_id", "value": {"value": "value"}}' localhost:9000 policy.attributes.AttributesService/CreateAttributeValue
     * </pre>
     */
    default void createAttributeValue(com.policy.attributes.CreateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.CreateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCreateAttributeValueMethod(), responseObserver);
    }

    /**
     */
    default void updateAttributeValue(com.policy.attributes.UpdateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.UpdateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getUpdateAttributeValueMethod(), responseObserver);
    }

    /**
     */
    default void deactivateAttributeValue(com.policy.attributes.DeactivateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.DeactivateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getDeactivateAttributeValueMethod(), responseObserver);
    }

    /**
     * <pre>
     *Assign Key Access Server to Attribute
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/AssignKeyAccessServerToAttribute
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    default void assignKeyAccessServerToAttribute(com.policy.attributes.AssignKeyAccessServerToAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.AssignKeyAccessServerToAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getAssignKeyAccessServerToAttributeMethod(), responseObserver);
    }

    /**
     * <pre>
     *Remove Key Access Server to Attribute
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/RemeoveKeyAccessServerFromAttribute
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    default void removeKeyAccessServerFromAttribute(com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getRemoveKeyAccessServerFromAttributeMethod(), responseObserver);
    }

    /**
     * <pre>
     *Assign Key Access Server to Value
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/AssignKeyAccessServerToValue
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"value_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"value_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    default void assignKeyAccessServerToValue(com.policy.attributes.AssignKeyAccessServerToValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.AssignKeyAccessServerToValueResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getAssignKeyAccessServerToValueMethod(), responseObserver);
    }

    /**
     * <pre>
     *Remove Key Access Server to Value
     *grpcurl -plaintext -d '{"value_key_access_server": {"value_id": "value_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/RemoveKeyAccessServerFromValue
     *Example Request:
     *{
     *"value_key_access_server": {
     *"value_id": "value_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"value_key_access_server": {
     *"value_id": "value_id",
     *"key_access_server_id
     * </pre>
     */
    default void removeKeyAccessServerFromValue(com.policy.attributes.RemoveKeyAccessServerFromValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.RemoveKeyAccessServerFromValueResponse> responseObserver) {
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
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *Request:
     *grpcurl -plaintext localhost:9000 policy.attributes.AttributesService/ListAttributes
     *OR (for inactive)
     *grpcurl -plaintext -d '{"state": "STATE_TYPE_ENUM_INACTIVE"}' localhost:9000 policy.attributes.AttributesService/ListAttributes
     *Response:
     *{
     *"attributes": [
     *{
     *"id": "attribute_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"namespace": {
     *"id": "namespace_id",
     *"name": "namespace_name"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"values": [
     *{
     *"id": "value_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"attribute_id": "attribute_id",
     *"value": "value",
     *"members": ["value_id"],
     *"grants": [
     *{
     *"id": "key_access_server_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"name": "key_access_server_name",
     *"description": "key_access_server_description",
     *}
     *],
     *}
     *],
     *"grants": [
     *{
     *"id": "key_access_server_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"name": "key_access_server_name",
     *"description": "key_access_server_description",
     *}
     *],
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    public void listAttributes(com.policy.attributes.ListAttributesRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.ListAttributesResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListAttributesMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *List Values
     *Request:
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *grpcurl -plaintext -d '{"state": "STATE_TYPE_ENUM_INACTIVE"}' localhost:9000 policy.attributes.AttributesService/ListAttributes
     *Response:
     *{
     *"attributes": [
     *{
     *"id": "attribute_id",
     *"metadata": {
     *"createdAt": "2024-02-14T20:24:23.057404Z",
     *"updatedAt": "2024-02-14T20:24:23.057404Z"
     *},
     *"namespace": {
     *"id": "namespace_id",
     *"name": "namespace_name"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"values": [
     *{
     *... VALUES ...
     *}
     *],
     *"grants": [
     *{
     *... GRANTS ...
     *}
     *],
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    public void listAttributeValues(com.policy.attributes.ListAttributeValuesRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.ListAttributeValuesResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getListAttributeValuesMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getAttribute(com.policy.attributes.GetAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.GetAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Create Attribute
     *Request:
     *grpcurl -plaintext -d '{"attribute": {"namespace_id": "namespace_id", "name": "attribute_name", "rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF"}}' localhost:9000 policy.attributes.AttributesService/CreateAttribute
     *Response
     *{
     *"attribute": {
     *"id": "e06f067b-d158-44bc-a814-1aa3f968dcf0",
     *"metadata": {
     *"createdAt": "2024-02-14T20:24:23.057404Z",
     *"updatedAt": "2024-02-14T20:24:23.057404Z"
     *},
     *"namespace": {
     *"id": "namespace_id"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"active": true
     *}
     *}
     * </pre>
     */
    public void createAttribute(com.policy.attributes.CreateAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.CreateAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateAttribute(com.policy.attributes.UpdateAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.UpdateAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deactivateAttribute(com.policy.attributes.DeactivateAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.DeactivateAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeactivateAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     ** Attribute Value *
     * </pre>
     */
    public void getAttributeValue(com.policy.attributes.GetAttributeValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.GetAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * Create Attribute Value
     * Example:
     *  grpcurl -plaintext -d '{"attribute_id": "attribute_id", "value": {"value": "value"}}' localhost:9000 policy.attributes.AttributesService/CreateAttributeValue
     * </pre>
     */
    public void createAttributeValue(com.policy.attributes.CreateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.CreateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCreateAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void updateAttributeValue(com.policy.attributes.UpdateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.UpdateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getUpdateAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void deactivateAttributeValue(com.policy.attributes.DeactivateAttributeValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.DeactivateAttributeValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getDeactivateAttributeValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Assign Key Access Server to Attribute
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/AssignKeyAccessServerToAttribute
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    public void assignKeyAccessServerToAttribute(com.policy.attributes.AssignKeyAccessServerToAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.AssignKeyAccessServerToAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getAssignKeyAccessServerToAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Remove Key Access Server to Attribute
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/RemeoveKeyAccessServerFromAttribute
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    public void removeKeyAccessServerFromAttribute(com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getRemoveKeyAccessServerFromAttributeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Assign Key Access Server to Value
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/AssignKeyAccessServerToValue
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"value_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"value_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    public void assignKeyAccessServerToValue(com.policy.attributes.AssignKeyAccessServerToValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.AssignKeyAccessServerToValueResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getAssignKeyAccessServerToValueMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     *Remove Key Access Server to Value
     *grpcurl -plaintext -d '{"value_key_access_server": {"value_id": "value_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/RemoveKeyAccessServerFromValue
     *Example Request:
     *{
     *"value_key_access_server": {
     *"value_id": "value_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"value_key_access_server": {
     *"value_id": "value_id",
     *"key_access_server_id
     * </pre>
     */
    public void removeKeyAccessServerFromValue(com.policy.attributes.RemoveKeyAccessServerFromValueRequest request,
        io.grpc.stub.StreamObserver<com.policy.attributes.RemoveKeyAccessServerFromValueResponse> responseObserver) {
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
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *Request:
     *grpcurl -plaintext localhost:9000 policy.attributes.AttributesService/ListAttributes
     *OR (for inactive)
     *grpcurl -plaintext -d '{"state": "STATE_TYPE_ENUM_INACTIVE"}' localhost:9000 policy.attributes.AttributesService/ListAttributes
     *Response:
     *{
     *"attributes": [
     *{
     *"id": "attribute_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"namespace": {
     *"id": "namespace_id",
     *"name": "namespace_name"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"values": [
     *{
     *"id": "value_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"attribute_id": "attribute_id",
     *"value": "value",
     *"members": ["value_id"],
     *"grants": [
     *{
     *"id": "key_access_server_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"name": "key_access_server_name",
     *"description": "key_access_server_description",
     *}
     *],
     *}
     *],
     *"grants": [
     *{
     *"id": "key_access_server_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"name": "key_access_server_name",
     *"description": "key_access_server_description",
     *}
     *],
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    public com.policy.attributes.ListAttributesResponse listAttributes(com.policy.attributes.ListAttributesRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListAttributesMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *List Values
     *Request:
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *grpcurl -plaintext -d '{"state": "STATE_TYPE_ENUM_INACTIVE"}' localhost:9000 policy.attributes.AttributesService/ListAttributes
     *Response:
     *{
     *"attributes": [
     *{
     *"id": "attribute_id",
     *"metadata": {
     *"createdAt": "2024-02-14T20:24:23.057404Z",
     *"updatedAt": "2024-02-14T20:24:23.057404Z"
     *},
     *"namespace": {
     *"id": "namespace_id",
     *"name": "namespace_name"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"values": [
     *{
     *... VALUES ...
     *}
     *],
     *"grants": [
     *{
     *... GRANTS ...
     *}
     *],
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    public com.policy.attributes.ListAttributeValuesResponse listAttributeValues(com.policy.attributes.ListAttributeValuesRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getListAttributeValuesMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.attributes.GetAttributeResponse getAttribute(com.policy.attributes.GetAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetAttributeMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Create Attribute
     *Request:
     *grpcurl -plaintext -d '{"attribute": {"namespace_id": "namespace_id", "name": "attribute_name", "rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF"}}' localhost:9000 policy.attributes.AttributesService/CreateAttribute
     *Response
     *{
     *"attribute": {
     *"id": "e06f067b-d158-44bc-a814-1aa3f968dcf0",
     *"metadata": {
     *"createdAt": "2024-02-14T20:24:23.057404Z",
     *"updatedAt": "2024-02-14T20:24:23.057404Z"
     *},
     *"namespace": {
     *"id": "namespace_id"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"active": true
     *}
     *}
     * </pre>
     */
    public com.policy.attributes.CreateAttributeResponse createAttribute(com.policy.attributes.CreateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateAttributeMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.attributes.UpdateAttributeResponse updateAttribute(com.policy.attributes.UpdateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateAttributeMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.attributes.DeactivateAttributeResponse deactivateAttribute(com.policy.attributes.DeactivateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeactivateAttributeMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     ** Attribute Value *
     * </pre>
     */
    public com.policy.attributes.GetAttributeValueResponse getAttributeValue(com.policy.attributes.GetAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * Create Attribute Value
     * Example:
     *  grpcurl -plaintext -d '{"attribute_id": "attribute_id", "value": {"value": "value"}}' localhost:9000 policy.attributes.AttributesService/CreateAttributeValue
     * </pre>
     */
    public com.policy.attributes.CreateAttributeValueResponse createAttributeValue(com.policy.attributes.CreateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCreateAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.attributes.UpdateAttributeValueResponse updateAttributeValue(com.policy.attributes.UpdateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getUpdateAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     */
    public com.policy.attributes.DeactivateAttributeValueResponse deactivateAttributeValue(com.policy.attributes.DeactivateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getDeactivateAttributeValueMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Assign Key Access Server to Attribute
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/AssignKeyAccessServerToAttribute
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    public com.policy.attributes.AssignKeyAccessServerToAttributeResponse assignKeyAccessServerToAttribute(com.policy.attributes.AssignKeyAccessServerToAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getAssignKeyAccessServerToAttributeMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Remove Key Access Server to Attribute
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/RemeoveKeyAccessServerFromAttribute
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    public com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse removeKeyAccessServerFromAttribute(com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getRemoveKeyAccessServerFromAttributeMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Assign Key Access Server to Value
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/AssignKeyAccessServerToValue
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"value_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"value_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    public com.policy.attributes.AssignKeyAccessServerToValueResponse assignKeyAccessServerToValue(com.policy.attributes.AssignKeyAccessServerToValueRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getAssignKeyAccessServerToValueMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     *Remove Key Access Server to Value
     *grpcurl -plaintext -d '{"value_key_access_server": {"value_id": "value_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/RemoveKeyAccessServerFromValue
     *Example Request:
     *{
     *"value_key_access_server": {
     *"value_id": "value_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"value_key_access_server": {
     *"value_id": "value_id",
     *"key_access_server_id
     * </pre>
     */
    public com.policy.attributes.RemoveKeyAccessServerFromValueResponse removeKeyAccessServerFromValue(com.policy.attributes.RemoveKeyAccessServerFromValueRequest request) {
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
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *Request:
     *grpcurl -plaintext localhost:9000 policy.attributes.AttributesService/ListAttributes
     *OR (for inactive)
     *grpcurl -plaintext -d '{"state": "STATE_TYPE_ENUM_INACTIVE"}' localhost:9000 policy.attributes.AttributesService/ListAttributes
     *Response:
     *{
     *"attributes": [
     *{
     *"id": "attribute_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"namespace": {
     *"id": "namespace_id",
     *"name": "namespace_name"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"values": [
     *{
     *"id": "value_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"attribute_id": "attribute_id",
     *"value": "value",
     *"members": ["value_id"],
     *"grants": [
     *{
     *"id": "key_access_server_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"name": "key_access_server_name",
     *"description": "key_access_server_description",
     *}
     *],
     *}
     *],
     *"grants": [
     *{
     *"id": "key_access_server_id",
     *"metadata": {
     *"created_at": "2021-01-01T00:00:00Z",
     *"updated_at": "2021-01-01T00:00:00Z"
     *},
     *"name": "key_access_server_name",
     *"description": "key_access_server_description",
     *}
     *],
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.ListAttributesResponse> listAttributes(
        com.policy.attributes.ListAttributesRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListAttributesMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *List Values
     *Request:
     *NOTE: ACTIVE state by default, INACTIVE or ANY when specified
     *grpcurl -plaintext -d '{"state": "STATE_TYPE_ENUM_INACTIVE"}' localhost:9000 policy.attributes.AttributesService/ListAttributes
     *Response:
     *{
     *"attributes": [
     *{
     *"id": "attribute_id",
     *"metadata": {
     *"createdAt": "2024-02-14T20:24:23.057404Z",
     *"updatedAt": "2024-02-14T20:24:23.057404Z"
     *},
     *"namespace": {
     *"id": "namespace_id",
     *"name": "namespace_name"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"values": [
     *{
     *... VALUES ...
     *}
     *],
     *"grants": [
     *{
     *... GRANTS ...
     *}
     *],
     *"active": true
     *}
     *]
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.ListAttributeValuesResponse> listAttributeValues(
        com.policy.attributes.ListAttributeValuesRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getListAttributeValuesMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.GetAttributeResponse> getAttribute(
        com.policy.attributes.GetAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetAttributeMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Create Attribute
     *Request:
     *grpcurl -plaintext -d '{"attribute": {"namespace_id": "namespace_id", "name": "attribute_name", "rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF"}}' localhost:9000 policy.attributes.AttributesService/CreateAttribute
     *Response
     *{
     *"attribute": {
     *"id": "e06f067b-d158-44bc-a814-1aa3f968dcf0",
     *"metadata": {
     *"createdAt": "2024-02-14T20:24:23.057404Z",
     *"updatedAt": "2024-02-14T20:24:23.057404Z"
     *},
     *"namespace": {
     *"id": "namespace_id"
     *},
     *"name": "attribute_name",
     *"rule": "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
     *"active": true
     *}
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.CreateAttributeResponse> createAttribute(
        com.policy.attributes.CreateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateAttributeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.UpdateAttributeResponse> updateAttribute(
        com.policy.attributes.UpdateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateAttributeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.DeactivateAttributeResponse> deactivateAttribute(
        com.policy.attributes.DeactivateAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeactivateAttributeMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     ** Attribute Value *
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.GetAttributeValueResponse> getAttributeValue(
        com.policy.attributes.GetAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * Create Attribute Value
     * Example:
     *  grpcurl -plaintext -d '{"attribute_id": "attribute_id", "value": {"value": "value"}}' localhost:9000 policy.attributes.AttributesService/CreateAttributeValue
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.CreateAttributeValueResponse> createAttributeValue(
        com.policy.attributes.CreateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCreateAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.UpdateAttributeValueResponse> updateAttributeValue(
        com.policy.attributes.UpdateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getUpdateAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.DeactivateAttributeValueResponse> deactivateAttributeValue(
        com.policy.attributes.DeactivateAttributeValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getDeactivateAttributeValueMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Assign Key Access Server to Attribute
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/AssignKeyAccessServerToAttribute
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.AssignKeyAccessServerToAttributeResponse> assignKeyAccessServerToAttribute(
        com.policy.attributes.AssignKeyAccessServerToAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getAssignKeyAccessServerToAttributeMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Remove Key Access Server to Attribute
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/RemeoveKeyAccessServerFromAttribute
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"attribute_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse> removeKeyAccessServerFromAttribute(
        com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getRemoveKeyAccessServerFromAttributeMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Assign Key Access Server to Value
     *grpcurl -plaintext -d '{"attribute_key_access_server": {"attribute_id": "attribute_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/AssignKeyAccessServerToValue
     *Example Request:
     *{
     *"attribute_key_access_server": {
     *"value_id": "attribute_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"attribute_key_access_server": {
     *"value_id": "attribute_id",
     *"key_access_server_id: "key_access_server_id"
     *}
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.AssignKeyAccessServerToValueResponse> assignKeyAccessServerToValue(
        com.policy.attributes.AssignKeyAccessServerToValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getAssignKeyAccessServerToValueMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     *Remove Key Access Server to Value
     *grpcurl -plaintext -d '{"value_key_access_server": {"value_id": "value_id", "key_access_server_id": "key_access_server_id"}}' localhost:9000 policy.attributes.AttributesService/RemoveKeyAccessServerFromValue
     *Example Request:
     *{
     *"value_key_access_server": {
     *"value_id": "value_id",
     *"key_access_server_id
     *}
     *Example Response:
     *{
     *"value_key_access_server": {
     *"value_id": "value_id",
     *"key_access_server_id
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<com.policy.attributes.RemoveKeyAccessServerFromValueResponse> removeKeyAccessServerFromValue(
        com.policy.attributes.RemoveKeyAccessServerFromValueRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getRemoveKeyAccessServerFromValueMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_LIST_ATTRIBUTES = 0;
  private static final int METHODID_LIST_ATTRIBUTE_VALUES = 1;
  private static final int METHODID_GET_ATTRIBUTE = 2;
  private static final int METHODID_CREATE_ATTRIBUTE = 3;
  private static final int METHODID_UPDATE_ATTRIBUTE = 4;
  private static final int METHODID_DEACTIVATE_ATTRIBUTE = 5;
  private static final int METHODID_GET_ATTRIBUTE_VALUE = 6;
  private static final int METHODID_CREATE_ATTRIBUTE_VALUE = 7;
  private static final int METHODID_UPDATE_ATTRIBUTE_VALUE = 8;
  private static final int METHODID_DEACTIVATE_ATTRIBUTE_VALUE = 9;
  private static final int METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_ATTRIBUTE = 10;
  private static final int METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_ATTRIBUTE = 11;
  private static final int METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_VALUE = 12;
  private static final int METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_VALUE = 13;

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
          serviceImpl.listAttributes((com.policy.attributes.ListAttributesRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.ListAttributesResponse>) responseObserver);
          break;
        case METHODID_LIST_ATTRIBUTE_VALUES:
          serviceImpl.listAttributeValues((com.policy.attributes.ListAttributeValuesRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.ListAttributeValuesResponse>) responseObserver);
          break;
        case METHODID_GET_ATTRIBUTE:
          serviceImpl.getAttribute((com.policy.attributes.GetAttributeRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.GetAttributeResponse>) responseObserver);
          break;
        case METHODID_CREATE_ATTRIBUTE:
          serviceImpl.createAttribute((com.policy.attributes.CreateAttributeRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.CreateAttributeResponse>) responseObserver);
          break;
        case METHODID_UPDATE_ATTRIBUTE:
          serviceImpl.updateAttribute((com.policy.attributes.UpdateAttributeRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.UpdateAttributeResponse>) responseObserver);
          break;
        case METHODID_DEACTIVATE_ATTRIBUTE:
          serviceImpl.deactivateAttribute((com.policy.attributes.DeactivateAttributeRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.DeactivateAttributeResponse>) responseObserver);
          break;
        case METHODID_GET_ATTRIBUTE_VALUE:
          serviceImpl.getAttributeValue((com.policy.attributes.GetAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.GetAttributeValueResponse>) responseObserver);
          break;
        case METHODID_CREATE_ATTRIBUTE_VALUE:
          serviceImpl.createAttributeValue((com.policy.attributes.CreateAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.CreateAttributeValueResponse>) responseObserver);
          break;
        case METHODID_UPDATE_ATTRIBUTE_VALUE:
          serviceImpl.updateAttributeValue((com.policy.attributes.UpdateAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.UpdateAttributeValueResponse>) responseObserver);
          break;
        case METHODID_DEACTIVATE_ATTRIBUTE_VALUE:
          serviceImpl.deactivateAttributeValue((com.policy.attributes.DeactivateAttributeValueRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.DeactivateAttributeValueResponse>) responseObserver);
          break;
        case METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_ATTRIBUTE:
          serviceImpl.assignKeyAccessServerToAttribute((com.policy.attributes.AssignKeyAccessServerToAttributeRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.AssignKeyAccessServerToAttributeResponse>) responseObserver);
          break;
        case METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_ATTRIBUTE:
          serviceImpl.removeKeyAccessServerFromAttribute((com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse>) responseObserver);
          break;
        case METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_VALUE:
          serviceImpl.assignKeyAccessServerToValue((com.policy.attributes.AssignKeyAccessServerToValueRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.AssignKeyAccessServerToValueResponse>) responseObserver);
          break;
        case METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_VALUE:
          serviceImpl.removeKeyAccessServerFromValue((com.policy.attributes.RemoveKeyAccessServerFromValueRequest) request,
              (io.grpc.stub.StreamObserver<com.policy.attributes.RemoveKeyAccessServerFromValueResponse>) responseObserver);
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
              com.policy.attributes.ListAttributesRequest,
              com.policy.attributes.ListAttributesResponse>(
                service, METHODID_LIST_ATTRIBUTES)))
        .addMethod(
          getListAttributeValuesMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.ListAttributeValuesRequest,
              com.policy.attributes.ListAttributeValuesResponse>(
                service, METHODID_LIST_ATTRIBUTE_VALUES)))
        .addMethod(
          getGetAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.GetAttributeRequest,
              com.policy.attributes.GetAttributeResponse>(
                service, METHODID_GET_ATTRIBUTE)))
        .addMethod(
          getCreateAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.CreateAttributeRequest,
              com.policy.attributes.CreateAttributeResponse>(
                service, METHODID_CREATE_ATTRIBUTE)))
        .addMethod(
          getUpdateAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.UpdateAttributeRequest,
              com.policy.attributes.UpdateAttributeResponse>(
                service, METHODID_UPDATE_ATTRIBUTE)))
        .addMethod(
          getDeactivateAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.DeactivateAttributeRequest,
              com.policy.attributes.DeactivateAttributeResponse>(
                service, METHODID_DEACTIVATE_ATTRIBUTE)))
        .addMethod(
          getGetAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.GetAttributeValueRequest,
              com.policy.attributes.GetAttributeValueResponse>(
                service, METHODID_GET_ATTRIBUTE_VALUE)))
        .addMethod(
          getCreateAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.CreateAttributeValueRequest,
              com.policy.attributes.CreateAttributeValueResponse>(
                service, METHODID_CREATE_ATTRIBUTE_VALUE)))
        .addMethod(
          getUpdateAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.UpdateAttributeValueRequest,
              com.policy.attributes.UpdateAttributeValueResponse>(
                service, METHODID_UPDATE_ATTRIBUTE_VALUE)))
        .addMethod(
          getDeactivateAttributeValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.DeactivateAttributeValueRequest,
              com.policy.attributes.DeactivateAttributeValueResponse>(
                service, METHODID_DEACTIVATE_ATTRIBUTE_VALUE)))
        .addMethod(
          getAssignKeyAccessServerToAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.AssignKeyAccessServerToAttributeRequest,
              com.policy.attributes.AssignKeyAccessServerToAttributeResponse>(
                service, METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_ATTRIBUTE)))
        .addMethod(
          getRemoveKeyAccessServerFromAttributeMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.RemoveKeyAccessServerFromAttributeRequest,
              com.policy.attributes.RemoveKeyAccessServerFromAttributeResponse>(
                service, METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_ATTRIBUTE)))
        .addMethod(
          getAssignKeyAccessServerToValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.AssignKeyAccessServerToValueRequest,
              com.policy.attributes.AssignKeyAccessServerToValueResponse>(
                service, METHODID_ASSIGN_KEY_ACCESS_SERVER_TO_VALUE)))
        .addMethod(
          getRemoveKeyAccessServerFromValueMethod(),
          io.grpc.stub.ServerCalls.asyncUnaryCall(
            new MethodHandlers<
              com.policy.attributes.RemoveKeyAccessServerFromValueRequest,
              com.policy.attributes.RemoveKeyAccessServerFromValueResponse>(
                service, METHODID_REMOVE_KEY_ACCESS_SERVER_FROM_VALUE)))
        .build();
  }

  private static abstract class AttributesServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    AttributesServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return com.policy.attributes.AttributesProto.getDescriptor();
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
