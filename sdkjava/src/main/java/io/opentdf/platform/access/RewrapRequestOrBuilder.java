// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: kas/access/service.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.access;

public interface RewrapRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:access.RewrapRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string signed_request_token = 1 [json_name = "signedRequestToken"];</code>
   * @return The signedRequestToken.
   */
  java.lang.String getSignedRequestToken();
  /**
   * <code>string signed_request_token = 1 [json_name = "signedRequestToken"];</code>
   * @return The bytes for signedRequestToken.
   */
  com.google.protobuf.ByteString
      getSignedRequestTokenBytes();

  /**
   * <code>string bearer = 2 [json_name = "bearer"];</code>
   * @return The bearer.
   */
  java.lang.String getBearer();
  /**
   * <code>string bearer = 2 [json_name = "bearer"];</code>
   * @return The bytes for bearer.
   */
  com.google.protobuf.ByteString
      getBearerBytes();
}
