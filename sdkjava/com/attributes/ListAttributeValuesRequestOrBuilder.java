// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: attributes/attributes.proto

// Protobuf Java Version: 3.25.2
package com.attributes;

public interface ListAttributeValuesRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:attributes.ListAttributeValuesRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string attribute_id = 1 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
   * @return The attributeId.
   */
  java.lang.String getAttributeId();
  /**
   * <code>string attribute_id = 1 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
   * @return The bytes for attributeId.
   */
  com.google.protobuf.ByteString
      getAttributeIdBytes();

  /**
   * <pre>
   * ACTIVE by default when not specified
   * </pre>
   *
   * <code>.common.ActiveStateEnum state = 2 [json_name = "state"];</code>
   * @return The enum numeric value on the wire for state.
   */
  int getStateValue();
  /**
   * <pre>
   * ACTIVE by default when not specified
   * </pre>
   *
   * <code>.common.ActiveStateEnum state = 2 [json_name = "state"];</code>
   * @return The state.
   */
  com.common.ActiveStateEnum getState();
}
