// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: opentdf/platform/attributes/attributes.proto

// Protobuf Java Version: 3.25.2
package io.opentdf.platform.attributes;

public interface UpdateAttributeResponseOrBuilder extends
    // @@protoc_insertion_point(interface_extends:opentdf.platform.attributes.UpdateAttributeResponse)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.opentdf.platform.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
   * @return Whether the attribute field is set.
   */
  boolean hasAttribute();
  /**
   * <code>.opentdf.platform.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
   * @return The attribute.
   */
  io.opentdf.platform.attributes.Attribute getAttribute();
  /**
   * <code>.opentdf.platform.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
   */
  io.opentdf.platform.attributes.AttributeOrBuilder getAttributeOrBuilder();
}
