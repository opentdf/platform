// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/attributes/attributes.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.attributes;

public interface AttributeAndValueOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.attributes.AttributeAndValue)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.policy.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
   * @return Whether the attribute field is set.
   */
  boolean hasAttribute();
  /**
   * <code>.policy.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
   * @return The attribute.
   */
  io.opentdf.platform.policy.attributes.Attribute getAttribute();
  /**
   * <code>.policy.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
   */
  io.opentdf.platform.policy.attributes.AttributeOrBuilder getAttributeOrBuilder();

  /**
   * <code>.policy.attributes.Value value = 2 [json_name = "value"];</code>
   * @return Whether the value field is set.
   */
  boolean hasValue();
  /**
   * <code>.policy.attributes.Value value = 2 [json_name = "value"];</code>
   * @return The value.
   */
  io.opentdf.platform.policy.attributes.Value getValue();
  /**
   * <code>.policy.attributes.Value value = 2 [json_name = "value"];</code>
   */
  io.opentdf.platform.policy.attributes.ValueOrBuilder getValueOrBuilder();
}
