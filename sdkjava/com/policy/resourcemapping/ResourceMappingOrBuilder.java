// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/resourcemapping/resource_mapping.proto

// Protobuf Java Version: 3.25.3
package com.policy.resourcemapping;

public interface ResourceMappingOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.resourcemapping.ResourceMapping)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string id = 1 [json_name = "id"];</code>
   * @return The id.
   */
  java.lang.String getId();
  /**
   * <code>string id = 1 [json_name = "id"];</code>
   * @return The bytes for id.
   */
  com.google.protobuf.ByteString
      getIdBytes();

  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  boolean hasMetadata();
  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  com.common.Metadata getMetadata();
  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   */
  com.common.MetadataOrBuilder getMetadataOrBuilder();

  /**
   * <code>.policy.attributes.Value attribute_value = 3 [json_name = "attributeValue", (.buf.validate.field) = { ... }</code>
   * @return Whether the attributeValue field is set.
   */
  boolean hasAttributeValue();
  /**
   * <code>.policy.attributes.Value attribute_value = 3 [json_name = "attributeValue", (.buf.validate.field) = { ... }</code>
   * @return The attributeValue.
   */
  com.policy.attributes.Value getAttributeValue();
  /**
   * <code>.policy.attributes.Value attribute_value = 3 [json_name = "attributeValue", (.buf.validate.field) = { ... }</code>
   */
  com.policy.attributes.ValueOrBuilder getAttributeValueOrBuilder();

  /**
   * <code>repeated string terms = 4 [json_name = "terms"];</code>
   * @return A list containing the terms.
   */
  java.util.List<java.lang.String>
      getTermsList();
  /**
   * <code>repeated string terms = 4 [json_name = "terms"];</code>
   * @return The count of terms.
   */
  int getTermsCount();
  /**
   * <code>repeated string terms = 4 [json_name = "terms"];</code>
   * @param index The index of the element to return.
   * @return The terms at the given index.
   */
  java.lang.String getTerms(int index);
  /**
   * <code>repeated string terms = 4 [json_name = "terms"];</code>
   * @param index The index of the value to return.
   * @return The bytes of the terms at the given index.
   */
  com.google.protobuf.ByteString
      getTermsBytes(int index);
}
