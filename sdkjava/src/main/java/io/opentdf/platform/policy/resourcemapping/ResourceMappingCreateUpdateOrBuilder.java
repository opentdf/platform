// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/resourcemapping/resource_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.resourcemapping;

public interface ResourceMappingCreateUpdateOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.resourcemapping.ResourceMappingCreateUpdate)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  boolean hasMetadata();
  /**
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  io.opentdf.platform.common.MetadataMutable getMetadata();
  /**
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   */
  io.opentdf.platform.common.MetadataMutableOrBuilder getMetadataOrBuilder();

  /**
   * <code>string attribute_value_id = 2 [json_name = "attributeValueId"];</code>
   * @return The attributeValueId.
   */
  java.lang.String getAttributeValueId();
  /**
   * <code>string attribute_value_id = 2 [json_name = "attributeValueId"];</code>
   * @return The bytes for attributeValueId.
   */
  com.google.protobuf.ByteString
      getAttributeValueIdBytes();

  /**
   * <code>repeated string terms = 3 [json_name = "terms"];</code>
   * @return A list containing the terms.
   */
  java.util.List<java.lang.String>
      getTermsList();
  /**
   * <code>repeated string terms = 3 [json_name = "terms"];</code>
   * @return The count of terms.
   */
  int getTermsCount();
  /**
   * <code>repeated string terms = 3 [json_name = "terms"];</code>
   * @param index The index of the element to return.
   * @return The terms at the given index.
   */
  java.lang.String getTerms(int index);
  /**
   * <code>repeated string terms = 3 [json_name = "terms"];</code>
   * @param index The index of the value to return.
   * @return The bytes of the terms at the given index.
   */
  com.google.protobuf.ByteString
      getTermsBytes(int index);
}
