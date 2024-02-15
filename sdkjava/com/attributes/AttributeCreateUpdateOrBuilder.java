// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: attributes/attributes.proto

// Protobuf Java Version: 3.25.2
package com.attributes;

public interface AttributeCreateUpdateOrBuilder extends
    // @@protoc_insertion_point(interface_extends:attributes.AttributeCreateUpdate)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * Optional metadata for the attribute definition
   * </pre>
   *
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  boolean hasMetadata();
  /**
   * <pre>
   * Optional metadata for the attribute definition
   * </pre>
   *
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  com.common.MetadataMutable getMetadata();
  /**
   * <pre>
   * Optional metadata for the attribute definition
   * </pre>
   *
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   */
  com.common.MetadataMutableOrBuilder getMetadataOrBuilder();

  /**
   * <pre>
   * namespace of the attribute
   * </pre>
   *
   * <code>string namespace_id = 2 [json_name = "namespaceId", (.buf.validate.field) = { ... }</code>
   * @return The namespaceId.
   */
  java.lang.String getNamespaceId();
  /**
   * <pre>
   * namespace of the attribute
   * </pre>
   *
   * <code>string namespace_id = 2 [json_name = "namespaceId", (.buf.validate.field) = { ... }</code>
   * @return The bytes for namespaceId.
   */
  com.google.protobuf.ByteString
      getNamespaceIdBytes();

  /**
   * <pre>
   *attribute name
   * </pre>
   *
   * <code>string name = 3 [json_name = "name", (.buf.validate.field) = { ... }</code>
   * @return The name.
   */
  java.lang.String getName();
  /**
   * <pre>
   *attribute name
   * </pre>
   *
   * <code>string name = 3 [json_name = "name", (.buf.validate.field) = { ... }</code>
   * @return The bytes for name.
   */
  com.google.protobuf.ByteString
      getNameBytes();

  /**
   * <pre>
   * attribute rule enum
   * </pre>
   *
   * <code>.attributes.AttributeRuleTypeEnum rule = 4 [json_name = "rule", (.buf.validate.field) = { ... }</code>
   * @return The enum numeric value on the wire for rule.
   */
  int getRuleValue();
  /**
   * <pre>
   * attribute rule enum
   * </pre>
   *
   * <code>.attributes.AttributeRuleTypeEnum rule = 4 [json_name = "rule", (.buf.validate.field) = { ... }</code>
   * @return The rule.
   */
  com.attributes.AttributeRuleTypeEnum getRule();

  /**
   * <pre>
   * optional
   * </pre>
   *
   * <code>repeated .attributes.ValueCreateUpdate values = 5 [json_name = "values"];</code>
   */
  java.util.List<com.attributes.ValueCreateUpdate> 
      getValuesList();
  /**
   * <pre>
   * optional
   * </pre>
   *
   * <code>repeated .attributes.ValueCreateUpdate values = 5 [json_name = "values"];</code>
   */
  com.attributes.ValueCreateUpdate getValues(int index);
  /**
   * <pre>
   * optional
   * </pre>
   *
   * <code>repeated .attributes.ValueCreateUpdate values = 5 [json_name = "values"];</code>
   */
  int getValuesCount();
  /**
   * <pre>
   * optional
   * </pre>
   *
   * <code>repeated .attributes.ValueCreateUpdate values = 5 [json_name = "values"];</code>
   */
  java.util.List<? extends com.attributes.ValueCreateUpdateOrBuilder> 
      getValuesOrBuilderList();
  /**
   * <pre>
   * optional
   * </pre>
   *
   * <code>repeated .attributes.ValueCreateUpdate values = 5 [json_name = "values"];</code>
   */
  com.attributes.ValueCreateUpdateOrBuilder getValuesOrBuilder(
      int index);

  /**
   * <code>string fqn = 6 [json_name = "fqn"];</code>
   * @return The fqn.
   */
  java.lang.String getFqn();
  /**
   * <code>string fqn = 6 [json_name = "fqn"];</code>
   * @return The bytes for fqn.
   */
  com.google.protobuf.ByteString
      getFqnBytes();
}
