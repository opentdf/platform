// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: attributes/attributes.proto

// Protobuf Java Version: 3.25.3
package com.attributes;

public interface AttributeOrBuilder extends
    // @@protoc_insertion_point(interface_extends:attributes.Attribute)
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
   * <pre>
   * Optional metadata for the attribute definition
   * </pre>
   *
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  boolean hasMetadata();
  /**
   * <pre>
   * Optional metadata for the attribute definition
   * </pre>
   *
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  com.common.Metadata getMetadata();
  /**
   * <pre>
   * Optional metadata for the attribute definition
   * </pre>
   *
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   */
  com.common.MetadataOrBuilder getMetadataOrBuilder();

  /**
   * <pre>
   * namespace of the attribute
   * </pre>
   *
   * <code>.namespaces.Namespace namespace = 3 [json_name = "namespace"];</code>
   * @return Whether the namespace field is set.
   */
  boolean hasNamespace();
  /**
   * <pre>
   * namespace of the attribute
   * </pre>
   *
   * <code>.namespaces.Namespace namespace = 3 [json_name = "namespace"];</code>
   * @return The namespace.
   */
  com.namespaces.Namespace getNamespace();
  /**
   * <pre>
   * namespace of the attribute
   * </pre>
   *
   * <code>.namespaces.Namespace namespace = 3 [json_name = "namespace"];</code>
   */
  com.namespaces.NamespaceOrBuilder getNamespaceOrBuilder();

  /**
   * <pre>
   *attribute name
   * </pre>
   *
   * <code>string name = 4 [json_name = "name"];</code>
   * @return The name.
   */
  java.lang.String getName();
  /**
   * <pre>
   *attribute name
   * </pre>
   *
   * <code>string name = 4 [json_name = "name"];</code>
   * @return The bytes for name.
   */
  com.google.protobuf.ByteString
      getNameBytes();

  /**
   * <pre>
   * attribute rule enum
   * </pre>
   *
   * <code>.attributes.AttributeRuleTypeEnum rule = 5 [json_name = "rule", (.buf.validate.field) = { ... }</code>
   * @return The enum numeric value on the wire for rule.
   */
  int getRuleValue();
  /**
   * <pre>
   * attribute rule enum
   * </pre>
   *
   * <code>.attributes.AttributeRuleTypeEnum rule = 5 [json_name = "rule", (.buf.validate.field) = { ... }</code>
   * @return The rule.
   */
  com.attributes.AttributeRuleTypeEnum getRule();

  /**
   * <code>repeated .attributes.Value values = 7 [json_name = "values"];</code>
   */
  java.util.List<com.attributes.Value> 
      getValuesList();
  /**
   * <code>repeated .attributes.Value values = 7 [json_name = "values"];</code>
   */
  com.attributes.Value getValues(int index);
  /**
   * <code>repeated .attributes.Value values = 7 [json_name = "values"];</code>
   */
  int getValuesCount();
  /**
   * <code>repeated .attributes.Value values = 7 [json_name = "values"];</code>
   */
  java.util.List<? extends com.attributes.ValueOrBuilder> 
      getValuesOrBuilderList();
  /**
   * <code>repeated .attributes.Value values = 7 [json_name = "values"];</code>
   */
  com.attributes.ValueOrBuilder getValuesOrBuilder(
      int index);

  /**
   * <code>repeated .kasregistry.KeyAccessServer grants = 8 [json_name = "grants"];</code>
   */
  java.util.List<com.kasregistry.KeyAccessServer> 
      getGrantsList();
  /**
   * <code>repeated .kasregistry.KeyAccessServer grants = 8 [json_name = "grants"];</code>
   */
  com.kasregistry.KeyAccessServer getGrants(int index);
  /**
   * <code>repeated .kasregistry.KeyAccessServer grants = 8 [json_name = "grants"];</code>
   */
  int getGrantsCount();
  /**
   * <code>repeated .kasregistry.KeyAccessServer grants = 8 [json_name = "grants"];</code>
   */
  java.util.List<? extends com.kasregistry.KeyAccessServerOrBuilder> 
      getGrantsOrBuilderList();
  /**
   * <code>repeated .kasregistry.KeyAccessServer grants = 8 [json_name = "grants"];</code>
   */
  com.kasregistry.KeyAccessServerOrBuilder getGrantsOrBuilder(
      int index);

  /**
   * <pre>
   * active by default until explicitly deactivated
   * </pre>
   *
   * <code>bool active = 9 [json_name = "active"];</code>
   * @return The active.
   */
  boolean getActive();
}
