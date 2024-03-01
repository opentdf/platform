// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

public interface SubjectMappingOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.subjectmapping.SubjectMapping)
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
  io.opentdf.platform.common.Metadata getMetadata();
  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   */
  io.opentdf.platform.common.MetadataOrBuilder getMetadataOrBuilder();

  /**
   * <pre>
   * the Attribute Value mapped to; aka: "The Entity Entitlement Attribute"
   * </pre>
   *
   * <code>.policy.attributes.Value attribute_value = 3 [json_name = "attributeValue"];</code>
   * @return Whether the attributeValue field is set.
   */
  boolean hasAttributeValue();
  /**
   * <pre>
   * the Attribute Value mapped to; aka: "The Entity Entitlement Attribute"
   * </pre>
   *
   * <code>.policy.attributes.Value attribute_value = 3 [json_name = "attributeValue"];</code>
   * @return The attributeValue.
   */
  io.opentdf.platform.policy.attributes.Value getAttributeValue();
  /**
   * <pre>
   * the Attribute Value mapped to; aka: "The Entity Entitlement Attribute"
   * </pre>
   *
   * <code>.policy.attributes.Value attribute_value = 3 [json_name = "attributeValue"];</code>
   */
  io.opentdf.platform.policy.attributes.ValueOrBuilder getAttributeValueOrBuilder();

  /**
   * <pre>
   * the reusable SubjectConditionSets mapped to the given Attribute Value
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectConditionSet subject_condition_sets = 4 [json_name = "subjectConditionSets"];</code>
   */
  java.util.List<io.opentdf.platform.policy.subjectmapping.SubjectConditionSet> 
      getSubjectConditionSetsList();
  /**
   * <pre>
   * the reusable SubjectConditionSets mapped to the given Attribute Value
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectConditionSet subject_condition_sets = 4 [json_name = "subjectConditionSets"];</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectConditionSet getSubjectConditionSets(int index);
  /**
   * <pre>
   * the reusable SubjectConditionSets mapped to the given Attribute Value
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectConditionSet subject_condition_sets = 4 [json_name = "subjectConditionSets"];</code>
   */
  int getSubjectConditionSetsCount();
  /**
   * <pre>
   * the reusable SubjectConditionSets mapped to the given Attribute Value
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectConditionSet subject_condition_sets = 4 [json_name = "subjectConditionSets"];</code>
   */
  java.util.List<? extends io.opentdf.platform.policy.subjectmapping.SubjectConditionSetOrBuilder> 
      getSubjectConditionSetsOrBuilderList();
  /**
   * <pre>
   * the reusable SubjectConditionSets mapped to the given Attribute Value
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectConditionSet subject_condition_sets = 4 [json_name = "subjectConditionSets"];</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectConditionSetOrBuilder getSubjectConditionSetsOrBuilder(
      int index);

  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .authorization.Action actions = 5 [json_name = "actions"];</code>
   */
  java.util.List<io.opentdf.platform.authorization.Action> 
      getActionsList();
  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .authorization.Action actions = 5 [json_name = "actions"];</code>
   */
  io.opentdf.platform.authorization.Action getActions(int index);
  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .authorization.Action actions = 5 [json_name = "actions"];</code>
   */
  int getActionsCount();
  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .authorization.Action actions = 5 [json_name = "actions"];</code>
   */
  java.util.List<? extends io.opentdf.platform.authorization.ActionOrBuilder> 
      getActionsOrBuilderList();
  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .authorization.Action actions = 5 [json_name = "actions"];</code>
   */
  io.opentdf.platform.authorization.ActionOrBuilder getActionsOrBuilder(
      int index);
}
