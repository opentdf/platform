// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/objects.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy;

public interface SubjectMappingOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.SubjectMapping)
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
   * the Attribute Value mapped to; aka: "The Entity Entitlement Attribute"
   * </pre>
   *
   * <code>.policy.Value attribute_value = 2 [json_name = "attributeValue"];</code>
   * @return Whether the attributeValue field is set.
   */
  boolean hasAttributeValue();
  /**
   * <pre>
   * the Attribute Value mapped to; aka: "The Entity Entitlement Attribute"
   * </pre>
   *
   * <code>.policy.Value attribute_value = 2 [json_name = "attributeValue"];</code>
   * @return The attributeValue.
   */
  io.opentdf.platform.policy.Value getAttributeValue();
  /**
   * <pre>
   * the Attribute Value mapped to; aka: "The Entity Entitlement Attribute"
   * </pre>
   *
   * <code>.policy.Value attribute_value = 2 [json_name = "attributeValue"];</code>
   */
  io.opentdf.platform.policy.ValueOrBuilder getAttributeValueOrBuilder();

  /**
   * <pre>
   * the reusable SubjectConditionSet mapped to the given Attribute Value
   * </pre>
   *
   * <code>.policy.SubjectConditionSet subject_condition_set = 3 [json_name = "subjectConditionSet"];</code>
   * @return Whether the subjectConditionSet field is set.
   */
  boolean hasSubjectConditionSet();
  /**
   * <pre>
   * the reusable SubjectConditionSet mapped to the given Attribute Value
   * </pre>
   *
   * <code>.policy.SubjectConditionSet subject_condition_set = 3 [json_name = "subjectConditionSet"];</code>
   * @return The subjectConditionSet.
   */
  io.opentdf.platform.policy.SubjectConditionSet getSubjectConditionSet();
  /**
   * <pre>
   * the reusable SubjectConditionSet mapped to the given Attribute Value
   * </pre>
   *
   * <code>.policy.SubjectConditionSet subject_condition_set = 3 [json_name = "subjectConditionSet"];</code>
   */
  io.opentdf.platform.policy.SubjectConditionSetOrBuilder getSubjectConditionSetOrBuilder();

  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .policy.Action actions = 4 [json_name = "actions"];</code>
   */
  java.util.List<io.opentdf.platform.policy.Action> 
      getActionsList();
  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .policy.Action actions = 4 [json_name = "actions"];</code>
   */
  io.opentdf.platform.policy.Action getActions(int index);
  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .policy.Action actions = 4 [json_name = "actions"];</code>
   */
  int getActionsCount();
  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .policy.Action actions = 4 [json_name = "actions"];</code>
   */
  java.util.List<? extends io.opentdf.platform.policy.ActionOrBuilder> 
      getActionsOrBuilderList();
  /**
   * <pre>
   * The actions permitted by subjects in this mapping
   * </pre>
   *
   * <code>repeated .policy.Action actions = 4 [json_name = "actions"];</code>
   */
  io.opentdf.platform.policy.ActionOrBuilder getActionsOrBuilder(
      int index);

  /**
   * <code>.common.Metadata metadata = 100 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  boolean hasMetadata();
  /**
   * <code>.common.Metadata metadata = 100 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  io.opentdf.platform.common.Metadata getMetadata();
  /**
   * <code>.common.Metadata metadata = 100 [json_name = "metadata"];</code>
   */
  io.opentdf.platform.common.MetadataOrBuilder getMetadataOrBuilder();
}
