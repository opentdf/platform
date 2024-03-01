// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

public interface SubjectMappingUpdateOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.subjectmapping.SubjectMappingUpdate)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.common.MetadataMutable updated_metadata = 2 [json_name = "updatedMetadata"];</code>
   * @return Whether the updatedMetadata field is set.
   */
  boolean hasUpdatedMetadata();
  /**
   * <code>.common.MetadataMutable updated_metadata = 2 [json_name = "updatedMetadata"];</code>
   * @return The updatedMetadata.
   */
  io.opentdf.platform.common.MetadataMutable getUpdatedMetadata();
  /**
   * <code>.common.MetadataMutable updated_metadata = 2 [json_name = "updatedMetadata"];</code>
   */
  io.opentdf.platform.common.MetadataMutableOrBuilder getUpdatedMetadataOrBuilder();

  /**
   * <pre>
   * Replaces entire list of existing SubjectConditionSet ids
   * </pre>
   *
   * <code>repeated string updated_subject_condition_set_ids = 3 [json_name = "updatedSubjectConditionSetIds"];</code>
   * @return A list containing the updatedSubjectConditionSetIds.
   */
  java.util.List<java.lang.String>
      getUpdatedSubjectConditionSetIdsList();
  /**
   * <pre>
   * Replaces entire list of existing SubjectConditionSet ids
   * </pre>
   *
   * <code>repeated string updated_subject_condition_set_ids = 3 [json_name = "updatedSubjectConditionSetIds"];</code>
   * @return The count of updatedSubjectConditionSetIds.
   */
  int getUpdatedSubjectConditionSetIdsCount();
  /**
   * <pre>
   * Replaces entire list of existing SubjectConditionSet ids
   * </pre>
   *
   * <code>repeated string updated_subject_condition_set_ids = 3 [json_name = "updatedSubjectConditionSetIds"];</code>
   * @param index The index of the element to return.
   * @return The updatedSubjectConditionSetIds at the given index.
   */
  java.lang.String getUpdatedSubjectConditionSetIds(int index);
  /**
   * <pre>
   * Replaces entire list of existing SubjectConditionSet ids
   * </pre>
   *
   * <code>repeated string updated_subject_condition_set_ids = 3 [json_name = "updatedSubjectConditionSetIds"];</code>
   * @param index The index of the value to return.
   * @return The bytes of the updatedSubjectConditionSetIds at the given index.
   */
  com.google.protobuf.ByteString
      getUpdatedSubjectConditionSetIdsBytes(int index);

  /**
   * <pre>
   * Replaces entire list of actions permitted by subjects
   * </pre>
   *
   * <code>repeated .authorization.Action udpated_actions = 5 [json_name = "udpatedActions"];</code>
   */
  java.util.List<io.opentdf.platform.authorization.Action> 
      getUdpatedActionsList();
  /**
   * <pre>
   * Replaces entire list of actions permitted by subjects
   * </pre>
   *
   * <code>repeated .authorization.Action udpated_actions = 5 [json_name = "udpatedActions"];</code>
   */
  io.opentdf.platform.authorization.Action getUdpatedActions(int index);
  /**
   * <pre>
   * Replaces entire list of actions permitted by subjects
   * </pre>
   *
   * <code>repeated .authorization.Action udpated_actions = 5 [json_name = "udpatedActions"];</code>
   */
  int getUdpatedActionsCount();
  /**
   * <pre>
   * Replaces entire list of actions permitted by subjects
   * </pre>
   *
   * <code>repeated .authorization.Action udpated_actions = 5 [json_name = "udpatedActions"];</code>
   */
  java.util.List<? extends io.opentdf.platform.authorization.ActionOrBuilder> 
      getUdpatedActionsOrBuilderList();
  /**
   * <pre>
   * Replaces entire list of actions permitted by subjects
   * </pre>
   *
   * <code>repeated .authorization.Action udpated_actions = 5 [json_name = "udpatedActions"];</code>
   */
  io.opentdf.platform.authorization.ActionOrBuilder getUdpatedActionsOrBuilder(
      int index);
}
