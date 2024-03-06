// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

public interface UpdateSubjectConditionSetRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.subjectmapping.UpdateSubjectConditionSetRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
   * @return The id.
   */
  java.lang.String getId();
  /**
   * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
   * @return The bytes for id.
   */
  com.google.protobuf.ByteString
      getIdBytes();

  /**
   * <code>.common.MetadataMutable update_metadata = 2 [json_name = "updateMetadata"];</code>
   * @return Whether the updateMetadata field is set.
   */
  boolean hasUpdateMetadata();
  /**
   * <code>.common.MetadataMutable update_metadata = 2 [json_name = "updateMetadata"];</code>
   * @return The updateMetadata.
   */
  io.opentdf.platform.common.MetadataMutable getUpdateMetadata();
  /**
   * <code>.common.MetadataMutable update_metadata = 2 [json_name = "updateMetadata"];</code>
   */
  io.opentdf.platform.common.MetadataMutableOrBuilder getUpdateMetadataOrBuilder();

  /**
   * <pre>
   * if provided, replaces entire existing structure of Subject Sets, Condition Groups, &amp; Conditions
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet update_subject_sets = 3 [json_name = "updateSubjectSets"];</code>
   */
  java.util.List<io.opentdf.platform.policy.subjectmapping.SubjectSet> 
      getUpdateSubjectSetsList();
  /**
   * <pre>
   * if provided, replaces entire existing structure of Subject Sets, Condition Groups, &amp; Conditions
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet update_subject_sets = 3 [json_name = "updateSubjectSets"];</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectSet getUpdateSubjectSets(int index);
  /**
   * <pre>
   * if provided, replaces entire existing structure of Subject Sets, Condition Groups, &amp; Conditions
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet update_subject_sets = 3 [json_name = "updateSubjectSets"];</code>
   */
  int getUpdateSubjectSetsCount();
  /**
   * <pre>
   * if provided, replaces entire existing structure of Subject Sets, Condition Groups, &amp; Conditions
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet update_subject_sets = 3 [json_name = "updateSubjectSets"];</code>
   */
  java.util.List<? extends io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder> 
      getUpdateSubjectSetsOrBuilderList();
  /**
   * <pre>
   * if provided, replaces entire existing structure of Subject Sets, Condition Groups, &amp; Conditions
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet update_subject_sets = 3 [json_name = "updateSubjectSets"];</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder getUpdateSubjectSetsOrBuilder(
      int index);
}
