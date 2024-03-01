// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

public interface SubjectConditionSetOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.subjectmapping.SubjectConditionSet)
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
   * an optional name for ease of reference
   * </pre>
   *
   * <code>string name = 2 [json_name = "name"];</code>
   * @return The name.
   */
  java.lang.String getName();
  /**
   * <pre>
   * an optional name for ease of reference
   * </pre>
   *
   * <code>string name = 2 [json_name = "name"];</code>
   * @return The bytes for name.
   */
  com.google.protobuf.ByteString
      getNameBytes();

  /**
   * <code>.common.Metadata metadata = 3 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  boolean hasMetadata();
  /**
   * <code>.common.Metadata metadata = 3 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  io.opentdf.platform.common.Metadata getMetadata();
  /**
   * <code>.common.Metadata metadata = 3 [json_name = "metadata"];</code>
   */
  io.opentdf.platform.common.MetadataOrBuilder getMetadataOrBuilder();

  /**
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 4 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  java.util.List<io.opentdf.platform.policy.subjectmapping.SubjectSet> 
      getSubjectSetsList();
  /**
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 4 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectSet getSubjectSets(int index);
  /**
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 4 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  int getSubjectSetsCount();
  /**
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 4 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  java.util.List<? extends io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder> 
      getSubjectSetsOrBuilderList();
  /**
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 4 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder getSubjectSetsOrBuilder(
      int index);
}
