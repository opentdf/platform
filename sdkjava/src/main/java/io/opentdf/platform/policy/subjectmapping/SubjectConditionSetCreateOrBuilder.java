// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

public interface SubjectConditionSetCreateOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.subjectmapping.SubjectConditionSetCreate)
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
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 3 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  java.util.List<io.opentdf.platform.policy.subjectmapping.SubjectSet> 
      getSubjectSetsList();
  /**
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 3 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectSet getSubjectSets(int index);
  /**
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 3 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  int getSubjectSetsCount();
  /**
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 3 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  java.util.List<? extends io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder> 
      getSubjectSetsOrBuilderList();
  /**
   * <pre>
   * multiple Subject Sets are evaluated with AND logic
   * </pre>
   *
   * <code>repeated .policy.subjectmapping.SubjectSet subject_sets = 3 [json_name = "subjectSets", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder getSubjectSetsOrBuilder(
      int index);
}
