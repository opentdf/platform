// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

public interface UpdateSubjectConditionSetResponseOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.subjectmapping.UpdateSubjectConditionSetResponse)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * Only ID of created Subject Condition Set provided
   * </pre>
   *
   * <code>.policy.subjectmapping.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
   * @return Whether the subjectConditionSet field is set.
   */
  boolean hasSubjectConditionSet();
  /**
   * <pre>
   * Only ID of created Subject Condition Set provided
   * </pre>
   *
   * <code>.policy.subjectmapping.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
   * @return The subjectConditionSet.
   */
  io.opentdf.platform.policy.subjectmapping.SubjectConditionSet getSubjectConditionSet();
  /**
   * <pre>
   * Only ID of created Subject Condition Set provided
   * </pre>
   *
   * <code>.policy.subjectmapping.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectConditionSetOrBuilder getSubjectConditionSetOrBuilder();
}
