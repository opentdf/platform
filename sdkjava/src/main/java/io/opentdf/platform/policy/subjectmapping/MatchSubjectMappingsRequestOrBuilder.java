// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

public interface MatchSubjectMappingsRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.subjectmapping.MatchSubjectMappingsRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.policy.subjectmapping.Subject subject = 1 [json_name = "subject"];</code>
   * @return Whether the subject field is set.
   */
  boolean hasSubject();
  /**
   * <code>.policy.subjectmapping.Subject subject = 1 [json_name = "subject"];</code>
   * @return The subject.
   */
  io.opentdf.platform.policy.subjectmapping.Subject getSubject();
  /**
   * <code>.policy.subjectmapping.Subject subject = 1 [json_name = "subject"];</code>
   */
  io.opentdf.platform.policy.subjectmapping.SubjectOrBuilder getSubjectOrBuilder();
}
