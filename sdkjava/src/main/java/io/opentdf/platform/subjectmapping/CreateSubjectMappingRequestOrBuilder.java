// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.subjectmapping;

public interface CreateSubjectMappingRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:subjectmapping.CreateSubjectMappingRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
   * @return Whether the subjectMapping field is set.
   */
  boolean hasSubjectMapping();
  /**
   * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
   * @return The subjectMapping.
   */
  io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate getSubjectMapping();
  /**
   * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdateOrBuilder getSubjectMappingOrBuilder();
}
