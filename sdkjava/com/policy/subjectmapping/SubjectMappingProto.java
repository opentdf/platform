// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package com.policy.subjectmapping;

public final class SubjectMappingProto {
  private SubjectMappingProto() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_SubjectMapping_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_SubjectMapping_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_SubjectMappingCreateUpdate_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_SubjectMappingCreateUpdate_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_GetSubjectMappingRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_GetSubjectMappingRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_GetSubjectMappingResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_GetSubjectMappingResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_ListSubjectMappingsRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_ListSubjectMappingsRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_ListSubjectMappingsResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_ListSubjectMappingsResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_CreateSubjectMappingRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_CreateSubjectMappingRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_CreateSubjectMappingResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_CreateSubjectMappingResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_UpdateSubjectMappingRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_UpdateSubjectMappingRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_UpdateSubjectMappingResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_UpdateSubjectMappingResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_DeleteSubjectMappingRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_DeleteSubjectMappingRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_subjectmapping_DeleteSubjectMappingResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_subjectmapping_DeleteSubjectMappingResponse_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n+policy/subjectmapping/subject_mapping." +
      "proto\022\025policy.subjectmapping\032\"policy/att" +
      "ributes/attributes.proto\032\033buf/validate/v" +
      "alidate.proto\032\023common/common.proto\032\034goog" +
      "le/api/annotations.proto\"\301\002\n\016SubjectMapp" +
      "ing\022\016\n\002id\030\001 \001(\tR\002id\022,\n\010metadata\030\002 \001(\0132\020." +
      "common.MetadataR\010metadata\022A\n\017attribute_v" +
      "alue\030\003 \001(\0132\030.policy.attributes.ValueR\016at" +
      "tributeValue\022+\n\021subject_attribute\030\004 \001(\tR" +
      "\020subjectAttribute\022%\n\016subject_values\030\005 \003(" +
      "\tR\rsubjectValues\022Z\n\010operator\030\006 \001(\01621.pol" +
      "icy.subjectmapping.SubjectMappingOperato" +
      "rEnumB\013\272H\010\202\001\002\020\001\310\001\001R\010operator\"\257\002\n\032Subject" +
      "MappingCreateUpdate\0223\n\010metadata\030\001 \001(\0132\027." +
      "common.MetadataMutableR\010metadata\022,\n\022attr" +
      "ibute_value_id\030\002 \001(\tR\020attributeValueId\022+" +
      "\n\021subject_attribute\030\003 \001(\tR\020subjectAttrib" +
      "ute\022%\n\016subject_values\030\004 \003(\tR\rsubjectValu" +
      "es\022Z\n\010operator\030\005 \001(\01621.policy.subjectmap" +
      "ping.SubjectMappingOperatorEnumB\013\272H\010\202\001\002\020" +
      "\001\310\001\001R\010operator\"2\n\030GetSubjectMappingReque" +
      "st\022\026\n\002id\030\001 \001(\tB\006\272H\003\310\001\001R\002id\"k\n\031GetSubject" +
      "MappingResponse\022N\n\017subject_mapping\030\001 \001(\013" +
      "2%.policy.subjectmapping.SubjectMappingR" +
      "\016subjectMapping\"\034\n\032ListSubjectMappingsRe" +
      "quest\"o\n\033ListSubjectMappingsResponse\022P\n\020" +
      "subject_mappings\030\001 \003(\0132%.policy.subjectm" +
      "apping.SubjectMappingR\017subjectMappings\"\201" +
      "\001\n\033CreateSubjectMappingRequest\022b\n\017subjec" +
      "t_mapping\030\001 \001(\01321.policy.subjectmapping." +
      "SubjectMappingCreateUpdateB\006\272H\003\310\001\001R\016subj" +
      "ectMapping\"n\n\034CreateSubjectMappingRespon" +
      "se\022N\n\017subject_mapping\030\001 \001(\0132%.policy.sub" +
      "jectmapping.SubjectMappingR\016subjectMappi" +
      "ng\"\231\001\n\033UpdateSubjectMappingRequest\022\026\n\002id" +
      "\030\001 \001(\tB\006\272H\003\310\001\001R\002id\022b\n\017subject_mapping\030\002 " +
      "\001(\01321.policy.subjectmapping.SubjectMappi" +
      "ngCreateUpdateB\006\272H\003\310\001\001R\016subjectMapping\"n" +
      "\n\034UpdateSubjectMappingResponse\022N\n\017subjec" +
      "t_mapping\030\001 \001(\0132%.policy.subjectmapping." +
      "SubjectMappingR\016subjectMapping\"5\n\033Delete" +
      "SubjectMappingRequest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310\001" +
      "\001R\002id\"n\n\034DeleteSubjectMappingResponse\022N\n" +
      "\017subject_mapping\030\001 \001(\0132%.policy.subjectm" +
      "apping.SubjectMappingR\016subjectMapping*\233\001" +
      "\n\032SubjectMappingOperatorEnum\022-\n)SUBJECT_" +
      "MAPPING_OPERATOR_ENUM_UNSPECIFIED\020\000\022$\n S" +
      "UBJECT_MAPPING_OPERATOR_ENUM_IN\020\001\022(\n$SUB" +
      "JECT_MAPPING_OPERATOR_ENUM_NOT_IN\020\0022\315\006\n\025" +
      "SubjectMappingService\022\227\001\n\023ListSubjectMap" +
      "pings\0221.policy.subjectmapping.ListSubjec" +
      "tMappingsRequest\0322.policy.subjectmapping" +
      ".ListSubjectMappingsResponse\"\031\202\323\344\223\002\023\022\021/s" +
      "ubject-mappings\022\226\001\n\021GetSubjectMapping\022/." +
      "policy.subjectmapping.GetSubjectMappingR" +
      "equest\0320.policy.subjectmapping.GetSubjec" +
      "tMappingResponse\"\036\202\323\344\223\002\030\022\026/subject-mappi" +
      "ngs/{id}\022\253\001\n\024CreateSubjectMapping\0222.poli" +
      "cy.subjectmapping.CreateSubjectMappingRe" +
      "quest\0323.policy.subjectmapping.CreateSubj" +
      "ectMappingResponse\"*\202\323\344\223\002$\"\021/subject-map" +
      "pings:\017subject_mapping\022\260\001\n\024UpdateSubject" +
      "Mapping\0222.policy.subjectmapping.UpdateSu" +
      "bjectMappingRequest\0323.policy.subjectmapp" +
      "ing.UpdateSubjectMappingResponse\"/\202\323\344\223\002)" +
      "\"\026/subject-mappings/{id}:\017subject_mappin" +
      "g\022\237\001\n\024DeleteSubjectMapping\0222.policy.subj" +
      "ectmapping.DeleteSubjectMappingRequest\0323" +
      ".policy.subjectmapping.DeleteSubjectMapp" +
      "ingResponse\"\036\202\323\344\223\002\030*\026/subject-mappings/{" +
      "id}B\352\001\n\031com.policy.subjectmappingB\023Subje" +
      "ctMappingProtoP\001ZCgithub.com/opentdf/ope" +
      "ntdf-v2-poc/protocol/go/policy/subjectma" +
      "pping\242\002\003PSX\252\002\025Policy.Subjectmapping\312\002\025Po" +
      "licy\\Subjectmapping\342\002!Policy\\Subjectmapp" +
      "ing\\GPBMetadata\352\002\026Policy::Subjectmapping" +
      "b\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          com.policy.attributes.AttributesProto.getDescriptor(),
          com.buf.validate.ValidateProto.getDescriptor(),
          com.common.CommonProto.getDescriptor(),
          com.google.api.AnnotationsProto.getDescriptor(),
        });
    internal_static_policy_subjectmapping_SubjectMapping_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_policy_subjectmapping_SubjectMapping_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_SubjectMapping_descriptor,
        new java.lang.String[] { "Id", "Metadata", "AttributeValue", "SubjectAttribute", "SubjectValues", "Operator", });
    internal_static_policy_subjectmapping_SubjectMappingCreateUpdate_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_policy_subjectmapping_SubjectMappingCreateUpdate_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_SubjectMappingCreateUpdate_descriptor,
        new java.lang.String[] { "Metadata", "AttributeValueId", "SubjectAttribute", "SubjectValues", "Operator", });
    internal_static_policy_subjectmapping_GetSubjectMappingRequest_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_policy_subjectmapping_GetSubjectMappingRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_GetSubjectMappingRequest_descriptor,
        new java.lang.String[] { "Id", });
    internal_static_policy_subjectmapping_GetSubjectMappingResponse_descriptor =
      getDescriptor().getMessageTypes().get(3);
    internal_static_policy_subjectmapping_GetSubjectMappingResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_GetSubjectMappingResponse_descriptor,
        new java.lang.String[] { "SubjectMapping", });
    internal_static_policy_subjectmapping_ListSubjectMappingsRequest_descriptor =
      getDescriptor().getMessageTypes().get(4);
    internal_static_policy_subjectmapping_ListSubjectMappingsRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_ListSubjectMappingsRequest_descriptor,
        new java.lang.String[] { });
    internal_static_policy_subjectmapping_ListSubjectMappingsResponse_descriptor =
      getDescriptor().getMessageTypes().get(5);
    internal_static_policy_subjectmapping_ListSubjectMappingsResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_ListSubjectMappingsResponse_descriptor,
        new java.lang.String[] { "SubjectMappings", });
    internal_static_policy_subjectmapping_CreateSubjectMappingRequest_descriptor =
      getDescriptor().getMessageTypes().get(6);
    internal_static_policy_subjectmapping_CreateSubjectMappingRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_CreateSubjectMappingRequest_descriptor,
        new java.lang.String[] { "SubjectMapping", });
    internal_static_policy_subjectmapping_CreateSubjectMappingResponse_descriptor =
      getDescriptor().getMessageTypes().get(7);
    internal_static_policy_subjectmapping_CreateSubjectMappingResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_CreateSubjectMappingResponse_descriptor,
        new java.lang.String[] { "SubjectMapping", });
    internal_static_policy_subjectmapping_UpdateSubjectMappingRequest_descriptor =
      getDescriptor().getMessageTypes().get(8);
    internal_static_policy_subjectmapping_UpdateSubjectMappingRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_UpdateSubjectMappingRequest_descriptor,
        new java.lang.String[] { "Id", "SubjectMapping", });
    internal_static_policy_subjectmapping_UpdateSubjectMappingResponse_descriptor =
      getDescriptor().getMessageTypes().get(9);
    internal_static_policy_subjectmapping_UpdateSubjectMappingResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_UpdateSubjectMappingResponse_descriptor,
        new java.lang.String[] { "SubjectMapping", });
    internal_static_policy_subjectmapping_DeleteSubjectMappingRequest_descriptor =
      getDescriptor().getMessageTypes().get(10);
    internal_static_policy_subjectmapping_DeleteSubjectMappingRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_DeleteSubjectMappingRequest_descriptor,
        new java.lang.String[] { "Id", });
    internal_static_policy_subjectmapping_DeleteSubjectMappingResponse_descriptor =
      getDescriptor().getMessageTypes().get(11);
    internal_static_policy_subjectmapping_DeleteSubjectMappingResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_subjectmapping_DeleteSubjectMappingResponse_descriptor,
        new java.lang.String[] { "SubjectMapping", });
    com.google.protobuf.ExtensionRegistry registry =
        com.google.protobuf.ExtensionRegistry.newInstance();
    registry.add(com.buf.validate.ValidateProto.field);
    registry.add(com.google.api.AnnotationsProto.http);
    com.google.protobuf.Descriptors.FileDescriptor
        .internalUpdateFileDescriptor(descriptor, registry);
    com.policy.attributes.AttributesProto.getDescriptor();
    com.buf.validate.ValidateProto.getDescriptor();
    com.common.CommonProto.getDescriptor();
    com.google.api.AnnotationsProto.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
