// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: common/common.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.common;

public final class CommonProto {
  private CommonProto() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_common_Metadata_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_common_Metadata_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_common_Metadata_LabelsEntry_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_common_Metadata_LabelsEntry_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_common_MetadataMutable_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_common_MetadataMutable_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_common_MetadataMutable_LabelsEntry_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_common_MetadataMutable_LabelsEntry_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\023common/common.proto\022\006common\032\037google/pr" +
      "otobuf/timestamp.proto\"\223\002\n\010Metadata\0229\n\nc" +
      "reated_at\030\001 \001(\0132\032.google.protobuf.Timest" +
      "ampR\tcreatedAt\0229\n\nupdated_at\030\002 \001(\0132\032.goo" +
      "gle.protobuf.TimestampR\tupdatedAt\0224\n\006lab" +
      "els\030\003 \003(\0132\034.common.Metadata.LabelsEntryR" +
      "\006labels\022 \n\013description\030\004 \001(\tR\013descriptio" +
      "n\0329\n\013LabelsEntry\022\020\n\003key\030\001 \001(\tR\003key\022\024\n\005va" +
      "lue\030\002 \001(\tR\005value:\0028\001\"\253\001\n\017MetadataMutable" +
      "\022;\n\006labels\030\003 \003(\0132#.common.MetadataMutabl" +
      "e.LabelsEntryR\006labels\022 \n\013description\030\004 \001" +
      "(\tR\013description\0329\n\013LabelsEntry\022\020\n\003key\030\001 " +
      "\001(\tR\003key\022\024\n\005value\030\002 \001(\tR\005value:\0028\001*\215\001\n\017A" +
      "ctiveStateEnum\022!\n\035ACTIVE_STATE_ENUM_UNSP" +
      "ECIFIED\020\000\022\034\n\030ACTIVE_STATE_ENUM_ACTIVE\020\001\022" +
      "\036\n\032ACTIVE_STATE_ENUM_INACTIVE\020\002\022\031\n\025ACTIV" +
      "E_STATE_ENUM_ANY\020\003B\221\001\n\032io.opentdf.platfo" +
      "rm.commonB\013CommonProtoP\001Z.github.com/ope" +
      "ntdf/platform/protocol/go/common\242\002\003CXX\252\002" +
      "\006Common\312\002\006Common\342\002\022Common\\GPBMetadata\352\002\006" +
      "Commonb\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          com.google.protobuf.TimestampProto.getDescriptor(),
        });
    internal_static_common_Metadata_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_common_Metadata_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_common_Metadata_descriptor,
        new java.lang.String[] { "CreatedAt", "UpdatedAt", "Labels", "Description", });
    internal_static_common_Metadata_LabelsEntry_descriptor =
      internal_static_common_Metadata_descriptor.getNestedTypes().get(0);
    internal_static_common_Metadata_LabelsEntry_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_common_Metadata_LabelsEntry_descriptor,
        new java.lang.String[] { "Key", "Value", });
    internal_static_common_MetadataMutable_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_common_MetadataMutable_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_common_MetadataMutable_descriptor,
        new java.lang.String[] { "Labels", "Description", });
    internal_static_common_MetadataMutable_LabelsEntry_descriptor =
      internal_static_common_MetadataMutable_descriptor.getNestedTypes().get(0);
    internal_static_common_MetadataMutable_LabelsEntry_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_common_MetadataMutable_LabelsEntry_descriptor,
        new java.lang.String[] { "Key", "Value", });
    com.google.protobuf.TimestampProto.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
