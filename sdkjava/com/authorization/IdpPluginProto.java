// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authorization/idp_plugin.proto

// Protobuf Java Version: 3.25.3
package com.authorization;

public final class IdpPluginProto {
  private IdpPluginProto() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_IdpEntity_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_IdpEntity_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_IdpPluginRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_IdpPluginRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_IdpEntityRepresentation_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_IdpEntityRepresentation_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_IdpPluginResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_IdpPluginResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_EntityNotFoundError_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_EntityNotFoundError_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\036authorization/idp_plugin.proto\022\rauthor" +
      "ization\032!authorization/authorization.pro" +
      "to\032\031google/protobuf/any.proto\032\034google/pr" +
      "otobuf/struct.proto\"\273\001\n\tIdpEntity\022\016\n\002id\030" +
      "\001 \001(\tR\002id\022%\n\remail_address\030\002 \001(\tH\000R\014emai" +
      "lAddress\022\035\n\tuser_name\030\003 \001(\tH\000R\010userName\022" +
      "\022\n\003jwt\030\004 \001(\tH\000R\003jwt\0225\n\006custom\030\005 \001(\0132\033.au" +
      "thorization.EntityCustomH\000R\006customB\r\n\013en" +
      "tity_type\"H\n\020IdpPluginRequest\0224\n\010entitie" +
      "s\030\001 \003(\0132\030.authorization.IdpEntityR\010entit" +
      "ies\"~\n\027IdpEntityRepresentation\022B\n\020additi" +
      "onal_props\030\001 \003(\0132\027.google.protobuf.Struc" +
      "tR\017additionalProps\022\037\n\013original_id\030\002 \001(\tR" +
      "\noriginalId\"r\n\021IdpPluginResponse\022]\n\026enti" +
      "ty_representations\030\001 \003(\0132&.authorization" +
      ".IdpEntityRepresentationR\025entityRepresen" +
      "tations\"s\n\023EntityNotFoundError\022\022\n\004user\030\001" +
      " \001(\tR\004user\022\030\n\007message\030\002 \001(\tR\007message\022.\n\007" +
      "details\030\003 \003(\0132\024.google.protobuf.AnyR\007det" +
      "ailsB\246\001\n\021com.authorizationB\016IdpPluginPro" +
      "toP\001Z-github.com/opentdf/platform/sdk/au" +
      "thorization\242\002\003AXX\252\002\rAuthorization\312\002\rAuth" +
      "orization\342\002\031Authorization\\GPBMetadata\352\002\r" +
      "Authorizationb\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          com.authorization.AuthorizationProto.getDescriptor(),
          com.google.protobuf.AnyProto.getDescriptor(),
          com.google.protobuf.StructProto.getDescriptor(),
        });
    internal_static_authorization_IdpEntity_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_authorization_IdpEntity_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_IdpEntity_descriptor,
        new java.lang.String[] { "Id", "EmailAddress", "UserName", "Jwt", "Custom", "EntityType", });
    internal_static_authorization_IdpPluginRequest_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_authorization_IdpPluginRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_IdpPluginRequest_descriptor,
        new java.lang.String[] { "Entities", });
    internal_static_authorization_IdpEntityRepresentation_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_authorization_IdpEntityRepresentation_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_IdpEntityRepresentation_descriptor,
        new java.lang.String[] { "AdditionalProps", "OriginalId", });
    internal_static_authorization_IdpPluginResponse_descriptor =
      getDescriptor().getMessageTypes().get(3);
    internal_static_authorization_IdpPluginResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_IdpPluginResponse_descriptor,
        new java.lang.String[] { "EntityRepresentations", });
    internal_static_authorization_EntityNotFoundError_descriptor =
      getDescriptor().getMessageTypes().get(4);
    internal_static_authorization_EntityNotFoundError_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_EntityNotFoundError_descriptor,
        new java.lang.String[] { "User", "Message", "Details", });
    com.authorization.AuthorizationProto.getDescriptor();
    com.google.protobuf.AnyProto.getDescriptor();
    com.google.protobuf.StructProto.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
