// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/namespaces/namespaces.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.namespaces;

public final class NamespacesProto {
  private NamespacesProto() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_Namespace_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_Namespace_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_GetNamespaceRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_GetNamespaceRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_GetNamespaceResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_GetNamespaceResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_ListNamespacesRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_ListNamespacesRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_ListNamespacesResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_ListNamespacesResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_CreateNamespaceRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_CreateNamespaceRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_CreateNamespaceResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_CreateNamespaceResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_UpdateNamespaceRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_UpdateNamespaceRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_UpdateNamespaceResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_UpdateNamespaceResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_DeactivateNamespaceRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_DeactivateNamespaceRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_policy_namespaces_DeactivateNamespaceResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_policy_namespaces_DeactivateNamespaceResponse_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\"policy/namespaces/namespaces.proto\022\021po" +
      "licy.namespaces\032\033buf/validate/validate.p" +
      "roto\032\023common/common.proto\032\034google/api/an" +
      "notations.proto\032\036google/protobuf/wrapper" +
      "s.proto\"\243\001\n\tNamespace\022\016\n\002id\030\001 \001(\tR\002id\022\022\n" +
      "\004name\030\002 \001(\tR\004name\022\020\n\003fqn\030\003 \001(\tR\003fqn\0222\n\006a" +
      "ctive\030\004 \001(\0132\032.google.protobuf.BoolValueR" +
      "\006active\022,\n\010metadata\030\005 \001(\0132\020.common.Metad" +
      "ataR\010metadata\"-\n\023GetNamespaceRequest\022\026\n\002" +
      "id\030\001 \001(\tB\006\272H\003\310\001\001R\002id\"R\n\024GetNamespaceResp" +
      "onse\022:\n\tnamespace\030\001 \001(\0132\034.policy.namespa" +
      "ces.NamespaceR\tnamespace\"F\n\025ListNamespac" +
      "esRequest\022-\n\005state\030\001 \001(\0162\027.common.Active" +
      "StateEnumR\005state\"V\n\026ListNamespacesRespon" +
      "se\022<\n\nnamespaces\030\001 \003(\0132\034.policy.namespac" +
      "es.NamespaceR\nnamespaces\"\307\004\n\026CreateNames" +
      "paceRequest\022\367\003\n\004name\030\001 \001(\tB\342\003\272H\336\003r\003\030\375\001\272\001" +
      "\322\003\n\020namespace_format\022\352\002Namespace must be" +
      " a valid hostname. It should include at " +
      "least one dot, with each segment (label)" +
      " starting and ending with an alphanumeri" +
      "c character. Each label must be 1 to 63 " +
      "characters long, allowing hyphens but no" +
      "t as the first or last character. The to" +
      "p-level domain (the last segment after t" +
      "he final dot) must consist of at least t" +
      "wo alphabetic characters.\032Qthis.matches(" +
      "\'^([a-zA-Z0-9]([a-zA-Z0-9\\\\-]{0,61}[a-zA" +
      "-Z0-9])?\\\\.)+[a-zA-Z]{2,}$\')\310\001\001R\004name\0223\n" +
      "\010metadata\030d \001(\0132\027.common.MetadataMutable" +
      "R\010metadata\"U\n\027CreateNamespaceResponse\022:\n" +
      "\tnamespace\030\001 \001(\0132\034.policy.namespaces.Nam" +
      "espaceR\tnamespace\"\273\001\n\026UpdateNamespaceReq" +
      "uest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310\001\001R\002id\0223\n\010metadata" +
      "\030d \001(\0132\027.common.MetadataMutableR\010metadat" +
      "a\022T\n\030metadata_update_behavior\030e \001(\0162\032.co" +
      "mmon.MetadataUpdateEnumR\026metadataUpdateB" +
      "ehavior\"U\n\027UpdateNamespaceResponse\022:\n\tna" +
      "mespace\030\001 \001(\0132\034.policy.namespaces.Namesp" +
      "aceR\tnamespace\"4\n\032DeactivateNamespaceReq" +
      "uest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310\001\001R\002id\"\035\n\033Deactiva" +
      "teNamespaceResponse2\336\005\n\020NamespaceService" +
      "\022\204\001\n\014GetNamespace\022&.policy.namespaces.Ge" +
      "tNamespaceRequest\032\'.policy.namespaces.Ge" +
      "tNamespaceResponse\"#\202\323\344\223\002\035\022\033/attributes/" +
      "namespaces/{id}\022\205\001\n\016ListNamespaces\022(.pol" +
      "icy.namespaces.ListNamespacesRequest\032).p" +
      "olicy.namespaces.ListNamespacesResponse\"" +
      "\036\202\323\344\223\002\030\022\026/attributes/namespaces\022\213\001\n\017Crea" +
      "teNamespace\022).policy.namespaces.CreateNa" +
      "mespaceRequest\032*.policy.namespaces.Creat" +
      "eNamespaceResponse\"!\202\323\344\223\002\033\"\026/attributes/" +
      "namespaces:\001*\022\220\001\n\017UpdateNamespace\022).poli" +
      "cy.namespaces.UpdateNamespaceRequest\032*.p" +
      "olicy.namespaces.UpdateNamespaceResponse" +
      "\"&\202\323\344\223\002 2\033/attributes/namespaces/{id}:\001*" +
      "\022\231\001\n\023DeactivateNamespace\022-.policy.namesp" +
      "aces.DeactivateNamespaceRequest\032..policy" +
      ".namespaces.DeactivateNamespaceResponse\"" +
      "#\202\323\344\223\002\035*\033/attributes/namespaces/{id}B\330\001\n" +
      "%io.opentdf.platform.policy.namespacesB\017" +
      "NamespacesProtoP\001Z9github.com/opentdf/pl" +
      "atform/protocol/go/policy/namespaces\242\002\003P" +
      "NX\252\002\021Policy.Namespaces\312\002\021Policy\\Namespac" +
      "es\342\002\035Policy\\Namespaces\\GPBMetadata\352\002\022Pol" +
      "icy::Namespacesb\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          build.buf.validate.ValidateProto.getDescriptor(),
          io.opentdf.platform.common.CommonProto.getDescriptor(),
          com.google.api.AnnotationsProto.getDescriptor(),
          com.google.protobuf.WrappersProto.getDescriptor(),
        });
    internal_static_policy_namespaces_Namespace_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_policy_namespaces_Namespace_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_Namespace_descriptor,
        new java.lang.String[] { "Id", "Name", "Fqn", "Active", "Metadata", });
    internal_static_policy_namespaces_GetNamespaceRequest_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_policy_namespaces_GetNamespaceRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_GetNamespaceRequest_descriptor,
        new java.lang.String[] { "Id", });
    internal_static_policy_namespaces_GetNamespaceResponse_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_policy_namespaces_GetNamespaceResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_GetNamespaceResponse_descriptor,
        new java.lang.String[] { "Namespace", });
    internal_static_policy_namespaces_ListNamespacesRequest_descriptor =
      getDescriptor().getMessageTypes().get(3);
    internal_static_policy_namespaces_ListNamespacesRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_ListNamespacesRequest_descriptor,
        new java.lang.String[] { "State", });
    internal_static_policy_namespaces_ListNamespacesResponse_descriptor =
      getDescriptor().getMessageTypes().get(4);
    internal_static_policy_namespaces_ListNamespacesResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_ListNamespacesResponse_descriptor,
        new java.lang.String[] { "Namespaces", });
    internal_static_policy_namespaces_CreateNamespaceRequest_descriptor =
      getDescriptor().getMessageTypes().get(5);
    internal_static_policy_namespaces_CreateNamespaceRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_CreateNamespaceRequest_descriptor,
        new java.lang.String[] { "Name", "Metadata", });
    internal_static_policy_namespaces_CreateNamespaceResponse_descriptor =
      getDescriptor().getMessageTypes().get(6);
    internal_static_policy_namespaces_CreateNamespaceResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_CreateNamespaceResponse_descriptor,
        new java.lang.String[] { "Namespace", });
    internal_static_policy_namespaces_UpdateNamespaceRequest_descriptor =
      getDescriptor().getMessageTypes().get(7);
    internal_static_policy_namespaces_UpdateNamespaceRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_UpdateNamespaceRequest_descriptor,
        new java.lang.String[] { "Id", "Metadata", "MetadataUpdateBehavior", });
    internal_static_policy_namespaces_UpdateNamespaceResponse_descriptor =
      getDescriptor().getMessageTypes().get(8);
    internal_static_policy_namespaces_UpdateNamespaceResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_UpdateNamespaceResponse_descriptor,
        new java.lang.String[] { "Namespace", });
    internal_static_policy_namespaces_DeactivateNamespaceRequest_descriptor =
      getDescriptor().getMessageTypes().get(9);
    internal_static_policy_namespaces_DeactivateNamespaceRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_DeactivateNamespaceRequest_descriptor,
        new java.lang.String[] { "Id", });
    internal_static_policy_namespaces_DeactivateNamespaceResponse_descriptor =
      getDescriptor().getMessageTypes().get(10);
    internal_static_policy_namespaces_DeactivateNamespaceResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_DeactivateNamespaceResponse_descriptor,
        new java.lang.String[] { });
    com.google.protobuf.ExtensionRegistry registry =
        com.google.protobuf.ExtensionRegistry.newInstance();
    registry.add(build.buf.validate.ValidateProto.field);
    registry.add(com.google.api.AnnotationsProto.http);
    com.google.protobuf.Descriptors.FileDescriptor
        .internalUpdateFileDescriptor(descriptor, registry);
    build.buf.validate.ValidateProto.getDescriptor();
    io.opentdf.platform.common.CommonProto.getDescriptor();
    com.google.api.AnnotationsProto.getDescriptor();
    com.google.protobuf.WrappersProto.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
