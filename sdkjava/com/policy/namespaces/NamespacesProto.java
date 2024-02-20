// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/namespaces/namespaces.proto

// Protobuf Java Version: 3.25.3
package com.policy.namespaces;

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
      "roto\032\034google/api/annotations.proto\032\036goog" +
      "le/protobuf/wrappers.proto\032\023common/commo" +
      "n.proto\"\311\004\n\tNamespace\022\016\n\002id\030\001 \001(\tR\002id\022\367\003" +
      "\n\004name\030\002 \001(\tB\342\003\272H\336\003r\003\030\375\001\272\001\322\003\n\020namespace_" +
      "format\022\352\002Namespace must be a valid hostn" +
      "ame. It should include at least one dot," +
      " with each segment (label) starting and " +
      "ending with an alphanumeric character. E" +
      "ach label must be 1 to 63 characters lon" +
      "g, allowing hyphens but not as the first" +
      " or last character. The top-level domain" +
      " (the last segment after the final dot) " +
      "must consist of at least two alphabetic " +
      "characters.\032Qthis.matches(\'^([a-zA-Z0-9]" +
      "([a-zA-Z0-9\\\\-]{0,61}[a-zA-Z0-9])?\\\\.)+[" +
      "a-zA-Z]{2,}$\')\310\001\001R\004name\0222\n\006active\030\003 \001(\0132" +
      "\032.google.protobuf.BoolValueR\006active\"-\n\023G" +
      "etNamespaceRequest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310\001\001R\002" +
      "id\"R\n\024GetNamespaceResponse\022:\n\tnamespace\030" +
      "\001 \001(\0132\034.policy.namespaces.NamespaceR\tnam" +
      "espace\"F\n\025ListNamespacesRequest\022-\n\005state" +
      "\030\001 \001(\0162\027.common.ActiveStateEnumR\005state\"V" +
      "\n\026ListNamespacesResponse\022<\n\nnamespaces\030\001" +
      " \003(\0132\034.policy.namespaces.NamespaceR\nname" +
      "spaces\"4\n\026CreateNamespaceRequest\022\032\n\004name" +
      "\030\001 \001(\tB\006\272H\003\310\001\001R\004name\"U\n\027CreateNamespaceR" +
      "esponse\022:\n\tnamespace\030\001 \001(\0132\034.policy.name" +
      "spaces.NamespaceR\tnamespace\"L\n\026UpdateNam" +
      "espaceRequest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310\001\001R\002id\022\032\n" +
      "\004name\030\002 \001(\tB\006\272H\003\310\001\001R\004name\"U\n\027UpdateNames" +
      "paceResponse\022:\n\tnamespace\030\001 \001(\0132\034.policy" +
      ".namespaces.NamespaceR\tnamespace\"4\n\032Deac" +
      "tivateNamespaceRequest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310" +
      "\001\001R\002id\"\035\n\033DeactivateNamespaceResponse2\330\005" +
      "\n\020NamespaceService\022\204\001\n\014GetNamespace\022&.po" +
      "licy.namespaces.GetNamespaceRequest\032\'.po" +
      "licy.namespaces.GetNamespaceResponse\"#\202\323" +
      "\344\223\002\035\022\033/attributes/namespaces/{id}\022\205\001\n\016Li" +
      "stNamespaces\022(.policy.namespaces.ListNam" +
      "espacesRequest\032).policy.namespaces.ListN" +
      "amespacesResponse\"\036\202\323\344\223\002\030\022\026/attributes/n" +
      "amespaces\022\210\001\n\017CreateNamespace\022).policy.n" +
      "amespaces.CreateNamespaceRequest\032*.polic" +
      "y.namespaces.CreateNamespaceResponse\"\036\202\323" +
      "\344\223\002\030\"\026/attributes/namespaces\022\215\001\n\017UpdateN" +
      "amespace\022).policy.namespaces.UpdateNames" +
      "paceRequest\032*.policy.namespaces.UpdateNa" +
      "mespaceResponse\"#\202\323\344\223\002\035\032\033/attributes/nam" +
      "espaces/{id}\022\231\001\n\023DeactivateNamespace\022-.p" +
      "olicy.namespaces.DeactivateNamespaceRequ" +
      "est\032..policy.namespaces.DeactivateNamesp" +
      "aceResponse\"#\202\323\344\223\002\035*\033/attributes/namespa" +
      "ces/{id}B\316\001\n\025com.policy.namespacesB\017Name" +
      "spacesProtoP\001Z?github.com/opentdf/opentd" +
      "f-v2-poc/protocol/go/policy/namespaces\242\002" +
      "\003PNX\252\002\021Policy.Namespaces\312\002\021Policy\\Namesp" +
      "aces\342\002\035Policy\\Namespaces\\GPBMetadata\352\002\022P" +
      "olicy::Namespacesb\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          com.buf.validate.ValidateProto.getDescriptor(),
          com.google.api.AnnotationsProto.getDescriptor(),
          com.google.protobuf.WrappersProto.getDescriptor(),
          com.common.CommonProto.getDescriptor(),
        });
    internal_static_policy_namespaces_Namespace_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_policy_namespaces_Namespace_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_policy_namespaces_Namespace_descriptor,
        new java.lang.String[] { "Id", "Name", "Active", });
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
        new java.lang.String[] { "Name", });
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
        new java.lang.String[] { "Id", "Name", });
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
    registry.add(com.buf.validate.ValidateProto.field);
    registry.add(com.google.api.AnnotationsProto.http);
    com.google.protobuf.Descriptors.FileDescriptor
        .internalUpdateFileDescriptor(descriptor, registry);
    com.buf.validate.ValidateProto.getDescriptor();
    com.google.api.AnnotationsProto.getDescriptor();
    com.google.protobuf.WrappersProto.getDescriptor();
    com.common.CommonProto.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
