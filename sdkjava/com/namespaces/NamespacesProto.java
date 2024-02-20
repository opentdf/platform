// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: namespaces/namespaces.proto

// Protobuf Java Version: 3.25.3
package com.namespaces;

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
    internal_static_namespaces_Namespace_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_Namespace_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_GetNamespaceRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_GetNamespaceRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_GetNamespaceResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_GetNamespaceResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_ListNamespacesRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_ListNamespacesRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_ListNamespacesResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_ListNamespacesResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_CreateNamespaceRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_CreateNamespaceRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_CreateNamespaceResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_CreateNamespaceResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_UpdateNamespaceRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_UpdateNamespaceRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_UpdateNamespaceResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_UpdateNamespaceResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_DeactivateNamespaceRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_DeactivateNamespaceRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_namespaces_DeactivateNamespaceResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_namespaces_DeactivateNamespaceResponse_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\033namespaces/namespaces.proto\022\nnamespace" +
      "s\032\033buf/validate/validate.proto\032\034google/a" +
      "pi/annotations.proto\032\036google/protobuf/wr" +
      "appers.proto\032\023common/common.proto\"\311\004\n\tNa" +
      "mespace\022\016\n\002id\030\001 \001(\tR\002id\022\367\003\n\004name\030\002 \001(\tB\342" +
      "\003\272H\336\003r\003\030\375\001\272\001\322\003\n\020namespace_format\022\352\002Names" +
      "pace must be a valid hostname. It should" +
      " include at least one dot, with each seg" +
      "ment (label) starting and ending with an" +
      " alphanumeric character. Each label must" +
      " be 1 to 63 characters long, allowing hy" +
      "phens but not as the first or last chara" +
      "cter. The top-level domain (the last seg" +
      "ment after the final dot) must consist o" +
      "f at least two alphabetic characters.\032Qt" +
      "his.matches(\'^([a-zA-Z0-9]([a-zA-Z0-9\\\\-" +
      "]{0,61}[a-zA-Z0-9])?\\\\.)+[a-zA-Z]{2,}$\')" +
      "\310\001\001R\004name\0222\n\006active\030\003 \001(\0132\032.google.proto" +
      "buf.BoolValueR\006active\"-\n\023GetNamespaceReq" +
      "uest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310\001\001R\002id\"K\n\024GetNames" +
      "paceResponse\0223\n\tnamespace\030\001 \001(\0132\025.namesp" +
      "aces.NamespaceR\tnamespace\"F\n\025ListNamespa" +
      "cesRequest\022-\n\005state\030\001 \001(\0162\027.common.Activ" +
      "eStateEnumR\005state\"O\n\026ListNamespacesRespo" +
      "nse\0225\n\nnamespaces\030\001 \003(\0132\025.namespaces.Nam" +
      "espaceR\nnamespaces\"4\n\026CreateNamespaceReq" +
      "uest\022\032\n\004name\030\001 \001(\tB\006\272H\003\310\001\001R\004name\"N\n\027Crea" +
      "teNamespaceResponse\0223\n\tnamespace\030\001 \001(\0132\025" +
      ".namespaces.NamespaceR\tnamespace\"L\n\026Upda" +
      "teNamespaceRequest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310\001\001R\002" +
      "id\022\032\n\004name\030\002 \001(\tB\006\272H\003\310\001\001R\004name\"N\n\027Update" +
      "NamespaceResponse\0223\n\tnamespace\030\001 \001(\0132\025.n" +
      "amespaces.NamespaceR\tnamespace\"4\n\032Deacti" +
      "vateNamespaceRequest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310\001\001" +
      "R\002id\"\035\n\033DeactivateNamespaceResponse2\216\005\n\020" +
      "NamespaceService\022v\n\014GetNamespace\022\037.names" +
      "paces.GetNamespaceRequest\032 .namespaces.G" +
      "etNamespaceResponse\"#\202\323\344\223\002\035\022\033/attributes" +
      "/namespaces/{id}\022w\n\016ListNamespaces\022!.nam" +
      "espaces.ListNamespacesRequest\032\".namespac" +
      "es.ListNamespacesResponse\"\036\202\323\344\223\002\030\022\026/attr" +
      "ibutes/namespaces\022z\n\017CreateNamespace\022\".n" +
      "amespaces.CreateNamespaceRequest\032#.names" +
      "paces.CreateNamespaceResponse\"\036\202\323\344\223\002\030\"\026/" +
      "attributes/namespaces\022\177\n\017UpdateNamespace" +
      "\022\".namespaces.UpdateNamespaceRequest\032#.n" +
      "amespaces.UpdateNamespaceResponse\"#\202\323\344\223\002" +
      "\035\032\033/attributes/namespaces/{id}\022\213\001\n\023Deact" +
      "ivateNamespace\022&.namespaces.DeactivateNa" +
      "mespaceRequest\032\'.namespaces.DeactivateNa" +
      "mespaceResponse\"#\202\323\344\223\002\035*\033/attributes/nam" +
      "espaces/{id}B\225\001\n\016com.namespacesB\017Namespa" +
      "cesProtoP\001Z*github.com/opentdf/platform/" +
      "sdk/namespaces\242\002\003NXX\252\002\nNamespaces\312\002\nName" +
      "spaces\342\002\026Namespaces\\GPBMetadata\352\002\nNamesp" +
      "acesb\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          com.buf.validate.ValidateProto.getDescriptor(),
          com.google.api.AnnotationsProto.getDescriptor(),
          com.google.protobuf.WrappersProto.getDescriptor(),
          com.common.CommonProto.getDescriptor(),
        });
    internal_static_namespaces_Namespace_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_namespaces_Namespace_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_Namespace_descriptor,
        new java.lang.String[] { "Id", "Name", "Active", });
    internal_static_namespaces_GetNamespaceRequest_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_namespaces_GetNamespaceRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_GetNamespaceRequest_descriptor,
        new java.lang.String[] { "Id", });
    internal_static_namespaces_GetNamespaceResponse_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_namespaces_GetNamespaceResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_GetNamespaceResponse_descriptor,
        new java.lang.String[] { "Namespace", });
    internal_static_namespaces_ListNamespacesRequest_descriptor =
      getDescriptor().getMessageTypes().get(3);
    internal_static_namespaces_ListNamespacesRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_ListNamespacesRequest_descriptor,
        new java.lang.String[] { "State", });
    internal_static_namespaces_ListNamespacesResponse_descriptor =
      getDescriptor().getMessageTypes().get(4);
    internal_static_namespaces_ListNamespacesResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_ListNamespacesResponse_descriptor,
        new java.lang.String[] { "Namespaces", });
    internal_static_namespaces_CreateNamespaceRequest_descriptor =
      getDescriptor().getMessageTypes().get(5);
    internal_static_namespaces_CreateNamespaceRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_CreateNamespaceRequest_descriptor,
        new java.lang.String[] { "Name", });
    internal_static_namespaces_CreateNamespaceResponse_descriptor =
      getDescriptor().getMessageTypes().get(6);
    internal_static_namespaces_CreateNamespaceResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_CreateNamespaceResponse_descriptor,
        new java.lang.String[] { "Namespace", });
    internal_static_namespaces_UpdateNamespaceRequest_descriptor =
      getDescriptor().getMessageTypes().get(7);
    internal_static_namespaces_UpdateNamespaceRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_UpdateNamespaceRequest_descriptor,
        new java.lang.String[] { "Id", "Name", });
    internal_static_namespaces_UpdateNamespaceResponse_descriptor =
      getDescriptor().getMessageTypes().get(8);
    internal_static_namespaces_UpdateNamespaceResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_UpdateNamespaceResponse_descriptor,
        new java.lang.String[] { "Namespace", });
    internal_static_namespaces_DeactivateNamespaceRequest_descriptor =
      getDescriptor().getMessageTypes().get(9);
    internal_static_namespaces_DeactivateNamespaceRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_DeactivateNamespaceRequest_descriptor,
        new java.lang.String[] { "Id", });
    internal_static_namespaces_DeactivateNamespaceResponse_descriptor =
      getDescriptor().getMessageTypes().get(10);
    internal_static_namespaces_DeactivateNamespaceResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_namespaces_DeactivateNamespaceResponse_descriptor,
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
