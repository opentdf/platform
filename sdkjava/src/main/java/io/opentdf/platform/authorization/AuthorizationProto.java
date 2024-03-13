// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authorization/authorization.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.authorization;

public final class AuthorizationProto {
  private AuthorizationProto() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_Entity_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_Entity_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_EntityCustom_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_EntityCustom_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_EntityChain_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_EntityChain_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_DecisionRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_DecisionRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_DecisionResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_DecisionResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_GetDecisionsRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_GetDecisionsRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_GetDecisionsResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_GetDecisionsResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_GetEntitlementsRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_GetEntitlementsRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_EntityEntitlements_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_EntityEntitlements_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_ResourceAttribute_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_ResourceAttribute_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_authorization_GetEntitlementsResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_authorization_GetEntitlementsResponse_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n!authorization/authorization.proto\022\raut" +
      "horization\032\034google/api/annotations.proto" +
      "\032\031google/protobuf/any.proto\032\024policy/obje" +
      "cts.proto\"\226\002\n\006Entity\022\016\n\002id\030\001 \001(\tR\002id\022%\n\r" +
      "email_address\030\002 \001(\tH\000R\014emailAddress\022\035\n\tu" +
      "ser_name\030\003 \001(\tH\000R\010userName\022,\n\021remote_cla" +
      "ims_url\030\004 \001(\tH\000R\017remoteClaimsUrl\022\022\n\003jwt\030" +
      "\005 \001(\tH\000R\003jwt\022.\n\006claims\030\006 \001(\0132\024.google.pr" +
      "otobuf.AnyH\000R\006claims\0225\n\006custom\030\007 \001(\0132\033.a" +
      "uthorization.EntityCustomH\000R\006customB\r\n\013e" +
      "ntity_type\"B\n\014EntityCustom\0222\n\textension\030" +
      "\001 \001(\0132\024.google.protobuf.AnyR\textension\"P" +
      "\n\013EntityChain\022\016\n\002id\030\001 \001(\tR\002id\0221\n\010entitie" +
      "s\030\002 \003(\0132\025.authorization.EntityR\010entities" +
      "\"\317\001\n\017DecisionRequest\022(\n\007actions\030\001 \003(\0132\016." +
      "policy.ActionR\007actions\022?\n\rentity_chains\030" +
      "\002 \003(\0132\032.authorization.EntityChainR\014entit" +
      "yChains\022Q\n\023resource_attributes\030\003 \003(\0132 .a" +
      "uthorization.ResourceAttributeR\022resource" +
      "Attributes\"\316\002\n\020DecisionResponse\022&\n\017entit" +
      "y_chain_id\030\001 \001(\tR\rentityChainId\0224\n\026resou" +
      "rce_attributes_id\030\002 \001(\tR\024resourceAttribu" +
      "tesId\022&\n\006action\030\003 \001(\0132\016.policy.ActionR\006a" +
      "ction\022D\n\010decision\030\004 \001(\0162(.authorization." +
      "DecisionResponse.DecisionR\010decision\022 \n\013o" +
      "bligations\030\005 \003(\tR\013obligations\"L\n\010Decisio" +
      "n\022\030\n\024DECISION_UNSPECIFIED\020\000\022\021\n\rDECISION_" +
      "DENY\020\001\022\023\n\017DECISION_PERMIT\020\002\"b\n\023GetDecisi" +
      "onsRequest\022K\n\021decision_requests\030\001 \003(\0132\036." +
      "authorization.DecisionRequestR\020decisionR" +
      "equests\"f\n\024GetDecisionsResponse\022N\n\022decis" +
      "ion_responses\030\001 \003(\0132\037.authorization.Deci" +
      "sionResponseR\021decisionResponses\"\222\001\n\026GetE" +
      "ntitlementsRequest\0221\n\010entities\030\001 \003(\0132\025.a" +
      "uthorization.EntityR\010entities\022;\n\005scope\030\002" +
      " \001(\0132 .authorization.ResourceAttributeH\000" +
      "R\005scope\210\001\001B\010\n\006_scope\"T\n\022EntityEntitlemen" +
      "ts\022\033\n\tentity_id\030\001 \001(\tR\010entityId\022!\n\014attri" +
      "bute_id\030\002 \003(\tR\013attributeId\":\n\021ResourceAt" +
      "tribute\022%\n\016attribute_fqns\030\002 \003(\tR\rattribu" +
      "teFqns\"`\n\027GetEntitlementsResponse\022E\n\014ent" +
      "itlements\030\001 \003(\0132!.authorization.EntityEn" +
      "titlementsR\014entitlements2\206\002\n\024Authorizati" +
      "onService\022r\n\014GetDecisions\022\".authorizatio" +
      "n.GetDecisionsRequest\032#.authorization.Ge" +
      "tDecisionsResponse\"\031\202\323\344\223\002\023\"\021/v1/authoriz" +
      "ation\022z\n\017GetEntitlements\022%.authorization" +
      ".GetEntitlementsRequest\032&.authorization." +
      "GetEntitlementsResponse\"\030\202\323\344\223\002\022\"\020/v1/ent" +
      "itlementsB\302\001\n!io.opentdf.platform.author" +
      "izationB\022AuthorizationProtoP\001Z5github.co" +
      "m/opentdf/platform/protocol/go/authoriza" +
      "tion\242\002\003AXX\252\002\rAuthorization\312\002\rAuthorizati" +
      "on\342\002\031Authorization\\GPBMetadata\352\002\rAuthori" +
      "zationb\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          com.google.api.AnnotationsProto.getDescriptor(),
          com.google.protobuf.AnyProto.getDescriptor(),
          io.opentdf.platform.policy.ObjectsProto.getDescriptor(),
        });
    internal_static_authorization_Entity_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_authorization_Entity_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_Entity_descriptor,
        new java.lang.String[] { "Id", "EmailAddress", "UserName", "RemoteClaimsUrl", "Jwt", "Claims", "Custom", "EntityType", });
    internal_static_authorization_EntityCustom_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_authorization_EntityCustom_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_EntityCustom_descriptor,
        new java.lang.String[] { "Extension", });
    internal_static_authorization_EntityChain_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_authorization_EntityChain_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_EntityChain_descriptor,
        new java.lang.String[] { "Id", "Entities", });
    internal_static_authorization_DecisionRequest_descriptor =
      getDescriptor().getMessageTypes().get(3);
    internal_static_authorization_DecisionRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_DecisionRequest_descriptor,
        new java.lang.String[] { "Actions", "EntityChains", "ResourceAttributes", });
    internal_static_authorization_DecisionResponse_descriptor =
      getDescriptor().getMessageTypes().get(4);
    internal_static_authorization_DecisionResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_DecisionResponse_descriptor,
        new java.lang.String[] { "EntityChainId", "ResourceAttributesId", "Action", "Decision", "Obligations", });
    internal_static_authorization_GetDecisionsRequest_descriptor =
      getDescriptor().getMessageTypes().get(5);
    internal_static_authorization_GetDecisionsRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_GetDecisionsRequest_descriptor,
        new java.lang.String[] { "DecisionRequests", });
    internal_static_authorization_GetDecisionsResponse_descriptor =
      getDescriptor().getMessageTypes().get(6);
    internal_static_authorization_GetDecisionsResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_GetDecisionsResponse_descriptor,
        new java.lang.String[] { "DecisionResponses", });
    internal_static_authorization_GetEntitlementsRequest_descriptor =
      getDescriptor().getMessageTypes().get(7);
    internal_static_authorization_GetEntitlementsRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_GetEntitlementsRequest_descriptor,
        new java.lang.String[] { "Entities", "Scope", });
    internal_static_authorization_EntityEntitlements_descriptor =
      getDescriptor().getMessageTypes().get(8);
    internal_static_authorization_EntityEntitlements_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_EntityEntitlements_descriptor,
        new java.lang.String[] { "EntityId", "AttributeId", });
    internal_static_authorization_ResourceAttribute_descriptor =
      getDescriptor().getMessageTypes().get(9);
    internal_static_authorization_ResourceAttribute_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_ResourceAttribute_descriptor,
        new java.lang.String[] { "AttributeFqns", });
    internal_static_authorization_GetEntitlementsResponse_descriptor =
      getDescriptor().getMessageTypes().get(10);
    internal_static_authorization_GetEntitlementsResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_authorization_GetEntitlementsResponse_descriptor,
        new java.lang.String[] { "Entitlements", });
    com.google.protobuf.ExtensionRegistry registry =
        com.google.protobuf.ExtensionRegistry.newInstance();
    registry.add(com.google.api.AnnotationsProto.http);
    com.google.protobuf.Descriptors.FileDescriptor
        .internalUpdateFileDescriptor(descriptor, registry);
    com.google.api.AnnotationsProto.getDescriptor();
    com.google.protobuf.AnyProto.getDescriptor();
    io.opentdf.platform.policy.ObjectsProto.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
