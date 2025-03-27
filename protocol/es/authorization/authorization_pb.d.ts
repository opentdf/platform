// @generated by protoc-gen-es v2.2.1
// @generated from file authorization/authorization.proto (package authorization, syntax proto3)
/* eslint-disable */

import type { GenEnum, GenFile, GenMessage, GenService } from "@bufbuild/protobuf/codegenv1";
import type { Message } from "@bufbuild/protobuf";
import type { Any } from "@bufbuild/protobuf/wkt";
import type { Action } from "../policy/objects_pb";

/**
 * Describes the file authorization/authorization.proto.
 */
export declare const file_authorization_authorization: GenFile;

/**
 * @generated from message authorization.Token
 */
export declare type Token = Message<"authorization.Token"> & {
  /**
   * ephemeral id for tracking between request and response
   *
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * the token
   *
   * @generated from field: string jwt = 2;
   */
  jwt: string;
};

/**
 * Describes the message authorization.Token.
 * Use `create(TokenSchema)` to create a new message.
 */
export declare const TokenSchema: GenMessage<Token>;

/**
 * PE (Person Entity) or NPE (Non-Person Entity)
 *
 * @generated from message authorization.Entity
 */
export declare type Entity = Message<"authorization.Entity"> & {
  /**
   * ephemeral id for tracking between request and response
   *
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * Standard entity types supported by the platform
   *
   * @generated from oneof authorization.Entity.entity_type
   */
  entityType: {
    /**
     * one of the entity options must be set
     *
     * @generated from field: string email_address = 2;
     */
    value: string;
    case: "emailAddress";
  } | {
    /**
     * @generated from field: string user_name = 3;
     */
    value: string;
    case: "userName";
  } | {
    /**
     * @generated from field: string remote_claims_url = 4;
     */
    value: string;
    case: "remoteClaimsUrl";
  } | {
    /**
     * @generated from field: string uuid = 5;
     */
    value: string;
    case: "uuid";
  } | {
    /**
     * @generated from field: google.protobuf.Any claims = 6;
     */
    value: Any;
    case: "claims";
  } | {
    /**
     * @generated from field: authorization.EntityCustom custom = 7;
     */
    value: EntityCustom;
    case: "custom";
  } | {
    /**
     * @generated from field: string client_id = 8;
     */
    value: string;
    case: "clientId";
  } | { case: undefined; value?: undefined };

  /**
   * @generated from field: authorization.Entity.Category category = 9;
   */
  category: Entity_Category;
};

/**
 * Describes the message authorization.Entity.
 * Use `create(EntitySchema)` to create a new message.
 */
export declare const EntitySchema: GenMessage<Entity>;

/**
 * @generated from enum authorization.Entity.Category
 */
export enum Entity_Category {
  /**
   * @generated from enum value: CATEGORY_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * @generated from enum value: CATEGORY_SUBJECT = 1;
   */
  SUBJECT = 1,

  /**
   * @generated from enum value: CATEGORY_ENVIRONMENT = 2;
   */
  ENVIRONMENT = 2,
}

/**
 * Describes the enum authorization.Entity.Category.
 */
export declare const Entity_CategorySchema: GenEnum<Entity_Category>;

/**
 * Entity type for custom entities beyond the standard types
 *
 * @generated from message authorization.EntityCustom
 */
export declare type EntityCustom = Message<"authorization.EntityCustom"> & {
  /**
   * @generated from field: google.protobuf.Any extension = 1;
   */
  extension?: Any;
};

/**
 * Describes the message authorization.EntityCustom.
 * Use `create(EntityCustomSchema)` to create a new message.
 */
export declare const EntityCustomSchema: GenMessage<EntityCustom>;

/**
 * A set of related PE and NPE
 *
 * @generated from message authorization.EntityChain
 */
export declare type EntityChain = Message<"authorization.EntityChain"> & {
  /**
   * ephemeral id for tracking between request and response
   *
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * @generated from field: repeated authorization.Entity entities = 2;
   */
  entities: Entity[];
};

/**
 * Describes the message authorization.EntityChain.
 * Use `create(EntityChainSchema)` to create a new message.
 */
export declare const EntityChainSchema: GenMessage<EntityChain>;

/**
 *
 * Example Request Get Decisions to answer the question -  Do Bob (represented by entity chain ec1)
 * and Alice (represented by entity chain ec2) have TRANSMIT authorization for
 * 2 resources; resource1 (attr-set-1) defined by attributes foo:bar  resource2 (attr-set-2) defined by attribute foo:bar, color:red ?
 *
 * {
 * "actions": [
 * {
 * "standard": "STANDARD_ACTION_TRANSMIT"
 * }
 * ],
 * "entityChains": [
 * {
 * "id": "ec1",
 * "entities": [
 * {
 * "emailAddress": "bob@example.org"
 * }
 * ]
 * },
 * {
 * "id": "ec2",
 * "entities": [
 * {
 * "userName": "alice@example.org"
 * }
 * ]
 * }
 * ],
 * "resourceAttributes": [
 * {
 * "resourceAttributeId":  "attr-set-1",
 * "attributeFqns": [
 * "https://www.example.org/attr/foo/value/value1"
 * ]
 * },
 * {
 * "resourceAttributeId":  "attr-set-2",
 * "attributeFqns": [
 * "https://example.net/attr/attr1/value/value1",
 * "https://example.net/attr/attr1/value/value2"
 * ]
 * }
 * ]
 * }
 *
 *
 * @generated from message authorization.DecisionRequest
 */
export declare type DecisionRequest = Message<"authorization.DecisionRequest"> & {
  /**
   * @generated from field: repeated policy.Action actions = 1;
   */
  actions: Action[];

  /**
   * @generated from field: repeated authorization.EntityChain entity_chains = 2;
   */
  entityChains: EntityChain[];

  /**
   * @generated from field: repeated authorization.ResourceAttribute resource_attributes = 3;
   */
  resourceAttributes: ResourceAttribute[];
};

/**
 * Describes the message authorization.DecisionRequest.
 * Use `create(DecisionRequestSchema)` to create a new message.
 */
export declare const DecisionRequestSchema: GenMessage<DecisionRequest>;

/**
 *
 *
 * Example response for a Decision Request -  Do Bob (represented by entity chain ec1)
 * and Alice (represented by entity chain ec2) have TRANSMIT authorization for
 * 2 resources; resource1 (attr-set-1) defined by attributes foo:bar  resource2 (attr-set-2) defined by attribute foo:bar, color:red ?
 *
 * Results:
 * - bob has permitted authorization to transmit for a resource defined by attr-set-1 attributes and has a watermark obligation
 * - bob has denied authorization to transmit a for a resource defined by attr-set-2 attributes
 * - alice has permitted authorization to transmit for a resource defined by attr-set-1 attributes
 * - alice has denied authorization to transmit a for a resource defined by attr-set-2 attributes
 *
 * {
 * "entityChainId":  "ec1",
 * "resourceAttributesId":  "attr-set-1",
 * "decision":  "DECISION_PERMIT",
 * "obligations":  [
 * "http://www.example.org/obligation/watermark"
 * ]
 * },
 * {
 * "entityChainId":  "ec1",
 * "resourceAttributesId":  "attr-set-2",
 * "decision":  "DECISION_PERMIT"
 * },
 * {
 * "entityChainId":  "ec2",
 * "resourceAttributesId":  "attr-set-1",
 * "decision":  "DECISION_PERMIT"
 * },
 * {
 * "entityChainId":  "ec2",
 * "resourceAttributesId":  "attr-set-2",
 * "decision":  "DECISION_DENY"
 * }
 *
 *
 *
 * @generated from message authorization.DecisionResponse
 */
export declare type DecisionResponse = Message<"authorization.DecisionResponse"> & {
  /**
   * ephemeral entity chain id from the request
   *
   * @generated from field: string entity_chain_id = 1;
   */
  entityChainId: string;

  /**
   * ephemeral resource attributes id from the request
   *
   * @generated from field: string resource_attributes_id = 2;
   */
  resourceAttributesId: string;

  /**
   * Action of the decision response
   *
   * @generated from field: policy.Action action = 3;
   */
  action?: Action;

  /**
   * The decision response
   *
   * @generated from field: authorization.DecisionResponse.Decision decision = 4;
   */
  decision: DecisionResponse_Decision;

  /**
   * optional list of obligations represented in URI format
   *
   * @generated from field: repeated string obligations = 5;
   */
  obligations: string[];
};

/**
 * Describes the message authorization.DecisionResponse.
 * Use `create(DecisionResponseSchema)` to create a new message.
 */
export declare const DecisionResponseSchema: GenMessage<DecisionResponse>;

/**
 * @generated from enum authorization.DecisionResponse.Decision
 */
export enum DecisionResponse_Decision {
  /**
   * @generated from enum value: DECISION_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * @generated from enum value: DECISION_DENY = 1;
   */
  DENY = 1,

  /**
   * @generated from enum value: DECISION_PERMIT = 2;
   */
  PERMIT = 2,
}

/**
 * Describes the enum authorization.DecisionResponse.Decision.
 */
export declare const DecisionResponse_DecisionSchema: GenEnum<DecisionResponse_Decision>;

/**
 * @generated from message authorization.GetDecisionsRequest
 */
export declare type GetDecisionsRequest = Message<"authorization.GetDecisionsRequest"> & {
  /**
   * @generated from field: repeated authorization.DecisionRequest decision_requests = 1;
   */
  decisionRequests: DecisionRequest[];
};

/**
 * Describes the message authorization.GetDecisionsRequest.
 * Use `create(GetDecisionsRequestSchema)` to create a new message.
 */
export declare const GetDecisionsRequestSchema: GenMessage<GetDecisionsRequest>;

/**
 * @generated from message authorization.GetDecisionsResponse
 */
export declare type GetDecisionsResponse = Message<"authorization.GetDecisionsResponse"> & {
  /**
   * @generated from field: repeated authorization.DecisionResponse decision_responses = 1;
   */
  decisionResponses: DecisionResponse[];
};

/**
 * Describes the message authorization.GetDecisionsResponse.
 * Use `create(GetDecisionsResponseSchema)` to create a new message.
 */
export declare const GetDecisionsResponseSchema: GenMessage<GetDecisionsResponse>;

/**
 *
 * Request to get entitlements for one or more entities for an optional attribute scope
 *
 * Example: Get entitlements for bob and alice (both represented using an email address
 *
 * {
 * "entities": [
 * {
 * "id": "e1",
 * "emailAddress": "bob@example.org"
 * },
 * {
 * "id": "e2",
 * "emailAddress": "alice@example.org"
 * }
 * ],
 * "scope": {
 * "attributeFqns": [
 * "https://example.net/attr/attr1/value/value1",
 * "https://example.net/attr/attr1/value/value2"
 * ]
 * }
 * }
 *
 *
 * @generated from message authorization.GetEntitlementsRequest
 */
export declare type GetEntitlementsRequest = Message<"authorization.GetEntitlementsRequest"> & {
  /**
   * list of requested entities
   *
   * @generated from field: repeated authorization.Entity entities = 1;
   */
  entities: Entity[];

  /**
   * optional attribute fqn as a scope
   *
   * @generated from field: optional authorization.ResourceAttribute scope = 2;
   */
  scope?: ResourceAttribute;

  /**
   * optional parameter to return a full list of entitlements - returns lower hierarchy attributes
   *
   * @generated from field: optional bool with_comprehensive_hierarchy = 3;
   */
  withComprehensiveHierarchy?: boolean;
};

/**
 * Describes the message authorization.GetEntitlementsRequest.
 * Use `create(GetEntitlementsRequestSchema)` to create a new message.
 */
export declare const GetEntitlementsRequestSchema: GenMessage<GetEntitlementsRequest>;

/**
 * @generated from message authorization.EntityEntitlements
 */
export declare type EntityEntitlements = Message<"authorization.EntityEntitlements"> & {
  /**
   * @generated from field: string entity_id = 1;
   */
  entityId: string;

  /**
   * @generated from field: repeated string attribute_value_fqns = 2;
   */
  attributeValueFqns: string[];
};

/**
 * Describes the message authorization.EntityEntitlements.
 * Use `create(EntityEntitlementsSchema)` to create a new message.
 */
export declare const EntityEntitlementsSchema: GenMessage<EntityEntitlements>;

/**
 * A logical bucket of attributes belonging to a "Resource"
 *
 * @generated from message authorization.ResourceAttribute
 */
export declare type ResourceAttribute = Message<"authorization.ResourceAttribute"> & {
  /**
   * @generated from field: string resource_attributes_id = 1;
   */
  resourceAttributesId: string;

  /**
   * @generated from field: repeated string attribute_value_fqns = 2;
   */
  attributeValueFqns: string[];
};

/**
 * Describes the message authorization.ResourceAttribute.
 * Use `create(ResourceAttributeSchema)` to create a new message.
 */
export declare const ResourceAttributeSchema: GenMessage<ResourceAttribute>;

/**
 *
 *
 * Example Response for a request of : Get entitlements for bob and alice (both represented using an email address
 *
 * {
 * "entitlements":  [
 * {
 * "entityId":  "e1",
 * "attributeValueReferences":  [
 * {
 * "attributeFqn":  "http://www.example.org/attr/foo/value/bar"
 * }
 * ]
 * },
 * {
 * "entityId":  "e2",
 * "attributeValueReferences":  [
 * {
 * "attributeFqn":  "http://www.example.org/attr/color/value/red"
 * }
 * ]
 * }
 * ]
 * }
 *
 *
 *
 * @generated from message authorization.GetEntitlementsResponse
 */
export declare type GetEntitlementsResponse = Message<"authorization.GetEntitlementsResponse"> & {
  /**
   * @generated from field: repeated authorization.EntityEntitlements entitlements = 1;
   */
  entitlements: EntityEntitlements[];
};

/**
 * Describes the message authorization.GetEntitlementsResponse.
 * Use `create(GetEntitlementsResponseSchema)` to create a new message.
 */
export declare const GetEntitlementsResponseSchema: GenMessage<GetEntitlementsResponse>;

/**
 *
 * Example Request Get Decisions by Token to answer the question -  Do Bob and client1 (represented by token tok1)
 * and Alice and client2 (represented by token tok2) have TRANSMIT authorization for
 * 2 resources; resource1 (attr-set-1) defined by attributes foo:bar  resource2 (attr-set-2) defined by attribute foo:bar, color:red ?
 *
 * {
 * "actions": [
 * {
 * "standard": "STANDARD_ACTION_TRANSMIT"
 * }
 * ],
 * "tokens": [
 * {
 * "id": "tok1",
 * "jwt": ....
 * },
 * {
 * "id": "tok2",
 * "jwt": .....
 * }
 * ],
 * "resourceAttributes": [
 * {
 * "attributeFqns": [
 * "https://www.example.org/attr/foo/value/value1"
 * ]
 * },
 * {
 * "attributeFqns": [
 * "https://example.net/attr/attr1/value/value1",
 * "https://example.net/attr/attr1/value/value2"
 * ]
 * }
 * ]
 * }
 *
 *
 * @generated from message authorization.TokenDecisionRequest
 */
export declare type TokenDecisionRequest = Message<"authorization.TokenDecisionRequest"> & {
  /**
   * @generated from field: repeated policy.Action actions = 1;
   */
  actions: Action[];

  /**
   * @generated from field: repeated authorization.Token tokens = 2;
   */
  tokens: Token[];

  /**
   * @generated from field: repeated authorization.ResourceAttribute resource_attributes = 3;
   */
  resourceAttributes: ResourceAttribute[];
};

/**
 * Describes the message authorization.TokenDecisionRequest.
 * Use `create(TokenDecisionRequestSchema)` to create a new message.
 */
export declare const TokenDecisionRequestSchema: GenMessage<TokenDecisionRequest>;

/**
 * @generated from message authorization.GetDecisionsByTokenRequest
 */
export declare type GetDecisionsByTokenRequest = Message<"authorization.GetDecisionsByTokenRequest"> & {
  /**
   * @generated from field: repeated authorization.TokenDecisionRequest decision_requests = 1;
   */
  decisionRequests: TokenDecisionRequest[];
};

/**
 * Describes the message authorization.GetDecisionsByTokenRequest.
 * Use `create(GetDecisionsByTokenRequestSchema)` to create a new message.
 */
export declare const GetDecisionsByTokenRequestSchema: GenMessage<GetDecisionsByTokenRequest>;

/**
 * @generated from message authorization.GetDecisionsByTokenResponse
 */
export declare type GetDecisionsByTokenResponse = Message<"authorization.GetDecisionsByTokenResponse"> & {
  /**
   * @generated from field: repeated authorization.DecisionResponse decision_responses = 1;
   */
  decisionResponses: DecisionResponse[];
};

/**
 * Describes the message authorization.GetDecisionsByTokenResponse.
 * Use `create(GetDecisionsByTokenResponseSchema)` to create a new message.
 */
export declare const GetDecisionsByTokenResponseSchema: GenMessage<GetDecisionsByTokenResponse>;

/**
 * @generated from service authorization.AuthorizationService
 */
export declare const AuthorizationService: GenService<{
  /**
   * @generated from rpc authorization.AuthorizationService.GetDecisions
   */
  getDecisions: {
    methodKind: "unary";
    input: typeof GetDecisionsRequestSchema;
    output: typeof GetDecisionsResponseSchema;
  },
  /**
   * @generated from rpc authorization.AuthorizationService.GetDecisionsByToken
   */
  getDecisionsByToken: {
    methodKind: "unary";
    input: typeof GetDecisionsByTokenRequestSchema;
    output: typeof GetDecisionsByTokenResponseSchema;
  },
  /**
   * @generated from rpc authorization.AuthorizationService.GetEntitlements
   */
  getEntitlements: {
    methodKind: "unary";
    input: typeof GetEntitlementsRequestSchema;
    output: typeof GetEntitlementsResponseSchema;
  },
}>;

