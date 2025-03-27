// @generated by protoc-gen-es v2.2.1
// @generated from file policy/objects.proto (package policy, syntax proto3)
/* eslint-disable */

import type { GenEnum, GenFile, GenMessage } from "@bufbuild/protobuf/codegenv1";
import type { Message } from "@bufbuild/protobuf";
import type { Metadata } from "../common/common_pb";

/**
 * Describes the file policy/objects.proto.
 */
export declare const file_policy_objects: GenFile;

/**
 * @generated from message policy.Namespace
 */
export declare type Namespace = Message<"policy.Namespace"> & {
  /**
   * generated uuid in database
   *
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * used to partition Attribute Definitions, support by namespace AuthN and enable federation
   *
   * @generated from field: string name = 2;
   */
  name: string;

  /**
   * @generated from field: string fqn = 3;
   */
  fqn: string;

  /**
   * active by default until explicitly deactivated
   *
   * @generated from field: google.protobuf.BoolValue active = 4;
   */
  active?: boolean;

  /**
   * @generated from field: common.Metadata metadata = 5;
   */
  metadata?: Metadata;

  /**
   * KAS grants for the namespace
   *
   * @generated from field: repeated policy.KeyAccessServer grants = 6;
   */
  grants: KeyAccessServer[];
};

/**
 * Describes the message policy.Namespace.
 * Use `create(NamespaceSchema)` to create a new message.
 */
export declare const NamespaceSchema: GenMessage<Namespace>;

/**
 * @generated from message policy.Attribute
 */
export declare type Attribute = Message<"policy.Attribute"> & {
  /**
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * namespace of the attribute
   *
   * @generated from field: policy.Namespace namespace = 2;
   */
  namespace?: Namespace;

  /**
   * attribute name
   *
   * @generated from field: string name = 3;
   */
  name: string;

  /**
   * attribute rule enum
   *
   * @generated from field: policy.AttributeRuleTypeEnum rule = 4;
   */
  rule: AttributeRuleTypeEnum;

  /**
   * @generated from field: repeated policy.Value values = 5;
   */
  values: Value[];

  /**
   * @generated from field: repeated policy.KeyAccessServer grants = 6;
   */
  grants: KeyAccessServer[];

  /**
   * @generated from field: string fqn = 7;
   */
  fqn: string;

  /**
   * active by default until explicitly deactivated
   *
   * @generated from field: google.protobuf.BoolValue active = 8;
   */
  active?: boolean;

  /**
   * Common metadata
   *
   * @generated from field: common.Metadata metadata = 100;
   */
  metadata?: Metadata;
};

/**
 * Describes the message policy.Attribute.
 * Use `create(AttributeSchema)` to create a new message.
 */
export declare const AttributeSchema: GenMessage<Attribute>;

/**
 * @generated from message policy.Value
 */
export declare type Value = Message<"policy.Value"> & {
  /**
   * generated uuid in database
   *
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * @generated from field: policy.Attribute attribute = 2;
   */
  attribute?: Attribute;

  /**
   * @generated from field: string value = 3;
   */
  value: string;

  /**
   * list of key access servers
   *
   * @generated from field: repeated policy.KeyAccessServer grants = 5;
   */
  grants: KeyAccessServer[];

  /**
   * @generated from field: string fqn = 6;
   */
  fqn: string;

  /**
   * active by default until explicitly deactivated
   *
   * @generated from field: google.protobuf.BoolValue active = 7;
   */
  active?: boolean;

  /**
   * subject mapping
   *
   * @generated from field: repeated policy.SubjectMapping subject_mappings = 8;
   */
  subjectMappings: SubjectMapping[];

  /**
   * Common metadata
   *
   * @generated from field: common.Metadata metadata = 100;
   */
  metadata?: Metadata;
};

/**
 * Describes the message policy.Value.
 * Use `create(ValueSchema)` to create a new message.
 */
export declare const ValueSchema: GenMessage<Value>;

/**
 * An action an entity can take
 *
 * @generated from message policy.Action
 */
export declare type Action = Message<"policy.Action"> & {
  /**
   * @generated from oneof policy.Action.value
   */
  value: {
    /**
     * @generated from field: policy.Action.StandardAction standard = 1;
     */
    value: Action_StandardAction;
    case: "standard";
  } | {
    /**
     * @generated from field: string custom = 2;
     */
    value: string;
    case: "custom";
  } | { case: undefined; value?: undefined };
};

/**
 * Describes the message policy.Action.
 * Use `create(ActionSchema)` to create a new message.
 */
export declare const ActionSchema: GenMessage<Action>;

/**
 * Standard actions supported by the platform
 *
 * @generated from enum policy.Action.StandardAction
 */
export enum Action_StandardAction {
  /**
   * @generated from enum value: STANDARD_ACTION_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * @generated from enum value: STANDARD_ACTION_DECRYPT = 1;
   */
  DECRYPT = 1,

  /**
   * @generated from enum value: STANDARD_ACTION_TRANSMIT = 2;
   */
  TRANSMIT = 2,
}

/**
 * Describes the enum policy.Action.StandardAction.
 */
export declare const Action_StandardActionSchema: GenEnum<Action_StandardAction>;

/**
 *
 * Subject Mapping: A Policy assigning Subject Set(s) to a permitted attribute value + action(s) combination
 *
 * Example: Subjects in sets 1 and 2 are entitled attribute value http://wwww.example.org/attr/example/value/one
 * with permitted actions TRANSMIT and DECRYPT
 * {
 * "id": "someid",
 * "attribute_value": {example_one_attribute_value...},
 * "subject_condition_set": {"subject_sets":[{subject_set_1},{subject_set_2}]...},
 * "actions": [{"standard": "STANDARD_ACTION_DECRYPT"}", {"standard": "STANDARD_ACTION_TRANSMIT"}]
 * }
 *
 * @generated from message policy.SubjectMapping
 */
export declare type SubjectMapping = Message<"policy.SubjectMapping"> & {
  /**
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * the Attribute Value mapped to; aka: "The Entity Entitlement Attribute"
   *
   * @generated from field: policy.Value attribute_value = 2;
   */
  attributeValue?: Value;

  /**
   * the reusable SubjectConditionSet mapped to the given Attribute Value
   *
   * @generated from field: policy.SubjectConditionSet subject_condition_set = 3;
   */
  subjectConditionSet?: SubjectConditionSet;

  /**
   * The actions permitted by subjects in this mapping
   *
   * @generated from field: repeated policy.Action actions = 4;
   */
  actions: Action[];

  /**
   * @generated from field: common.Metadata metadata = 100;
   */
  metadata?: Metadata;
};

/**
 * Describes the message policy.SubjectMapping.
 * Use `create(SubjectMappingSchema)` to create a new message.
 */
export declare const SubjectMappingSchema: GenMessage<SubjectMapping>;

/**
 * *
 * A Condition defines a rule of <the value at the flattened 'selector value' location> <operator> <subject external values>
 *
 * @generated from message policy.Condition
 */
export declare type Condition = Message<"policy.Condition"> & {
  /**
   * a selector for a field value on a flattened Entity Representation (such as from idP/LDAP)
   *
   * @generated from field: string subject_external_selector_value = 1;
   */
  subjectExternalSelectorValue: string;

  /**
   * the evaluation operator of relation
   *
   * @generated from field: policy.SubjectMappingOperatorEnum operator = 2;
   */
  operator: SubjectMappingOperatorEnum;

  /**
   * list of comparison values for the result of applying the subject_external_selector_value on a flattened Entity Representation (Subject), evaluated by the operator
   *
   * @generated from field: repeated string subject_external_values = 3;
   */
  subjectExternalValues: string[];
};

/**
 * Describes the message policy.Condition.
 * Use `create(ConditionSchema)` to create a new message.
 */
export declare const ConditionSchema: GenMessage<Condition>;

/**
 * A collection of Conditions evaluated by the boolean_operator provided
 *
 * @generated from message policy.ConditionGroup
 */
export declare type ConditionGroup = Message<"policy.ConditionGroup"> & {
  /**
   * @generated from field: repeated policy.Condition conditions = 1;
   */
  conditions: Condition[];

  /**
   * the boolean evaluation type across the conditions
   *
   * @generated from field: policy.ConditionBooleanTypeEnum boolean_operator = 2;
   */
  booleanOperator: ConditionBooleanTypeEnum;
};

/**
 * Describes the message policy.ConditionGroup.
 * Use `create(ConditionGroupSchema)` to create a new message.
 */
export declare const ConditionGroupSchema: GenMessage<ConditionGroup>;

/**
 * A collection of Condition Groups
 *
 * @generated from message policy.SubjectSet
 */
export declare type SubjectSet = Message<"policy.SubjectSet"> & {
  /**
   * multiple Condition Groups are evaluated with AND logic
   *
   * @generated from field: repeated policy.ConditionGroup condition_groups = 1;
   */
  conditionGroups: ConditionGroup[];
};

/**
 * Describes the message policy.SubjectSet.
 * Use `create(SubjectSetSchema)` to create a new message.
 */
export declare const SubjectSetSchema: GenMessage<SubjectSet>;

/**
 *
 * A container for multiple Subject Sets, each containing Condition Groups, each containing Conditions. Multiple Subject Sets in a SubjectConditionSet
 * are evaluated with AND logic. As each Subject Mapping has only one Attribute Value, the SubjectConditionSet is reusable across multiple
 * Subject Mappings / Attribute Values and is an independent unit.
 *
 * @generated from message policy.SubjectConditionSet
 */
export declare type SubjectConditionSet = Message<"policy.SubjectConditionSet"> & {
  /**
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * @generated from field: repeated policy.SubjectSet subject_sets = 3;
   */
  subjectSets: SubjectSet[];

  /**
   * @generated from field: common.Metadata metadata = 100;
   */
  metadata?: Metadata;
};

/**
 * Describes the message policy.SubjectConditionSet.
 * Use `create(SubjectConditionSetSchema)` to create a new message.
 */
export declare const SubjectConditionSetSchema: GenMessage<SubjectConditionSet>;

/**
 *
 *
 * A property of a Subject/Entity as its selector expression -> value result pair. This would mirror external user attributes retrieved
 * from an authoritative source such as an IDP (Identity Provider) or User Store. Examples include such ADFS/LDAP, OKTA, etc.
 * For now, a valid property must contain both a selector expression & a resulting value.
 *
 * The external_selector_value is a specifier to select a value from a flattened external representation of an Entity (such as from idP/LDAP),
 * and the external_value is the value selected by the external_selector_value on that Entity Representation (Subject Context). These mirror the Condition.
 *
 * @generated from message policy.SubjectProperty
 */
export declare type SubjectProperty = Message<"policy.SubjectProperty"> & {
  /**
   * @generated from field: string external_selector_value = 1;
   */
  externalSelectorValue: string;

  /**
   * @generated from field: string external_value = 2;
   */
  externalValue: string;
};

/**
 * Describes the message policy.SubjectProperty.
 * Use `create(SubjectPropertySchema)` to create a new message.
 */
export declare const SubjectPropertySchema: GenMessage<SubjectProperty>;

/**
 *
 * Resource Mapping Groups are namespaced collections of Resource Mappings associated under a common group name.
 *
 * @generated from message policy.ResourceMappingGroup
 */
export declare type ResourceMappingGroup = Message<"policy.ResourceMappingGroup"> & {
  /**
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * the namespace containing the group of resource mappings
   *
   * @generated from field: string namespace_id = 2;
   */
  namespaceId: string;

  /**
   * the common name for the group of resource mappings, which must be unique per namespace
   *
   * @generated from field: string name = 3;
   */
  name: string;

  /**
   * Common metadata
   *
   * @generated from field: common.Metadata metadata = 100;
   */
  metadata?: Metadata;
};

/**
 * Describes the message policy.ResourceMappingGroup.
 * Use `create(ResourceMappingGroupSchema)` to create a new message.
 */
export declare const ResourceMappingGroupSchema: GenMessage<ResourceMappingGroup>;

/**
 *
 * Resource Mappings (aka Access Control Resource Encodings aka ACRE) are structures supporting the mapping of Resources and Attribute Values
 *
 * @generated from message policy.ResourceMapping
 */
export declare type ResourceMapping = Message<"policy.ResourceMapping"> & {
  /**
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * @generated from field: common.Metadata metadata = 2;
   */
  metadata?: Metadata;

  /**
   * @generated from field: policy.Value attribute_value = 3;
   */
  attributeValue?: Value;

  /**
   * @generated from field: repeated string terms = 4;
   */
  terms: string[];

  /**
   * @generated from field: policy.ResourceMappingGroup group = 5;
   */
  group?: ResourceMappingGroup;
};

/**
 * Describes the message policy.ResourceMapping.
 * Use `create(ResourceMappingSchema)` to create a new message.
 */
export declare const ResourceMappingSchema: GenMessage<ResourceMapping>;

/**
 *
 * Key Access Server Registry
 *
 * @generated from message policy.KeyAccessServer
 */
export declare type KeyAccessServer = Message<"policy.KeyAccessServer"> & {
  /**
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * Address of a KAS instance
   *
   * @generated from field: string uri = 2;
   */
  uri: string;

  /**
   * @generated from field: policy.PublicKey public_key = 3;
   */
  publicKey?: PublicKey;

  /**
   * Optional
   * Unique name of the KAS instance
   *
   * @generated from field: string name = 20;
   */
  name: string;

  /**
   * Common metadata
   *
   * @generated from field: common.Metadata metadata = 100;
   */
  metadata?: Metadata;
};

/**
 * Describes the message policy.KeyAccessServer.
 * Use `create(KeyAccessServerSchema)` to create a new message.
 */
export declare const KeyAccessServerSchema: GenMessage<KeyAccessServer>;

/**
 * A KAS public key and some associated metadata for further identifcation
 *
 * @generated from message policy.KasPublicKey
 */
export declare type KasPublicKey = Message<"policy.KasPublicKey"> & {
  /**
   * x509 ASN.1 content in PEM envelope, usually
   *
   * @generated from field: string pem = 1;
   */
  pem: string;

  /**
   * A unique string identifier for this key
   *
   * @generated from field: string kid = 2;
   */
  kid: string;

  /**
   * A known algorithm type with any additional parameters encoded.
   * To start, these may be `rsa:2048` for encrypting ZTDF files and 
   * `ec:secp256r1` for nanoTDF, but more formats may be added as needed.
   *
   * @generated from field: policy.KasPublicKeyAlgEnum alg = 3;
   */
  alg: KasPublicKeyAlgEnum;
};

/**
 * Describes the message policy.KasPublicKey.
 * Use `create(KasPublicKeySchema)` to create a new message.
 */
export declare const KasPublicKeySchema: GenMessage<KasPublicKey>;

/**
 * A list of known KAS public keys
 *
 * @generated from message policy.KasPublicKeySet
 */
export declare type KasPublicKeySet = Message<"policy.KasPublicKeySet"> & {
  /**
   * @generated from field: repeated policy.KasPublicKey keys = 1;
   */
  keys: KasPublicKey[];
};

/**
 * Describes the message policy.KasPublicKeySet.
 * Use `create(KasPublicKeySetSchema)` to create a new message.
 */
export declare const KasPublicKeySetSchema: GenMessage<KasPublicKeySet>;

/**
 * @generated from message policy.PublicKey
 */
export declare type PublicKey = Message<"policy.PublicKey"> & {
  /**
   * @generated from oneof policy.PublicKey.public_key
   */
  publicKey: {
    /**
     * kas public key url - optional since can also be retrieved via public key
     *
     * @generated from field: string remote = 1;
     */
    value: string;
    case: "remote";
  } | {
    /**
     * public key with additional information. Current preferred version
     *
     * @generated from field: policy.KasPublicKeySet cached = 3;
     */
    value: KasPublicKeySet;
    case: "cached";
  } | { case: undefined; value?: undefined };
};

/**
 * Describes the message policy.PublicKey.
 * Use `create(PublicKeySchema)` to create a new message.
 */
export declare const PublicKeySchema: GenMessage<PublicKey>;

/**
 * buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package
 *
 * @generated from enum policy.AttributeRuleTypeEnum
 */
export enum AttributeRuleTypeEnum {
  /**
   * @generated from enum value: ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * @generated from enum value: ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF = 1;
   */
  ALL_OF = 1,

  /**
   * @generated from enum value: ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF = 2;
   */
  ANY_OF = 2,

  /**
   * @generated from enum value: ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY = 3;
   */
  HIERARCHY = 3,
}

/**
 * Describes the enum policy.AttributeRuleTypeEnum.
 */
export declare const AttributeRuleTypeEnumSchema: GenEnum<AttributeRuleTypeEnum>;

/**
 * buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package
 *
 * @generated from enum policy.SubjectMappingOperatorEnum
 */
export enum SubjectMappingOperatorEnum {
  /**
   * @generated from enum value: SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * operator that returns true if a value in a list matches the string
   *
   * @generated from enum value: SUBJECT_MAPPING_OPERATOR_ENUM_IN = 1;
   */
  IN = 1,

  /**
   * operator that returns true if a value is not in a list that is matched by string
   *
   * @generated from enum value: SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN = 2;
   */
  NOT_IN = 2,

  /**
   * operator that returns true if a value in a list contains the substring
   *
   * @generated from enum value: SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS = 3;
   */
  IN_CONTAINS = 3,
}

/**
 * Describes the enum policy.SubjectMappingOperatorEnum.
 */
export declare const SubjectMappingOperatorEnumSchema: GenEnum<SubjectMappingOperatorEnum>;

/**
 * buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package
 *
 * @generated from enum policy.ConditionBooleanTypeEnum
 */
export enum ConditionBooleanTypeEnum {
  /**
   * @generated from enum value: CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * @generated from enum value: CONDITION_BOOLEAN_TYPE_ENUM_AND = 1;
   */
  AND = 1,

  /**
   * @generated from enum value: CONDITION_BOOLEAN_TYPE_ENUM_OR = 2;
   */
  OR = 2,
}

/**
 * Describes the enum policy.ConditionBooleanTypeEnum.
 */
export declare const ConditionBooleanTypeEnumSchema: GenEnum<ConditionBooleanTypeEnum>;

/**
 * @generated from enum policy.KasPublicKeyAlgEnum
 */
export enum KasPublicKeyAlgEnum {
  /**
   * @generated from enum value: KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * @generated from enum value: KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048 = 1;
   */
  RSA_2048 = 1,

  /**
   * @generated from enum value: KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1 = 5;
   */
  EC_SECP256R1 = 5,
}

/**
 * Describes the enum policy.KasPublicKeyAlgEnum.
 */
export declare const KasPublicKeyAlgEnumSchema: GenEnum<KasPublicKeyAlgEnum>;

