// @generated by protoc-gen-es v2.2.1
// @generated from file policy/namespaces/namespaces.proto (package policy.namespaces, syntax proto3)
/* eslint-disable */

import type { GenFile, GenMessage, GenService } from "@bufbuild/protobuf/codegenv1";
import type { Message } from "@bufbuild/protobuf";
import type { Namespace } from "../objects_pb";
import type { ActiveStateEnum, MetadataMutable, MetadataUpdateEnum } from "../../common/common_pb";
import type { PageRequest, PageResponse } from "../selectors_pb";

/**
 * Describes the file policy/namespaces/namespaces.proto.
 */
export declare const file_policy_namespaces_namespaces: GenFile;

/**
 * @generated from message policy.namespaces.NamespaceKeyAccessServer
 */
export declare type NamespaceKeyAccessServer = Message<"policy.namespaces.NamespaceKeyAccessServer"> & {
  /**
   * Required
   *
   * @generated from field: string namespace_id = 1;
   */
  namespaceId: string;

  /**
   * Required
   *
   * @generated from field: string key_access_server_id = 2;
   */
  keyAccessServerId: string;
};

/**
 * Describes the message policy.namespaces.NamespaceKeyAccessServer.
 * Use `create(NamespaceKeyAccessServerSchema)` to create a new message.
 */
export declare const NamespaceKeyAccessServerSchema: GenMessage<NamespaceKeyAccessServer>;

/**
 * @generated from message policy.namespaces.GetNamespaceRequest
 */
export declare type GetNamespaceRequest = Message<"policy.namespaces.GetNamespaceRequest"> & {
  /**
   * Required
   *
   * @generated from field: string id = 1;
   */
  id: string;
};

/**
 * Describes the message policy.namespaces.GetNamespaceRequest.
 * Use `create(GetNamespaceRequestSchema)` to create a new message.
 */
export declare const GetNamespaceRequestSchema: GenMessage<GetNamespaceRequest>;

/**
 * @generated from message policy.namespaces.GetNamespaceResponse
 */
export declare type GetNamespaceResponse = Message<"policy.namespaces.GetNamespaceResponse"> & {
  /**
   * @generated from field: policy.Namespace namespace = 1;
   */
  namespace?: Namespace;
};

/**
 * Describes the message policy.namespaces.GetNamespaceResponse.
 * Use `create(GetNamespaceResponseSchema)` to create a new message.
 */
export declare const GetNamespaceResponseSchema: GenMessage<GetNamespaceResponse>;

/**
 * @generated from message policy.namespaces.ListNamespacesRequest
 */
export declare type ListNamespacesRequest = Message<"policy.namespaces.ListNamespacesRequest"> & {
  /**
   * Optional
   * ACTIVE by default when not specified
   *
   * @generated from field: common.ActiveStateEnum state = 1;
   */
  state: ActiveStateEnum;

  /**
   * Optional
   *
   * @generated from field: policy.PageRequest pagination = 10;
   */
  pagination?: PageRequest;
};

/**
 * Describes the message policy.namespaces.ListNamespacesRequest.
 * Use `create(ListNamespacesRequestSchema)` to create a new message.
 */
export declare const ListNamespacesRequestSchema: GenMessage<ListNamespacesRequest>;

/**
 * @generated from message policy.namespaces.ListNamespacesResponse
 */
export declare type ListNamespacesResponse = Message<"policy.namespaces.ListNamespacesResponse"> & {
  /**
   * @generated from field: repeated policy.Namespace namespaces = 1;
   */
  namespaces: Namespace[];

  /**
   * @generated from field: policy.PageResponse pagination = 10;
   */
  pagination?: PageResponse;
};

/**
 * Describes the message policy.namespaces.ListNamespacesResponse.
 * Use `create(ListNamespacesResponseSchema)` to create a new message.
 */
export declare const ListNamespacesResponseSchema: GenMessage<ListNamespacesResponse>;

/**
 * @generated from message policy.namespaces.CreateNamespaceRequest
 */
export declare type CreateNamespaceRequest = Message<"policy.namespaces.CreateNamespaceRequest"> & {
  /**
   * Required
   *
   * @generated from field: string name = 1;
   */
  name: string;

  /**
   * Optional
   *
   * @generated from field: common.MetadataMutable metadata = 100;
   */
  metadata?: MetadataMutable;
};

/**
 * Describes the message policy.namespaces.CreateNamespaceRequest.
 * Use `create(CreateNamespaceRequestSchema)` to create a new message.
 */
export declare const CreateNamespaceRequestSchema: GenMessage<CreateNamespaceRequest>;

/**
 * @generated from message policy.namespaces.CreateNamespaceResponse
 */
export declare type CreateNamespaceResponse = Message<"policy.namespaces.CreateNamespaceResponse"> & {
  /**
   * @generated from field: policy.Namespace namespace = 1;
   */
  namespace?: Namespace;
};

/**
 * Describes the message policy.namespaces.CreateNamespaceResponse.
 * Use `create(CreateNamespaceResponseSchema)` to create a new message.
 */
export declare const CreateNamespaceResponseSchema: GenMessage<CreateNamespaceResponse>;

/**
 * @generated from message policy.namespaces.UpdateNamespaceRequest
 */
export declare type UpdateNamespaceRequest = Message<"policy.namespaces.UpdateNamespaceRequest"> & {
  /**
   * Required
   *
   * @generated from field: string id = 1;
   */
  id: string;

  /**
   * Optional
   *
   * @generated from field: common.MetadataMutable metadata = 100;
   */
  metadata?: MetadataMutable;

  /**
   * @generated from field: common.MetadataUpdateEnum metadata_update_behavior = 101;
   */
  metadataUpdateBehavior: MetadataUpdateEnum;
};

/**
 * Describes the message policy.namespaces.UpdateNamespaceRequest.
 * Use `create(UpdateNamespaceRequestSchema)` to create a new message.
 */
export declare const UpdateNamespaceRequestSchema: GenMessage<UpdateNamespaceRequest>;

/**
 * @generated from message policy.namespaces.UpdateNamespaceResponse
 */
export declare type UpdateNamespaceResponse = Message<"policy.namespaces.UpdateNamespaceResponse"> & {
  /**
   * @generated from field: policy.Namespace namespace = 1;
   */
  namespace?: Namespace;
};

/**
 * Describes the message policy.namespaces.UpdateNamespaceResponse.
 * Use `create(UpdateNamespaceResponseSchema)` to create a new message.
 */
export declare const UpdateNamespaceResponseSchema: GenMessage<UpdateNamespaceResponse>;

/**
 * @generated from message policy.namespaces.DeactivateNamespaceRequest
 */
export declare type DeactivateNamespaceRequest = Message<"policy.namespaces.DeactivateNamespaceRequest"> & {
  /**
   * Required
   *
   * @generated from field: string id = 1;
   */
  id: string;
};

/**
 * Describes the message policy.namespaces.DeactivateNamespaceRequest.
 * Use `create(DeactivateNamespaceRequestSchema)` to create a new message.
 */
export declare const DeactivateNamespaceRequestSchema: GenMessage<DeactivateNamespaceRequest>;

/**
 * @generated from message policy.namespaces.DeactivateNamespaceResponse
 */
export declare type DeactivateNamespaceResponse = Message<"policy.namespaces.DeactivateNamespaceResponse"> & {
};

/**
 * Describes the message policy.namespaces.DeactivateNamespaceResponse.
 * Use `create(DeactivateNamespaceResponseSchema)` to create a new message.
 */
export declare const DeactivateNamespaceResponseSchema: GenMessage<DeactivateNamespaceResponse>;

/**
 * @generated from message policy.namespaces.AssignKeyAccessServerToNamespaceRequest
 */
export declare type AssignKeyAccessServerToNamespaceRequest = Message<"policy.namespaces.AssignKeyAccessServerToNamespaceRequest"> & {
  /**
   * @generated from field: policy.namespaces.NamespaceKeyAccessServer namespace_key_access_server = 1;
   */
  namespaceKeyAccessServer?: NamespaceKeyAccessServer;
};

/**
 * Describes the message policy.namespaces.AssignKeyAccessServerToNamespaceRequest.
 * Use `create(AssignKeyAccessServerToNamespaceRequestSchema)` to create a new message.
 */
export declare const AssignKeyAccessServerToNamespaceRequestSchema: GenMessage<AssignKeyAccessServerToNamespaceRequest>;

/**
 * @generated from message policy.namespaces.AssignKeyAccessServerToNamespaceResponse
 */
export declare type AssignKeyAccessServerToNamespaceResponse = Message<"policy.namespaces.AssignKeyAccessServerToNamespaceResponse"> & {
  /**
   * @generated from field: policy.namespaces.NamespaceKeyAccessServer namespace_key_access_server = 1;
   */
  namespaceKeyAccessServer?: NamespaceKeyAccessServer;
};

/**
 * Describes the message policy.namespaces.AssignKeyAccessServerToNamespaceResponse.
 * Use `create(AssignKeyAccessServerToNamespaceResponseSchema)` to create a new message.
 */
export declare const AssignKeyAccessServerToNamespaceResponseSchema: GenMessage<AssignKeyAccessServerToNamespaceResponse>;

/**
 * @generated from message policy.namespaces.RemoveKeyAccessServerFromNamespaceRequest
 */
export declare type RemoveKeyAccessServerFromNamespaceRequest = Message<"policy.namespaces.RemoveKeyAccessServerFromNamespaceRequest"> & {
  /**
   * @generated from field: policy.namespaces.NamespaceKeyAccessServer namespace_key_access_server = 1;
   */
  namespaceKeyAccessServer?: NamespaceKeyAccessServer;
};

/**
 * Describes the message policy.namespaces.RemoveKeyAccessServerFromNamespaceRequest.
 * Use `create(RemoveKeyAccessServerFromNamespaceRequestSchema)` to create a new message.
 */
export declare const RemoveKeyAccessServerFromNamespaceRequestSchema: GenMessage<RemoveKeyAccessServerFromNamespaceRequest>;

/**
 * @generated from message policy.namespaces.RemoveKeyAccessServerFromNamespaceResponse
 */
export declare type RemoveKeyAccessServerFromNamespaceResponse = Message<"policy.namespaces.RemoveKeyAccessServerFromNamespaceResponse"> & {
  /**
   * @generated from field: policy.namespaces.NamespaceKeyAccessServer namespace_key_access_server = 1;
   */
  namespaceKeyAccessServer?: NamespaceKeyAccessServer;
};

/**
 * Describes the message policy.namespaces.RemoveKeyAccessServerFromNamespaceResponse.
 * Use `create(RemoveKeyAccessServerFromNamespaceResponseSchema)` to create a new message.
 */
export declare const RemoveKeyAccessServerFromNamespaceResponseSchema: GenMessage<RemoveKeyAccessServerFromNamespaceResponse>;

/**
 * @generated from service policy.namespaces.NamespaceService
 */
export declare const NamespaceService: GenService<{
  /**
   * @generated from rpc policy.namespaces.NamespaceService.GetNamespace
   */
  getNamespace: {
    methodKind: "unary";
    input: typeof GetNamespaceRequestSchema;
    output: typeof GetNamespaceResponseSchema;
  },
  /**
   * @generated from rpc policy.namespaces.NamespaceService.ListNamespaces
   */
  listNamespaces: {
    methodKind: "unary";
    input: typeof ListNamespacesRequestSchema;
    output: typeof ListNamespacesResponseSchema;
  },
  /**
   * @generated from rpc policy.namespaces.NamespaceService.CreateNamespace
   */
  createNamespace: {
    methodKind: "unary";
    input: typeof CreateNamespaceRequestSchema;
    output: typeof CreateNamespaceResponseSchema;
  },
  /**
   * @generated from rpc policy.namespaces.NamespaceService.UpdateNamespace
   */
  updateNamespace: {
    methodKind: "unary";
    input: typeof UpdateNamespaceRequestSchema;
    output: typeof UpdateNamespaceResponseSchema;
  },
  /**
   * @generated from rpc policy.namespaces.NamespaceService.DeactivateNamespace
   */
  deactivateNamespace: {
    methodKind: "unary";
    input: typeof DeactivateNamespaceRequestSchema;
    output: typeof DeactivateNamespaceResponseSchema;
  },
  /**
   * --------------------------------------*
   * Namespace <> Key Access Server RPCs
   * ---------------------------------------
   *
   * @generated from rpc policy.namespaces.NamespaceService.AssignKeyAccessServerToNamespace
   */
  assignKeyAccessServerToNamespace: {
    methodKind: "unary";
    input: typeof AssignKeyAccessServerToNamespaceRequestSchema;
    output: typeof AssignKeyAccessServerToNamespaceResponseSchema;
  },
  /**
   * @generated from rpc policy.namespaces.NamespaceService.RemoveKeyAccessServerFromNamespace
   */
  removeKeyAccessServerFromNamespace: {
    methodKind: "unary";
    input: typeof RemoveKeyAccessServerFromNamespaceRequestSchema;
    output: typeof RemoveKeyAccessServerFromNamespaceResponseSchema;
  },
}>;

