/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as CommonV1Common from "../../common/v1/common.pb"
import * as fm from "../../fetch.pb"

type Absent<T, K extends keyof T> = { [k in Exclude<keyof T, K>]?: undefined };
type OneOf<T> =
  | { [k in keyof T]?: undefined }
  | (
    keyof T extends infer K ?
      (K extends string & keyof T ? { [k in K]: T[K] } & Absent<T, K>
        : never)
    : never);

export enum AttributeDefinitionAttributeRuleType {
  ATTRIBUTE_RULE_TYPE_UNSPECIFIED = "ATTRIBUTE_RULE_TYPE_UNSPECIFIED",
  ATTRIBUTE_RULE_TYPE_ALL_OF = "ATTRIBUTE_RULE_TYPE_ALL_OF",
  ATTRIBUTE_RULE_TYPE_ANY_OF = "ATTRIBUTE_RULE_TYPE_ANY_OF",
  ATTRIBUTE_RULE_TYPE_HIERARCHICAL = "ATTRIBUTE_RULE_TYPE_HIERARCHICAL",
}

export type AttributeSet = {
  descriptor?: CommonV1Common.ResourceDescriptor
  definitions?: AttributeDefinition[]
}

export type AttributeDefinition = {
  descriptor?: CommonV1Common.ResourceDescriptor
  name?: string
  rule?: AttributeDefinitionAttributeRuleType
  values?: AttributeDefinitionValue[]
  groupBy?: AttributeDefinitionValue[]
}


type BaseAttributeDefinitionReference = {
}

export type AttributeDefinitionReference = BaseAttributeDefinitionReference
  & OneOf<{ descriptor: CommonV1Common.ResourceDescriptor; definition: AttributeDefinition }>

export type AttributeDefinitionValue = {
  descriptor?: CommonV1Common.ResourceDescriptor
  value?: string
  attributePublicKey?: string
}


type BaseAttributeValueReference = {
}

export type AttributeValueReference = BaseAttributeValueReference
  & OneOf<{ descriptor: CommonV1Common.ResourceDescriptor; attributeValue: AttributeDefinitionValue }>

export type AttributeGroup = {
  descriptor?: CommonV1Common.ResourceDescriptor
  groupValue?: AttributeValueReference
  memberValues?: AttributeValueReference[]
}

export type AttributeGroupSet = {
  descriptor?: CommonV1Common.ResourceDescriptor
  groups?: AttributeGroup[]
}

export type AttributeRequestOptions = {
}

export type GetAttributeRequest = {
  id?: string
  options?: AttributeRequestOptions
}

export type GetAttributeResponse = {
  definition?: AttributeDefinition
}

export type ListAttributesRequest = {
  selector?: CommonV1Common.ResourceSelector
}

export type ListAttributesResponse = {
  definitions?: AttributeDefinition[]
}

export type CreateAttributeRequest = {
  definition?: AttributeDefinition
}

export type CreateAttributeResponse = {
}

export type UpdateAttributeRequest = {
  id?: string
  definition?: AttributeDefinition
}

export type UpdateAttributeResponse = {
}

export type DeleteAttributeRequest = {
  id?: string
}

export type DeleteAttributeResponse = {
}

export type GetAttributeGroupRequest = {
  id?: string
  options?: AttributeRequestOptions
}

export type GetAttributeGroupResponse = {
  group?: AttributeGroup
}

export type ListAttributeGroupsRequest = {
  selector?: CommonV1Common.ResourceSelector
}

export type ListAttributeGroupsResponse = {
  groups?: AttributeGroup[]
}

export type CreateAttributeGroupRequest = {
  group?: AttributeGroup
}

export type CreateAttributeGroupResponse = {
}

export type UpdateAttributeGroupRequest = {
  id?: string
  group?: AttributeGroup
}

export type UpdateAttributeGroupResponse = {
}

export type DeleteAttributeGroupRequest = {
  id?: string
}

export type DeleteAttributeGroupResponse = {
}

export class AttributesService {
  static GetAttribute(req: GetAttributeRequest, initReq?: fm.InitReq): Promise<GetAttributeResponse> {
    return fm.fetchReq<GetAttributeRequest, GetAttributeResponse>(`/v1/attribute/definitions/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static GetAttributeGroup(req: GetAttributeGroupRequest, initReq?: fm.InitReq): Promise<GetAttributeGroupResponse> {
    return fm.fetchReq<GetAttributeGroupRequest, GetAttributeGroupResponse>(`/v1/attribute/groups/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static ListAttributes(req: ListAttributesRequest, initReq?: fm.InitReq): Promise<ListAttributesResponse> {
    return fm.fetchReq<ListAttributesRequest, ListAttributesResponse>(`/v1/attribute/definitions?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static ListAttributeGroups(req: ListAttributeGroupsRequest, initReq?: fm.InitReq): Promise<ListAttributeGroupsResponse> {
    return fm.fetchReq<ListAttributeGroupsRequest, ListAttributeGroupsResponse>(`/v1/attribute/groups?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static CreateAttribute(req: CreateAttributeRequest, initReq?: fm.InitReq): Promise<CreateAttributeResponse> {
    return fm.fetchReq<CreateAttributeRequest, CreateAttributeResponse>(`/v1/attributes/definitions`, {...initReq, method: "POST", body: JSON.stringify(req["definition"], fm.replacer)})
  }
  static CreateAttributeGroup(req: CreateAttributeGroupRequest, initReq?: fm.InitReq): Promise<CreateAttributeGroupResponse> {
    return fm.fetchReq<CreateAttributeGroupRequest, CreateAttributeGroupResponse>(`/v1/attributes/groups`, {...initReq, method: "POST", body: JSON.stringify(req["group"], fm.replacer)})
  }
  static UpdateAttribute(req: UpdateAttributeRequest, initReq?: fm.InitReq): Promise<UpdateAttributeResponse> {
    return fm.fetchReq<UpdateAttributeRequest, UpdateAttributeResponse>(`/v1/attribute/definitions/${req["id"]}`, {...initReq, method: "POST", body: JSON.stringify(req["definition"], fm.replacer)})
  }
  static UpdateAttributeGroup(req: UpdateAttributeGroupRequest, initReq?: fm.InitReq): Promise<UpdateAttributeGroupResponse> {
    return fm.fetchReq<UpdateAttributeGroupRequest, UpdateAttributeGroupResponse>(`/v1/attribute/groups/${req["id"]}`, {...initReq, method: "POST", body: JSON.stringify(req["group"], fm.replacer)})
  }
  static DeleteAttribute(req: DeleteAttributeRequest, initReq?: fm.InitReq): Promise<DeleteAttributeResponse> {
    return fm.fetchReq<DeleteAttributeRequest, DeleteAttributeResponse>(`/v1/attribute/definitions/${req["id"]}`, {...initReq, method: "DELETE"})
  }
  static DeleteAttributeGroup(req: DeleteAttributeGroupRequest, initReq?: fm.InitReq): Promise<DeleteAttributeGroupResponse> {
    return fm.fetchReq<DeleteAttributeGroupRequest, DeleteAttributeGroupResponse>(`/v1/attribute/groups/${req["id"]}`, {...initReq, method: "DELETE"})
  }
}