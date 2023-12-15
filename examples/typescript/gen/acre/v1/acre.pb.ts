/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as AttributesV1Attributes from "../../attributes/v1/attributes.pb"
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
export type ResourceMappingSet = {
  descriptor?: CommonV1Common.ResourceDescriptor
  mappings?: ResourceMappingRef[]
}

export type Synonyms = {
  descriptor?: CommonV1Common.ResourceDescriptor
  terms?: string[]
}

export type ResourceMapping = {
  descriptor?: CommonV1Common.ResourceDescriptor
  attributeValueRef?: AttributesV1Attributes.AttributeValueReference
  synonymRef?: SynonymRef
}

export type ResourceGroup = {
  descriptor?: CommonV1Common.ResourceDescriptor
  value?: string
  members?: string[]
}


type BaseResourceMappingRef = {
}

export type ResourceMappingRef = BaseResourceMappingRef
  & OneOf<{ descriptor: CommonV1Common.ResourceDescriptor; resourceMapping: ResourceMapping }>


type BaseSynonymRef = {
}

export type SynonymRef = BaseSynonymRef
  & OneOf<{ descriptor: CommonV1Common.ResourceDescriptor; synonyms: Synonyms }>

export type ResourceEncodingRequestOptions = {
  descriptor?: CommonV1Common.ResourceDescriptor
}

export type ListResourceMappingsRequest = {
  selector?: CommonV1Common.ResourceSelector
}

export type ListResourceMappingsResponse = {
  mappings?: ResourceMapping[]
}

export type GetResourceMappingRequest = {
  id?: string
  options?: ResourceEncodingRequestOptions
}

export type GetResourceMappingResponse = {
  mapping?: ResourceMapping
}

export type CreateResourceMappingRequest = {
  mapping?: ResourceMapping
}

export type CreateResourceMappingResponse = {
}

export type UpdateResourceMappingRequest = {
  id?: string
  mapping?: ResourceMapping
}

export type UpdateResourceMappingResponse = {
}

export type DeleteResourceMappingRequest = {
  id?: string
}

export type DeleteResourceMappingResponse = {
}

export type ListResourceSynonymsRequest = {
  selector?: CommonV1Common.ResourceSelector
}

export type ListResourceSynonymsResponse = {
  synonyms?: Synonyms[]
}

export type GetResourceSynonymRequest = {
  id?: string
  options?: ResourceEncodingRequestOptions
}

export type GetResourceSynonymResponse = {
  synonym?: Synonyms
}

export type CreateResourceSynonymRequest = {
  synonym?: Synonyms
}

export type CreateResourceSynonymResponse = {
}

export type UpdateResourceSynonymRequest = {
  id?: string
  synonym?: Synonyms
}

export type UpdateResourceSynonymResponse = {
}

export type DeleteResourceSynonymRequest = {
  id?: string
}

export type DeleteResourceSynonymResponse = {
}

export type ListResourceGroupsRequest = {
  selector?: CommonV1Common.ResourceSelector
}

export type ListResourceGroupsResponse = {
  groups?: ResourceGroup[]
}

export type GetResourceGroupRequest = {
  id?: string
  options?: ResourceEncodingRequestOptions
}

export type GetResourceGroupResponse = {
  group?: ResourceGroup
}

export type CreateResourceGroupRequest = {
  group?: ResourceGroup
}

export type CreateResourceGroupResponse = {
}

export type UpdateResourceGroupRequest = {
  id?: string
  group?: ResourceGroup
}

export type UpdateResourceGroupResponse = {
}

export type DeleteResourceGroupRequest = {
  id?: string
}

export type DeleteResourceGroupResponse = {
}

export class ResourcEncodingService {
  static ListResourceMappings(req: ListResourceMappingsRequest, initReq?: fm.InitReq): Promise<ListResourceMappingsResponse> {
    return fm.fetchReq<ListResourceMappingsRequest, ListResourceMappingsResponse>(`/v1/encoding/resource/mappings?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetResourceMapping(req: GetResourceMappingRequest, initReq?: fm.InitReq): Promise<GetResourceMappingResponse> {
    return fm.fetchReq<GetResourceMappingRequest, GetResourceMappingResponse>(`/v1/encoding/resource/mappings/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateResourceMapping(req: CreateResourceMappingRequest, initReq?: fm.InitReq): Promise<CreateResourceMappingResponse> {
    return fm.fetchReq<CreateResourceMappingRequest, CreateResourceMappingResponse>(`/v1/encoding/resource/mappings`, {...initReq, method: "POST", body: JSON.stringify(req["mapping"], fm.replacer)})
  }
  static UpdateResourceMapping(req: UpdateResourceMappingRequest, initReq?: fm.InitReq): Promise<UpdateResourceMappingResponse> {
    return fm.fetchReq<UpdateResourceMappingRequest, UpdateResourceMappingResponse>(`/v1/encoding/resource/mappings/${req["id"]}`, {...initReq, method: "POST", body: JSON.stringify(req["mapping"], fm.replacer)})
  }
  static DeleteResourceMapping(req: DeleteResourceMappingRequest, initReq?: fm.InitReq): Promise<DeleteResourceMappingResponse> {
    return fm.fetchReq<DeleteResourceMappingRequest, DeleteResourceMappingResponse>(`/v1/encoding/resource/mappings/${req["id"]}`, {...initReq, method: "DELETE"})
  }
  static ListResourceSynonyms(req: ListResourceSynonymsRequest, initReq?: fm.InitReq): Promise<ListResourceSynonymsResponse> {
    return fm.fetchReq<ListResourceSynonymsRequest, ListResourceSynonymsResponse>(`/v1/encoding/resource/synonyms?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetResourceSynonym(req: GetResourceSynonymRequest, initReq?: fm.InitReq): Promise<GetResourceSynonymResponse> {
    return fm.fetchReq<GetResourceSynonymRequest, GetResourceSynonymResponse>(`/v1/encoding/resource/synonyms/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateResourceSynonym(req: CreateResourceSynonymRequest, initReq?: fm.InitReq): Promise<CreateResourceSynonymResponse> {
    return fm.fetchReq<CreateResourceSynonymRequest, CreateResourceSynonymResponse>(`/v1/encoding/resource/synonyms`, {...initReq, method: "POST", body: JSON.stringify(req["synonym"], fm.replacer)})
  }
  static UpdateResourceSynonym(req: UpdateResourceSynonymRequest, initReq?: fm.InitReq): Promise<UpdateResourceSynonymResponse> {
    return fm.fetchReq<UpdateResourceSynonymRequest, UpdateResourceSynonymResponse>(`/v1/encoding/resource/synonyms/${req["id"]}`, {...initReq, method: "POST", body: JSON.stringify(req["synonym"], fm.replacer)})
  }
  static DeleteResourceSynonym(req: DeleteResourceSynonymRequest, initReq?: fm.InitReq): Promise<DeleteResourceSynonymResponse> {
    return fm.fetchReq<DeleteResourceSynonymRequest, DeleteResourceSynonymResponse>(`/v1/encoding/resource/synonyms/${req["id"]}`, {...initReq, method: "DELETE"})
  }
  static ListResourceGroups(req: ListResourceGroupsRequest, initReq?: fm.InitReq): Promise<ListResourceGroupsResponse> {
    return fm.fetchReq<ListResourceGroupsRequest, ListResourceGroupsResponse>(`/v1/encoding/resource/groups?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetResourceGroup(req: GetResourceGroupRequest, initReq?: fm.InitReq): Promise<GetResourceGroupResponse> {
    return fm.fetchReq<GetResourceGroupRequest, GetResourceGroupResponse>(`/v1/encoding/resource/groups/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateResourceGroup(req: CreateResourceGroupRequest, initReq?: fm.InitReq): Promise<CreateResourceGroupResponse> {
    return fm.fetchReq<CreateResourceGroupRequest, CreateResourceGroupResponse>(`/v1/encoding/resource/groups`, {...initReq, method: "POST", body: JSON.stringify(req["group"], fm.replacer)})
  }
  static UpdateResourceGroup(req: UpdateResourceGroupRequest, initReq?: fm.InitReq): Promise<UpdateResourceGroupResponse> {
    return fm.fetchReq<UpdateResourceGroupRequest, UpdateResourceGroupResponse>(`/v1/encoding/resource/groups/${req["id"]}`, {...initReq, method: "POST", body: JSON.stringify(req["group"], fm.replacer)})
  }
  static DeleteResourceGroup(req: DeleteResourceGroupRequest, initReq?: fm.InitReq): Promise<DeleteResourceGroupResponse> {
    return fm.fetchReq<DeleteResourceGroupRequest, DeleteResourceGroupResponse>(`/v1/encoding/resource/groups/${req["id"]}`, {...initReq, method: "DELETE"})
  }
}