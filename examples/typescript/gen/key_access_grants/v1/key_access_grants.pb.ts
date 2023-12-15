/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as AttributesV1Attributes from "../../attributes/v1/attributes.pb"
import * as CommonV1Common from "../../common/v1/common.pb"
import * as fm from "../../fetch.pb"
export type KeyAccessServer = {
  descriptor?: CommonV1Common.ResourceDescriptor
  url?: string
  publiKey?: string
}

export type KeyAccessGrants = {
  descriptor?: CommonV1Common.ResourceDescriptor
  keyAccessServers?: KeyAccessServer[]
  keyAccessGrants?: KeyAccessGrant[]
}

export type KeyAccessGrant = {
  attributeDefinition?: AttributesV1Attributes.AttributeDefinition
  attributeValueGrants?: KeyAccessGrantAttributeValue[]
}

export type KeyAccessGrantAttributeValue = {
  value?: AttributesV1Attributes.AttributeValueReference
  kasIds?: string[]
}

export type KeyAccessGrantsRequestOptions = {
}

export type GetKeyAccessGrantRequest = {
  id?: string
  options?: KeyAccessGrantsRequestOptions
}

export type GetKeyAccessGrantResponse = {
  grant?: KeyAccessGrant
}

export type ListKeyAccessGrantsRequest = {
  options?: KeyAccessGrantsRequestOptions
}

export type ListKeyAccessGrantsResponse = {
  grants?: KeyAccessGrant[]
}

export type CreateKeyAccessGrantsRequest = {
}

export type CreateKeyAccessGrantsResponse = {
}

export type UpdateKeyAccessGrantsRequest = {
  id?: string
  grant?: KeyAccessGrant
}

export type UpdateKeyAccessGrantsResponse = {
}

export type DeleteKeyAccessGrantsRequest = {
  id?: string
}

export type DeleteKeyAccessGrantsResponse = {
}

export class KeyAccessGrantsService {
  static ListKeyAccessGrants(req: ListKeyAccessGrantsRequest, initReq?: fm.InitReq): Promise<ListKeyAccessGrantsResponse> {
    return fm.fetchReq<ListKeyAccessGrantsRequest, ListKeyAccessGrantsResponse>(`/v1/grants?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetKeyAccessGrant(req: GetKeyAccessGrantRequest, initReq?: fm.InitReq): Promise<GetKeyAccessGrantResponse> {
    return fm.fetchReq<GetKeyAccessGrantRequest, GetKeyAccessGrantResponse>(`/v1/grants/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateKeyAccessGrants(req: CreateKeyAccessGrantsRequest, initReq?: fm.InitReq): Promise<CreateKeyAccessGrantsResponse> {
    return fm.fetchReq<CreateKeyAccessGrantsRequest, CreateKeyAccessGrantsResponse>(`/v1/grants`, {...initReq, method: "POST", body: JSON.stringify(req, fm.replacer)})
  }
  static UpdateKeyAccessGrants(req: UpdateKeyAccessGrantsRequest, initReq?: fm.InitReq): Promise<UpdateKeyAccessGrantsResponse> {
    return fm.fetchReq<UpdateKeyAccessGrantsRequest, UpdateKeyAccessGrantsResponse>(`/v1/grants/${req["id"]}`, {...initReq, method: "PUT", body: JSON.stringify(req["grant"], fm.replacer)})
  }
  static DeleteKeyAccessGrants(req: DeleteKeyAccessGrantsRequest, initReq?: fm.InitReq): Promise<DeleteKeyAccessGrantsResponse> {
    return fm.fetchReq<DeleteKeyAccessGrantsRequest, DeleteKeyAccessGrantsResponse>(`/v1/grants/${req["id"]}`, {...initReq, method: "DELETE"})
  }
}