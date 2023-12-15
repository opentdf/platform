/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as fm from "../../fetch.pb"
export type Entity = {
  id?: string
  context?: {[key: string]: string}
}

export type Entitlements = {
  entitlements?: string[]
}

export type GetEntitlementsRequest = {
  entities?: {[key: string]: Entity}
}

export type GetEntitlementsResponse = {
  entitlements?: {[key: string]: Entitlements}
}

export class EntitlementsService {
  static GetEntitlements(req: GetEntitlementsRequest, initReq?: fm.InitReq): Promise<GetEntitlementsResponse> {
    return fm.fetchReq<GetEntitlementsRequest, GetEntitlementsResponse>(`/v1/entitlements`, {...initReq, method: "POST", body: JSON.stringify(req["entities"], fm.replacer)})
  }
}