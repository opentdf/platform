/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as AttributesV1Attributes from "../../attributes/v1/attributes.pb"
import * as CommonV1Common from "../../common/v1/common.pb"
import * as fm from "../../fetch.pb"

export enum SubjectMappingOperator {
  OPERATOR_UNSPECIFIED = "OPERATOR_UNSPECIFIED",
  OPERATOR_IN = "OPERATOR_IN",
  OPERATOR_NOT_IN = "OPERATOR_NOT_IN",
}

export type SubjectMappingSet = {
  descriptor?: CommonV1Common.ResourceDescriptor
  subjectMappings?: SubjectMapping[]
}

export type SubjectMapping = {
  descriptor?: CommonV1Common.ResourceDescriptor
  attributeValueRef?: AttributesV1Attributes.AttributeValueReference
  subjectAttribute?: string
  subjectValues?: string[]
  operator?: SubjectMappingOperator
}

export type SubjectEncodingRequestOptions = {
}

export type GetSubjectMappingRequest = {
  id?: string
  options?: SubjectEncodingRequestOptions
}

export type GetSubjectMappingResponse = {
  subjectMapping?: SubjectMapping
}

export type ListSubjectMappingsRequest = {
  selector?: CommonV1Common.ResourceSelector
}

export type ListSubjectMappingsResponse = {
  subjectMappings?: SubjectMapping[]
}

export type CreateSubjectMappingRequest = {
  subjectMapping?: SubjectMapping
}

export type CreateSubjectMappingResponse = {
}

export type UpdateSubjectMappingRequest = {
  id?: string
  subjectMapping?: SubjectMapping
}

export type UpdateSubjectMappingResponse = {
}

export type DeleteSubjectMappingRequest = {
  id?: string
}

export type DeleteSubjectMappingResponse = {
}

export class SubjectEncodingService {
  static ListSubjectMappings(req: ListSubjectMappingsRequest, initReq?: fm.InitReq): Promise<ListSubjectMappingsResponse> {
    return fm.fetchReq<ListSubjectMappingsRequest, ListSubjectMappingsResponse>(`/v1/encoding/subject/mappings?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
  static GetSubjectMapping(req: GetSubjectMappingRequest, initReq?: fm.InitReq): Promise<GetSubjectMappingResponse> {
    return fm.fetchReq<GetSubjectMappingRequest, GetSubjectMappingResponse>(`/v1/encoding/subject/mappings/${req["id"]}?${fm.renderURLSearchParams(req, ["id"])}`, {...initReq, method: "GET"})
  }
  static CreateSubjectMapping(req: CreateSubjectMappingRequest, initReq?: fm.InitReq): Promise<CreateSubjectMappingResponse> {
    return fm.fetchReq<CreateSubjectMappingRequest, CreateSubjectMappingResponse>(`/v1/encoding/subject/mappings`, {...initReq, method: "POST", body: JSON.stringify(req["subject_mapping"], fm.replacer)})
  }
  static UpdateSubjectMapping(req: UpdateSubjectMappingRequest, initReq?: fm.InitReq): Promise<UpdateSubjectMappingResponse> {
    return fm.fetchReq<UpdateSubjectMappingRequest, UpdateSubjectMappingResponse>(`/v1/encoding/subject/mappings/${req["id"]}`, {...initReq, method: "POST", body: JSON.stringify(req["subject_mapping"], fm.replacer)})
  }
  static DeleteSubjectMapping(req: DeleteSubjectMappingRequest, initReq?: fm.InitReq): Promise<DeleteSubjectMappingResponse> {
    return fm.fetchReq<DeleteSubjectMappingRequest, DeleteSubjectMappingResponse>(`/v1/encoding/subjects/mappings/${req["id"]}`, {...initReq, method: "DELETE"})
  }
}