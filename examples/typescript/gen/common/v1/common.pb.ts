/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

type Absent<T, K extends keyof T> = { [k in Exclude<keyof T, K>]?: undefined };
type OneOf<T> =
  | { [k in keyof T]?: undefined }
  | (
    keyof T extends infer K ?
      (K extends string & keyof T ? { [k in K]: T[K] } & Absent<T, K>
        : never)
    : never);

export enum PolicyResourceType {
  POLICY_RESOURCE_TYPE_UNSPECIFIED = "POLICY_RESOURCE_TYPE_UNSPECIFIED",
  POLICY_RESOURCE_TYPE_RESOURCE_ENCODING = "POLICY_RESOURCE_TYPE_RESOURCE_ENCODING",
  POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM = "POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM",
  POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING = "POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING",
  POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP = "POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP",
  POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING = "POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING",
  POLICY_RESOURCE_TYPE_KEY_ACCESS = "POLICY_RESOURCE_TYPE_KEY_ACCESS",
  POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION = "POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION",
  POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP = "POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP",
}

export type ResourceDescriptor = {
  type?: PolicyResourceType
  id?: number
  version?: number
  name?: string
  namespace?: string
  fqn?: string
  labels?: {[key: string]: string}
  description?: string
  dependencies?: ResourceDependency[]
}

export type ResourceDependency = {
  namespace?: string
  version?: string
  type?: PolicyResourceType
}

export type ResourceSelectorLabelSelector = {
  labels?: {[key: string]: string}
}


type BaseResourceSelector = {
  namespace?: string
  version?: string
}

export type ResourceSelector = BaseResourceSelector
  & OneOf<{ name: string; labelSelector: ResourceSelectorLabelSelector }>