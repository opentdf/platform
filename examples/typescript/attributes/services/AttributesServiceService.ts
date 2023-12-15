/* generated using openapi-typescript-codegen -- do no edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { rpcStatus } from '../models/rpcStatus';
import type { v1AttributeDefinition } from '../models/v1AttributeDefinition';
import type { v1AttributeGroup } from '../models/v1AttributeGroup';
import type { v1CreateAttributeGroupResponse } from '../models/v1CreateAttributeGroupResponse';
import type { v1CreateAttributeResponse } from '../models/v1CreateAttributeResponse';
import type { v1DeleteAttributeGroupResponse } from '../models/v1DeleteAttributeGroupResponse';
import type { v1DeleteAttributeResponse } from '../models/v1DeleteAttributeResponse';
import type { v1GetAttributeGroupResponse } from '../models/v1GetAttributeGroupResponse';
import type { v1GetAttributeResponse } from '../models/v1GetAttributeResponse';
import type { v1ListAttributeGroupsResponse } from '../models/v1ListAttributeGroupsResponse';
import type { v1ListAttributesResponse } from '../models/v1ListAttributesResponse';
import type { v1UpdateAttributeGroupResponse } from '../models/v1UpdateAttributeGroupResponse';
import type { v1UpdateAttributeResponse } from '../models/v1UpdateAttributeResponse';

import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';

export class AttributesServiceService {

    /**
     * @param selectorNamespace namespace of referenced resource
     * @param selectorVersion version of reference resource
     * @param selectorName name of referenced resource
     * @param selectorLabelSelectorLabels labels to match a against a resource
     *
     * This is a request variable of the map type. The query format is "map_name[key]=value", e.g. If the map name is Age, the key type is string, and the value type is integer, the query parameter is expressed as Age["bob"]=18
     * @returns v1ListAttributesResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceListAttributes(
        selectorNamespace?: string,
        selectorVersion?: string,
        selectorName?: string,
        selectorLabelSelectorLabels?: string,
    ): CancelablePromise<v1ListAttributesResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/v1/attribute/definitions',
            query: {
                'selector.namespace': selectorNamespace,
                'selector.version': selectorVersion,
                'selector.name': selectorName,
                'selector.labelSelector.labels': selectorLabelSelectorLabels,
            },
        });
    }

    /**
     * @param id
     * @returns v1GetAttributeResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceGetAttribute(
        id: string,
    ): CancelablePromise<v1GetAttributeResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/v1/attribute/definitions/{id}',
            path: {
                'id': id,
            },
        });
    }

    /**
     * @param id
     * @returns v1DeleteAttributeResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceDeleteAttribute(
        id: string,
    ): CancelablePromise<v1DeleteAttributeResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/v1/attribute/definitions/{id}',
            path: {
                'id': id,
            },
        });
    }

    /**
     * @param id
     * @param definition
     * @returns v1UpdateAttributeResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceUpdateAttribute(
        id: string,
        definition: v1AttributeDefinition,
    ): CancelablePromise<v1UpdateAttributeResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/v1/attribute/definitions/{id}',
            path: {
                'id': id,
            },
            body: definition,
        });
    }

    /**
     * @param selectorNamespace namespace of referenced resource
     * @param selectorVersion version of reference resource
     * @param selectorName name of referenced resource
     * @param selectorLabelSelectorLabels labels to match a against a resource
     *
     * This is a request variable of the map type. The query format is "map_name[key]=value", e.g. If the map name is Age, the key type is string, and the value type is integer, the query parameter is expressed as Age["bob"]=18
     * @returns v1ListAttributeGroupsResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceListAttributeGroups(
        selectorNamespace?: string,
        selectorVersion?: string,
        selectorName?: string,
        selectorLabelSelectorLabels?: string,
    ): CancelablePromise<v1ListAttributeGroupsResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/v1/attribute/groups',
            query: {
                'selector.namespace': selectorNamespace,
                'selector.version': selectorVersion,
                'selector.name': selectorName,
                'selector.labelSelector.labels': selectorLabelSelectorLabels,
            },
        });
    }

    /**
     * @param id
     * @returns v1GetAttributeGroupResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceGetAttributeGroup(
        id: string,
    ): CancelablePromise<v1GetAttributeGroupResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/v1/attribute/groups/{id}',
            path: {
                'id': id,
            },
        });
    }

    /**
     * @param id
     * @returns v1DeleteAttributeGroupResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceDeleteAttributeGroup(
        id: string,
    ): CancelablePromise<v1DeleteAttributeGroupResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/v1/attribute/groups/{id}',
            path: {
                'id': id,
            },
        });
    }

    /**
     * @param id
     * @param group
     * @returns v1UpdateAttributeGroupResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceUpdateAttributeGroup(
        id: string,
        group: v1AttributeGroup,
    ): CancelablePromise<v1UpdateAttributeGroupResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/v1/attribute/groups/{id}',
            path: {
                'id': id,
            },
            body: group,
        });
    }

    /**
     * @param definition
     * @returns v1CreateAttributeResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceCreateAttribute(
        definition: v1AttributeDefinition,
    ): CancelablePromise<v1CreateAttributeResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/v1/attributes/definitions',
            body: definition,
        });
    }

    /**
     * @param group
     * @returns v1CreateAttributeGroupResponse A successful response.
     * @returns rpcStatus An unexpected error response.
     * @throws ApiError
     */
    public static attributesServiceCreateAttributeGroup(
        group: v1AttributeGroup,
    ): CancelablePromise<v1CreateAttributeGroupResponse | rpcStatus> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/v1/attributes/groups',
            body: group,
        });
    }

}
