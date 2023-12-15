/* generated using openapi-typescript-codegen -- do no edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */

import type { v1AttributeValueReference } from './v1AttributeValueReference';
import type { v1ResourceDescriptor } from './v1ResourceDescriptor';

/**
 * Example for Org1 FVEY:
 * id: 1
 * version: 1.0
 * namespace: demo.com
 * groupValue: http://demo.com/attr/relTo/FVEY
 * members: [http://demo.com/attr/relTo/USA,http://demo.com/attr/relTo/GBR,...]
 */
export type v1AttributeGroup = {
    descriptor?: v1ResourceDescriptor;
    groupValue?: v1AttributeValueReference;
    memberValues?: Array<v1AttributeValueReference>;
};

