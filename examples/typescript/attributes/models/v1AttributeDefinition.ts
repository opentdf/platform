/* generated using openapi-typescript-codegen -- do no edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */

import type { AttributeDefinitionAttributeRuleType } from './AttributeDefinitionAttributeRuleType';
import type { v1AttributeDefinitionValue } from './v1AttributeDefinitionValue';
import type { v1ResourceDescriptor } from './v1ResourceDescriptor';

export type v1AttributeDefinition = {
    descriptor?: v1ResourceDescriptor;
    name?: string;
    rule?: AttributeDefinitionAttributeRuleType;
    values?: Array<v1AttributeDefinitionValue>;
    groupBy?: Array<v1AttributeDefinitionValue>;
};

