/* generated using openapi-typescript-codegen -- do no edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */

import type { v1PolicyResourceType } from './v1PolicyResourceType';
import type { v1ResourceDependency } from './v1ResourceDependency';

export type v1ResourceDescriptor = {
    type?: v1PolicyResourceType;
    id?: number;
    version?: number;
    name?: string;
    namespace?: string;
    /**
     * optional fully qualified name of the resource.  FQN is used to support direct references and to eliminate the need
     * for clients to compose an FQN at run time.
     *
     * the fqn may be specific to the resource type.
     */
    fqn?: string;
    labels?: Record<string, string>;
    description?: string;
    dependencies?: Array<v1ResourceDependency>;
};

