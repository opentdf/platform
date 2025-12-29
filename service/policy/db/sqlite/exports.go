package sqlite

import (
	"context"
	"database/sql"
)

// toNullString converts an interface{} to sql.NullString for SQLite
func toNullString(v interface{}) sql.NullString {
	if v == nil {
		return sql.NullString{Valid: false}
	}
	switch val := v.(type) {
	case string:
		if val == "" {
			return sql.NullString{Valid: false}
		}
		return sql.NullString{String: val, Valid: true}
	case sql.NullString:
		return val
	default:
		return sql.NullString{Valid: false}
	}
}

// Export types for use by the query router

// ListNamespacesParams exports the listNamespacesParams type
type ListNamespacesParams = listNamespacesParams

// ListNamespacesRow exports the listNamespacesRow type
type ListNamespacesRow = listNamespacesRow

// GetNamespaceParams exports the getNamespaceParams type
type GetNamespaceParams = getNamespaceParams

// GetNamespaceRow exports the getNamespaceRow type
type GetNamespaceRow = getNamespaceRow

// UpdateNamespaceParams exports the updateNamespaceParams type
type UpdateNamespaceParams = updateNamespaceParams

// CreateNamespaceParams exports the createNamespaceParams type
type CreateNamespaceParams = createNamespaceParams

// ListNamespaces exports the listNamespaces method
func (q *Queries) ListNamespaces(ctx context.Context, arg ListNamespacesParams) ([]ListNamespacesRow, error) {
	return q.listNamespaces(ctx, arg)
}

// GetNamespace exports the getNamespace method
func (q *Queries) GetNamespace(ctx context.Context, arg GetNamespaceParams) (GetNamespaceRow, error) {
	return q.getNamespace(ctx, arg)
}

// UpdateNamespace exports the updateNamespace method
func (q *Queries) UpdateNamespace(ctx context.Context, arg UpdateNamespaceParams) (int64, error) {
	return q.updateNamespace(ctx, arg)
}

// CreateNamespace exports the createNamespace method
func (q *Queries) CreateNamespace(ctx context.Context, arg CreateNamespaceParams) (string, error) {
	return q.createNamespace(ctx, arg)
}

// FQN-related exports

// UpsertAttributeNamespaceFqnParams exports the upsertAttributeNamespaceFqnParams type
type UpsertAttributeNamespaceFqnParams = upsertAttributeNamespaceFqnParams

// UpsertAttributeNamespaceFqnRow exports the upsertAttributeNamespaceFqnRow type
type UpsertAttributeNamespaceFqnRow = upsertAttributeNamespaceFqnRow

// UpsertAttributeDefinitionFqnParams exports the upsertAttributeDefinitionFqnParams type
type UpsertAttributeDefinitionFqnParams = upsertAttributeDefinitionFqnParams

// UpsertAttributeDefinitionFqnRow exports the upsertAttributeDefinitionFqnRow type
type UpsertAttributeDefinitionFqnRow = upsertAttributeDefinitionFqnRow

// UpsertAttributeValueFqnParams exports the upsertAttributeValueFqnParams type
type UpsertAttributeValueFqnParams = upsertAttributeValueFqnParams

// UpsertAttributeValueFqnRow exports the upsertAttributeValueFqnRow type
type UpsertAttributeValueFqnRow = upsertAttributeValueFqnRow

// GetDefinitionFqnsByNamespaceRow exports the getDefinitionFqnsByNamespaceRow type
type GetDefinitionFqnsByNamespaceRow = getDefinitionFqnsByNamespaceRow

// GetValueFqnsByNamespaceRow exports the getValueFqnsByNamespaceRow type
type GetValueFqnsByNamespaceRow = getValueFqnsByNamespaceRow

// UpsertAttributeNamespaceFqn exports the upsertAttributeNamespaceFqn method
func (q *Queries) UpsertAttributeNamespaceFqn(ctx context.Context, arg UpsertAttributeNamespaceFqnParams) (UpsertAttributeNamespaceFqnRow, error) {
	return q.upsertAttributeNamespaceFqn(ctx, arg)
}

// UpsertAttributeDefinitionFqn exports the upsertAttributeDefinitionFqn method
func (q *Queries) UpsertAttributeDefinitionFqn(ctx context.Context, arg UpsertAttributeDefinitionFqnParams) (UpsertAttributeDefinitionFqnRow, error) {
	return q.upsertAttributeDefinitionFqn(ctx, arg)
}

// UpsertAttributeValueFqn exports the upsertAttributeValueFqn method
func (q *Queries) UpsertAttributeValueFqn(ctx context.Context, arg UpsertAttributeValueFqnParams) (UpsertAttributeValueFqnRow, error) {
	return q.upsertAttributeValueFqn(ctx, arg)
}

// GetDefinitionFqnsByNamespace exports the getDefinitionFqnsByNamespace method
func (q *Queries) GetDefinitionFqnsByNamespace(ctx context.Context, namespaceID string) ([]GetDefinitionFqnsByNamespaceRow, error) {
	return q.getDefinitionFqnsByNamespace(ctx, namespaceID)
}

// GetValueFqnsByNamespace exports the getValueFqnsByNamespace method
func (q *Queries) GetValueFqnsByNamespace(ctx context.Context, namespaceID string) ([]GetValueFqnsByNamespaceRow, error) {
	return q.getValueFqnsByNamespace(ctx, namespaceID)
}

// GetValueFqnsByDefinition exports the getValueFqnsByDefinition method
func (q *Queries) GetValueFqnsByDefinition(ctx context.Context, attributeID string) ([]GetValueFqnsByDefinitionRow, error) {
	return q.getValueFqnsByDefinition(ctx, attributeID)
}

// GetValueFqnsByDefinitionRow exports the getValueFqnsByDefinitionRow type
type GetValueFqnsByDefinitionRow = getValueFqnsByDefinitionRow

// Attribute-related exports

// CreateAttributeParams exports the createAttributeParams type
type CreateAttributeParams = createAttributeParams

// CreateAttribute exports the createAttribute method
func (q *Queries) CreateAttribute(ctx context.Context, arg CreateAttributeParams) (string, error) {
	return q.createAttribute(ctx, arg)
}

// Attribute value-related exports

// CreateAttributeValueParams exports the createAttributeValueParams type
type CreateAttributeValueParams = createAttributeValueParams

// CreateAttributeValue exports the createAttributeValue method
func (q *Queries) CreateAttributeValue(ctx context.Context, arg CreateAttributeValueParams) (string, error) {
	return q.createAttributeValue(ctx, arg)
}

// GetAttributeValueParams exports the getAttributeValueParams type
type GetAttributeValueParams = getAttributeValueParams

// GetAttributeValueRow exports the getAttributeValueRow type
type GetAttributeValueRow = getAttributeValueRow

// GetAttributeValue exports the getAttributeValue method
func (q *Queries) GetAttributeValue(ctx context.Context, arg GetAttributeValueParams) (GetAttributeValueRow, error) {
	return q.getAttributeValue(ctx, arg)
}

// ListAttributeValuesParams exports the listAttributeValuesParams type
type ListAttributeValuesParams = listAttributeValuesParams

// ListAttributeValuesRow exports the listAttributeValuesRow type
type ListAttributeValuesRow = listAttributeValuesRow

// ListAttributeValues exports the listAttributeValues method
func (q *Queries) ListAttributeValues(ctx context.Context, arg ListAttributeValuesParams) ([]ListAttributeValuesRow, error) {
	return q.listAttributeValues(ctx, arg)
}

// UpdateAttributeValueParams exports the updateAttributeValueParams type
type UpdateAttributeValueParams = updateAttributeValueParams

// UpdateAttributeValue exports the updateAttributeValue method
func (q *Queries) UpdateAttributeValue(ctx context.Context, arg UpdateAttributeValueParams) (int64, error) {
	return q.updateAttributeValue(ctx, arg)
}

// DeleteAttributeValue exports the deleteAttributeValue method
func (q *Queries) DeleteAttributeValue(ctx context.Context, id string) (int64, error) {
	return q.deleteAttributeValue(ctx, id)
}

// AssignPublicKeyToAttributeValueParams exports the assignPublicKeyToAttributeValueParams type
type AssignPublicKeyToAttributeValueParams = assignPublicKeyToAttributeValueParams

// AssignPublicKeyToAttributeValue exports the assignPublicKeyToAttributeValue method
func (q *Queries) AssignPublicKeyToAttributeValue(ctx context.Context, arg AssignPublicKeyToAttributeValueParams) (AttributeValuePublicKeyMap, error) {
	return q.assignPublicKeyToAttributeValue(ctx, arg)
}

// RemovePublicKeyFromAttributeValueParams exports the removePublicKeyFromAttributeValueParams type
type RemovePublicKeyFromAttributeValueParams = removePublicKeyFromAttributeValueParams

// RemovePublicKeyFromAttributeValue exports the removePublicKeyFromAttributeValue method
func (q *Queries) RemovePublicKeyFromAttributeValue(ctx context.Context, arg RemovePublicKeyFromAttributeValueParams) (int64, error) {
	return q.removePublicKeyFromAttributeValue(ctx, arg)
}

// RemoveKeyAccessServerFromAttributeValueParams exports the removeKeyAccessServerFromAttributeValueParams type
type RemoveKeyAccessServerFromAttributeValueParams = removeKeyAccessServerFromAttributeValueParams

// RemoveKeyAccessServerFromAttributeValue exports the removeKeyAccessServerFromAttributeValue method
func (q *Queries) RemoveKeyAccessServerFromAttributeValue(ctx context.Context, arg RemoveKeyAccessServerFromAttributeValueParams) (int64, error) {
	return q.removeKeyAccessServerFromAttributeValue(ctx, arg)
}

// Action-related exports

// GetActionParams exports the getActionParams type
type GetActionParams = getActionParams

// GetActionRow exports the getActionRow type
type GetActionRow = getActionRow

// ListActionsParams exports the listActionsParams type
type ListActionsParams = listActionsParams

// ListActionsRow exports the listActionsRow type
type ListActionsRow = listActionsRow

// CreateCustomActionParams exports the createCustomActionParams type
type CreateCustomActionParams = createCustomActionParams

// UpdateCustomActionParams exports the updateCustomActionParams type
type UpdateCustomActionParams = updateCustomActionParams

// GetAction exports the getAction method
func (q *Queries) GetAction(ctx context.Context, arg GetActionParams) (GetActionRow, error) {
	return q.getAction(ctx, arg)
}

// ListActions exports the listActions method
func (q *Queries) ListActions(ctx context.Context, arg ListActionsParams) ([]ListActionsRow, error) {
	return q.listActions(ctx, arg)
}

// CreateCustomAction exports the createCustomAction method
func (q *Queries) CreateCustomAction(ctx context.Context, arg CreateCustomActionParams) (string, error) {
	return q.createCustomAction(ctx, arg)
}

// UpdateCustomAction exports the updateCustomAction method
func (q *Queries) UpdateCustomAction(ctx context.Context, arg UpdateCustomActionParams) (int64, error) {
	return q.updateCustomAction(ctx, arg)
}

// DeleteCustomAction exports the deleteCustomAction method
func (q *Queries) DeleteCustomAction(ctx context.Context, id string) (int64, error) {
	return q.deleteCustomAction(ctx, id)
}

// Key Management exports

// CreateProviderConfigParams exports the createProviderConfigParams type
type CreateProviderConfigParams = createProviderConfigParams

// CreateProviderConfig exports the createProviderConfig method
func (q *Queries) CreateProviderConfig(ctx context.Context, arg CreateProviderConfigParams) (string, error) {
	return q.createProviderConfig(ctx, arg)
}

// GetProviderConfigFullParams exports the getProviderConfigFullParams type
type GetProviderConfigFullParams = getProviderConfigFullParams

// GetProviderConfigFullRow exports the getProviderConfigFullRow type
type GetProviderConfigFullRow = getProviderConfigFullRow

// GetProviderConfigFull exports the getProviderConfigFull method
func (q *Queries) GetProviderConfigFull(ctx context.Context, arg GetProviderConfigFullParams) (GetProviderConfigFullRow, error) {
	return q.getProviderConfigFull(ctx, arg)
}

// ListProviderConfigsParams exports the listProviderConfigsParams type
type ListProviderConfigsParams = listProviderConfigsParams

// ListProviderConfigsRow exports the listProviderConfigsRow type
type ListProviderConfigsRow = listProviderConfigsRow

// ListProviderConfigs exports the listProviderConfigs method
func (q *Queries) ListProviderConfigs(ctx context.Context, arg ListProviderConfigsParams) ([]ListProviderConfigsRow, error) {
	return q.listProviderConfigs(ctx, arg)
}

// UpdateProviderConfigParams exports the updateProviderConfigParams type
type UpdateProviderConfigParams = updateProviderConfigParams

// UpdateProviderConfig exports the updateProviderConfig method
func (q *Queries) UpdateProviderConfig(ctx context.Context, arg UpdateProviderConfigParams) (int64, error) {
	return q.updateProviderConfig(ctx, arg)
}

// DeleteProviderConfig exports the deleteProviderConfig method
func (q *Queries) DeleteProviderConfig(ctx context.Context, id string) (int64, error) {
	return q.deleteProviderConfig(ctx, id)
}

// Attribute definition query exports

// GetAttributeParams exports the getAttributeParams type
type GetAttributeParams = getAttributeParams

// GetAttributeRow exports the getAttributeRow type
type GetAttributeRow = getAttributeRow

// GetAttribute exports the getAttribute method
func (q *Queries) GetAttribute(ctx context.Context, arg GetAttributeParams) (GetAttributeRow, error) {
	return q.getAttribute(ctx, arg)
}

// ListAttributesDetailParams exports the listAttributesDetailParams type
type ListAttributesDetailParams = listAttributesDetailParams

// ListAttributesDetailRow exports the listAttributesDetailRow type
type ListAttributesDetailRow = listAttributesDetailRow

// ListAttributesDetail exports the listAttributesDetail method
func (q *Queries) ListAttributesDetail(ctx context.Context, arg ListAttributesDetailParams) ([]ListAttributesDetailRow, error) {
	return q.listAttributesDetail(ctx, arg)
}

// ListAttributesSummaryParams exports the listAttributesSummaryParams type
type ListAttributesSummaryParams = listAttributesSummaryParams

// ListAttributesSummaryRow exports the listAttributesSummaryRow type
type ListAttributesSummaryRow = listAttributesSummaryRow

// ListAttributesSummary exports the listAttributesSummary method
func (q *Queries) ListAttributesSummary(ctx context.Context, arg ListAttributesSummaryParams) ([]ListAttributesSummaryRow, error) {
	return q.listAttributesSummary(ctx, arg)
}

// ListAttributesByDefOrValueFqnsRow exports the listAttributesByDefOrValueFqnsRow type
type ListAttributesByDefOrValueFqnsRow = listAttributesByDefOrValueFqnsRow

// listAttributesByDefOrValueFqnsWithParam is the query with proper parameter binding
// This is needed because sqlc doesn't properly detect the @fqns param inside json_each()
const listAttributesByDefOrValueFqnsWithParam = `
WITH target_definition AS (
    SELECT DISTINCT
        ad.id,
        ad.namespace_id,
        ad.name,
        ad.rule,
        ad.active,
        ad.values_order
    FROM attribute_fqns fqns
    INNER JOIN attribute_definitions ad ON fqns.attribute_id = ad.id
    WHERE fqns.fqn IN (SELECT value FROM json_each(?1))
        AND ad.active = 1
    GROUP BY ad.id
),
namespace_grants AS (
    SELECT
        ankag.namespace_id,
        json_group_array(
            json_object(
                'id', kas.id,
                'uri', kas.uri,
                'name', kas.name,
                'public_key', kas.public_key
            )
        ) AS grants
    FROM attribute_namespace_key_access_grants ankag
    JOIN key_access_servers kas ON ankag.key_access_server_id = kas.id
    GROUP BY ankag.namespace_id
),
namespace_keys AS (
    SELECT
        k.namespace_id,
        json_group_array(
            json_object(
                'kas_uri', kas.uri,
                'kas_id', kas.id,
                'public_key', json_object(
                    'algorithm', kask.key_algorithm,
                    'kid', kask.key_id,
                    'pem', json_extract(kask.public_key_ctx, '$.pem')
                )
            )
        ) AS keys
    FROM attribute_namespace_public_key_map k
    INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
    INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
    GROUP BY k.namespace_id
),
namespaces AS (
    SELECT
        n.id,
        json_object(
            'id', n.id,
            'name', n.name,
            'active', n.active,
            'fqn', fqns.fqn,
            'grants', json(COALESCE(ng.grants, '[]')),
            'kas_keys', json(COALESCE(nk.keys, '[]'))
        ) AS namespace
    FROM target_definition td
    INNER JOIN attribute_namespaces n ON td.namespace_id = n.id
    INNER JOIN attribute_fqns fqns ON n.id = fqns.namespace_id
    LEFT JOIN namespace_grants ng ON n.id = ng.namespace_id
    LEFT JOIN namespace_keys nk ON n.id = nk.namespace_id
    WHERE n.active = 1
        AND (fqns.attribute_id IS NULL AND fqns.value_id IS NULL)
    GROUP BY n.id, fqns.fqn
),
value_grants AS (
    SELECT
        av.id,
        json_group_array(
            json_object(
                'id', kas.id,
                'uri', kas.uri,
                'name', kas.name,
                'public_key', kas.public_key
            )
        ) AS grants
    FROM target_definition td
    LEFT JOIN attribute_values av ON td.id = av.attribute_definition_id
    LEFT JOIN attribute_value_key_access_grants avkag ON av.id = avkag.attribute_value_id
    LEFT JOIN key_access_servers kas ON avkag.key_access_server_id = kas.id
    WHERE kas.id IS NOT NULL
    GROUP BY av.id
),
value_subject_mappings AS (
    SELECT
        av.id,
        json_group_array(
            json_object(
                'id', sm.id,
                'actions', (
                    SELECT COALESCE(
                        json_group_array(
                            json_object(
                                'id', a.id,
                                'name', a.name
                            )
                        ),
                        '[]'
                    )
                    FROM subject_mapping_actions sma
                    LEFT JOIN actions a ON sma.action_id = a.id
                    WHERE sma.subject_mapping_id = sm.id AND a.id IS NOT NULL
                ),
                'subject_condition_set', json_object(
                    'id', scs.id,
                    'subject_sets', json(scs.condition)
                )
            )
        ) AS sub_maps
    FROM target_definition td
    LEFT JOIN attribute_values av ON td.id = av.attribute_definition_id
    LEFT JOIN subject_mappings sm ON av.id = sm.attribute_value_id
    LEFT JOIN subject_condition_set scs ON sm.subject_condition_set_id = scs.id
    WHERE sm.id IS NOT NULL
    GROUP BY av.id
),
value_resource_mappings AS (
    SELECT
        av.id,
        json_group_array(
            json_object(
                'id', rm.id,
                'terms', json(rm.terms),
                'group', CASE
                    WHEN rm.group_id IS NULL THEN NULL
                    ELSE json_object(
                        'id', rmg.id,
                        'name', rmg.name,
                        'namespace_id', rmg.namespace_id
                    )
                END
            )
        ) AS res_maps
    FROM target_definition td
    LEFT JOIN attribute_values av ON td.id = av.attribute_definition_id
    LEFT JOIN resource_mappings rm ON av.id = rm.attribute_value_id
    LEFT JOIN resource_mapping_groups rmg ON rm.group_id = rmg.id
    WHERE rm.id IS NOT NULL
    GROUP BY av.id
),
value_keys AS (
    SELECT
        k.value_id,
        json_group_array(
            json_object(
                'kas_uri', kas.uri,
                'kas_id', kas.id,
                'public_key', json_object(
                    'algorithm', kask.key_algorithm,
                    'kid', kask.key_id,
                    'pem', json_extract(kask.public_key_ctx, '$.pem')
                )
            )
        ) AS keys
    FROM attribute_value_public_key_map k
    INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
    INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
    GROUP BY k.value_id
)
SELECT
    td.id,
    td.name,
    td.rule,
    td.active,
    n.namespace,
    fqns.fqn,
    (
        SELECT json_group_array(
            json_object(
                'id', av.id,
                'value', av.value,
                'active', av.active,
                'fqn', vfqns.fqn,
                'grants', json(COALESCE(vg.grants, '[]')),
                'subject_mappings', json(COALESCE(vsm.sub_maps, '[]')),
                'resource_mappings', json(COALESCE(vrm.res_maps, '[]')),
                'kas_keys', json(COALESCE(vk.keys, '[]'))
            )
        )
        FROM attribute_values av
        LEFT JOIN attribute_fqns vfqns ON av.id = vfqns.value_id
        LEFT JOIN value_grants vg ON av.id = vg.id
        LEFT JOIN value_subject_mappings vsm ON av.id = vsm.id
        LEFT JOIN value_resource_mappings vrm ON av.id = vrm.id
        LEFT JOIN value_keys vk ON av.id = vk.value_id
        WHERE av.attribute_definition_id = td.id AND av.active = 1
    ) AS "values",
    (
        SELECT json_group_array(
            json_object(
                'id', kas.id,
                'uri', kas.uri,
                'name', kas.name,
                'public_key', kas.public_key
            )
        )
        FROM attribute_definition_key_access_grants adkag
        JOIN key_access_servers kas ON adkag.key_access_server_id = kas.id
        WHERE adkag.attribute_definition_id = td.id
    ) AS grants,
    (
        SELECT json_group_array(
            json_object(
                'kas_uri', kas.uri,
                'kas_id', kas.id,
                'public_key', json_object(
                    'algorithm', kask.key_algorithm,
                    'kid', kask.key_id,
                    'pem', json_extract(kask.public_key_ctx, '$.pem')
                )
            )
        )
        FROM attribute_definition_public_key_map k
        INNER JOIN key_access_server_keys kask ON k.key_access_server_key_id = kask.id
        INNER JOIN key_access_servers kas ON kask.key_access_server_id = kas.id
        WHERE k.definition_id = td.id
    ) AS keys
FROM target_definition td
INNER JOIN attribute_fqns fqns ON td.id = fqns.attribute_id
INNER JOIN namespaces n ON td.namespace_id = n.id
WHERE fqns.value_id IS NULL
`

// ListAttributesByDefOrValueFqns exports the listAttributesByDefOrValueFqns method with proper parameter binding
func (q *Queries) ListAttributesByDefOrValueFqns(ctx context.Context, fqnsJSON string) ([]ListAttributesByDefOrValueFqnsRow, error) {
	rows, err := q.db.QueryContext(ctx, listAttributesByDefOrValueFqnsWithParam, fqnsJSON)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ListAttributesByDefOrValueFqnsRow
	for rows.Next() {
		var i ListAttributesByDefOrValueFqnsRow
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Rule,
			&i.Active,
			&i.Namespace,
			&i.Fqn,
			&i.Values,
			&i.Grants,
			&i.Keys,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// UpdateAttributeParams exports the updateAttributeParams type
type UpdateAttributeParams = updateAttributeParams

// UpdateAttribute exports the updateAttribute method
func (q *Queries) UpdateAttribute(ctx context.Context, arg UpdateAttributeParams) (int64, error) {
	return q.updateAttribute(ctx, arg)
}

// DeleteAttribute exports the deleteAttribute method
func (q *Queries) DeleteAttribute(ctx context.Context, id string) (int64, error) {
	return q.deleteAttribute(ctx, id)
}

// RemoveKeyAccessServerFromAttributeParams exports the removeKeyAccessServerFromAttributeParams type
type RemoveKeyAccessServerFromAttributeParams = removeKeyAccessServerFromAttributeParams

// RemoveKeyAccessServerFromAttribute exports the removeKeyAccessServerFromAttribute method
func (q *Queries) RemoveKeyAccessServerFromAttribute(ctx context.Context, arg RemoveKeyAccessServerFromAttributeParams) (int64, error) {
	return q.removeKeyAccessServerFromAttribute(ctx, arg)
}

// AssignPublicKeyToAttributeDefinitionParams exports the assignPublicKeyToAttributeDefinitionParams type
type AssignPublicKeyToAttributeDefinitionParams = assignPublicKeyToAttributeDefinitionParams

// AssignPublicKeyToAttributeDefinition exports the assignPublicKeyToAttributeDefinition method
func (q *Queries) AssignPublicKeyToAttributeDefinition(ctx context.Context, arg AssignPublicKeyToAttributeDefinitionParams) (AttributeDefinitionPublicKeyMap, error) {
	return q.assignPublicKeyToAttributeDefinition(ctx, arg)
}

// RemovePublicKeyFromAttributeDefinitionParams exports the removePublicKeyFromAttributeDefinitionParams type
type RemovePublicKeyFromAttributeDefinitionParams = removePublicKeyFromAttributeDefinitionParams

// RemovePublicKeyFromAttributeDefinition exports the removePublicKeyFromAttributeDefinition method
func (q *Queries) RemovePublicKeyFromAttributeDefinition(ctx context.Context, arg RemovePublicKeyFromAttributeDefinitionParams) (int64, error) {
	return q.removePublicKeyFromAttributeDefinition(ctx, arg)
}

// Namespace deletion export

// DeleteNamespace exports the deleteNamespace method
func (q *Queries) DeleteNamespace(ctx context.Context, id string) (int64, error) {
	return q.deleteNamespace(ctx, id)
}

// Key access server namespace grants exports

// RemoveKeyAccessServerFromNamespaceParams exports the removeKeyAccessServerFromNamespaceParams type
type RemoveKeyAccessServerFromNamespaceParams = removeKeyAccessServerFromNamespaceParams

// RemoveKeyAccessServerFromNamespace exports the removeKeyAccessServerFromNamespace method
func (q *Queries) RemoveKeyAccessServerFromNamespace(ctx context.Context, arg RemoveKeyAccessServerFromNamespaceParams) (int64, error) {
	return q.removeKeyAccessServerFromNamespace(ctx, arg)
}

// Public key namespace mapping exports

// AssignPublicKeyToNamespaceParams exports the assignPublicKeyToNamespaceParams type
type AssignPublicKeyToNamespaceParams = assignPublicKeyToNamespaceParams

// AssignPublicKeyToNamespaceRow exports the AttributeNamespacePublicKeyMap type for return value
type AssignPublicKeyToNamespaceRow = AttributeNamespacePublicKeyMap

// AssignPublicKeyToNamespace exports the assignPublicKeyToNamespace method
func (q *Queries) AssignPublicKeyToNamespace(ctx context.Context, arg AssignPublicKeyToNamespaceParams) (AssignPublicKeyToNamespaceRow, error) {
	return q.assignPublicKeyToNamespace(ctx, arg)
}

// RemovePublicKeyFromNamespaceParams exports the removePublicKeyFromNamespaceParams type
type RemovePublicKeyFromNamespaceParams = removePublicKeyFromNamespaceParams

// RemovePublicKeyFromNamespace exports the removePublicKeyFromNamespace method
func (q *Queries) RemovePublicKeyFromNamespace(ctx context.Context, arg RemovePublicKeyFromNamespaceParams) (int64, error) {
	return q.removePublicKeyFromNamespace(ctx, arg)
}

// Certificate-related exports

// CreateCertificateParams exports the createCertificateParams type
type CreateCertificateParams = createCertificateParams

// CreateCertificate exports the createCertificate method
func (q *Queries) CreateCertificate(ctx context.Context, arg CreateCertificateParams) (string, error) {
	return q.createCertificate(ctx, arg)
}

// GetCertificateRow exports the getCertificateRow type
type GetCertificateRow = getCertificateRow

// GetCertificate exports the getCertificate method
func (q *Queries) GetCertificate(ctx context.Context, id string) (GetCertificateRow, error) {
	return q.getCertificate(ctx, id)
}

// GetCertificateByPEMRow exports the getCertificateByPEMRow type
type GetCertificateByPEMRow = getCertificateByPEMRow

// GetCertificateByPEM exports the getCertificateByPEM method
func (q *Queries) GetCertificateByPEM(ctx context.Context, pem string) (GetCertificateByPEMRow, error) {
	return q.getCertificateByPEM(ctx, pem)
}

// DeleteCertificate exports the deleteCertificate method
func (q *Queries) DeleteCertificate(ctx context.Context, id string) (int64, error) {
	return q.deleteCertificate(ctx, id)
}

// Certificate-namespace assignment exports

// AssignCertificateToNamespaceParams exports the assignCertificateToNamespaceParams type
type AssignCertificateToNamespaceParams = assignCertificateToNamespaceParams

// AssignCertificateToNamespaceRow exports the AttributeNamespaceCertificate type for return value
type AssignCertificateToNamespaceRow = AttributeNamespaceCertificate

// AssignCertificateToNamespace exports the assignCertificateToNamespace method
func (q *Queries) AssignCertificateToNamespace(ctx context.Context, arg AssignCertificateToNamespaceParams) (AssignCertificateToNamespaceRow, error) {
	return q.assignCertificateToNamespace(ctx, arg)
}

// RemoveCertificateFromNamespaceParams exports the removeCertificateFromNamespaceParams type
type RemoveCertificateFromNamespaceParams = removeCertificateFromNamespaceParams

// RemoveCertificateFromNamespace exports the removeCertificateFromNamespace method
func (q *Queries) RemoveCertificateFromNamespace(ctx context.Context, arg RemoveCertificateFromNamespaceParams) (int64, error) {
	return q.removeCertificateFromNamespace(ctx, arg)
}

// CountCertificateNamespaceAssignments exports the countCertificateNamespaceAssignments method
func (q *Queries) CountCertificateNamespaceAssignments(ctx context.Context, certificateID string) (int64, error) {
	return q.countCertificateNamespaceAssignments(ctx, certificateID)
}

// Subject Condition Set exports

// CreateSubjectConditionSetParams exports the createSubjectConditionSetParams type
type CreateSubjectConditionSetParams = createSubjectConditionSetParams

// GetSubjectConditionSetRow exports the getSubjectConditionSetRow type
type GetSubjectConditionSetRow = getSubjectConditionSetRow

// ListSubjectConditionSetsParams exports the listSubjectConditionSetsParams type
type ListSubjectConditionSetsParams = listSubjectConditionSetsParams

// ListSubjectConditionSetsRow exports the listSubjectConditionSetsRow type
type ListSubjectConditionSetsRow = listSubjectConditionSetsRow

// UpdateSubjectConditionSetParams exports the updateSubjectConditionSetParams type
type UpdateSubjectConditionSetParams = updateSubjectConditionSetParams

// CreateSubjectConditionSet exports the createSubjectConditionSet method
func (q *Queries) CreateSubjectConditionSet(ctx context.Context, arg CreateSubjectConditionSetParams) (string, error) {
	return q.createSubjectConditionSet(ctx, arg)
}

// GetSubjectConditionSet exports the getSubjectConditionSet method
func (q *Queries) GetSubjectConditionSet(ctx context.Context, id string) (GetSubjectConditionSetRow, error) {
	return q.getSubjectConditionSet(ctx, id)
}

// ListSubjectConditionSets exports the listSubjectConditionSets method
func (q *Queries) ListSubjectConditionSets(ctx context.Context, arg ListSubjectConditionSetsParams) ([]ListSubjectConditionSetsRow, error) {
	return q.listSubjectConditionSets(ctx, arg)
}

// UpdateSubjectConditionSet exports the updateSubjectConditionSet method
func (q *Queries) UpdateSubjectConditionSet(ctx context.Context, arg UpdateSubjectConditionSetParams) (int64, error) {
	return q.updateSubjectConditionSet(ctx, arg)
}

// DeleteSubjectConditionSet exports the deleteSubjectConditionSet method
func (q *Queries) DeleteSubjectConditionSet(ctx context.Context, id string) (int64, error) {
	return q.deleteSubjectConditionSet(ctx, id)
}

// DeleteAllUnmappedSubjectConditionSets exports the deleteAllUnmappedSubjectConditionSets method
func (q *Queries) DeleteAllUnmappedSubjectConditionSets(ctx context.Context) ([]string, error) {
	return q.deleteAllUnmappedSubjectConditionSets(ctx)
}

// Subject Mapping exports

// CreateSubjectMappingParams exports the createSubjectMappingParams type
type CreateSubjectMappingParams = createSubjectMappingParams

// GetSubjectMappingRow exports the getSubjectMappingRow type
type GetSubjectMappingRow = getSubjectMappingRow

// ListSubjectMappingsParams exports the listSubjectMappingsParams type
type ListSubjectMappingsParams = listSubjectMappingsParams

// ListSubjectMappingsRow exports the listSubjectMappingsRow type
type ListSubjectMappingsRow = listSubjectMappingsRow

// MatchSubjectMappingsRow exports the matchSubjectMappingsRow type
type MatchSubjectMappingsRow = matchSubjectMappingsRow

// UpdateSubjectMappingParams exports the updateSubjectMappingParams type
type UpdateSubjectMappingParams = updateSubjectMappingParams

// AddActionToSubjectMappingParams exports the addActionToSubjectMappingParams type
type AddActionToSubjectMappingParams = addActionToSubjectMappingParams

// CreateSubjectMapping exports the createSubjectMapping method
func (q *Queries) CreateSubjectMapping(ctx context.Context, arg CreateSubjectMappingParams) (string, error) {
	return q.createSubjectMapping(ctx, arg)
}

// GetSubjectMapping exports the getSubjectMapping method
func (q *Queries) GetSubjectMapping(ctx context.Context, id string) (GetSubjectMappingRow, error) {
	return q.getSubjectMapping(ctx, id)
}

// ListSubjectMappings exports the listSubjectMappings method
func (q *Queries) ListSubjectMappings(ctx context.Context, arg ListSubjectMappingsParams) ([]ListSubjectMappingsRow, error) {
	return q.listSubjectMappings(ctx, arg)
}

// UpdateSubjectMapping exports the updateSubjectMapping method
func (q *Queries) UpdateSubjectMapping(ctx context.Context, arg UpdateSubjectMappingParams) (int64, error) {
	return q.updateSubjectMapping(ctx, arg)
}

// DeleteSubjectMapping exports the deleteSubjectMapping method
func (q *Queries) DeleteSubjectMapping(ctx context.Context, id string) (int64, error) {
	return q.deleteSubjectMapping(ctx, id)
}

// AddActionToSubjectMapping exports the addActionToSubjectMapping method
func (q *Queries) AddActionToSubjectMapping(ctx context.Context, arg AddActionToSubjectMappingParams) error {
	return q.addActionToSubjectMapping(ctx, arg)
}

// RemoveAllActionsFromSubjectMapping exports the removeAllActionsFromSubjectMapping method
func (q *Queries) RemoveAllActionsFromSubjectMapping(ctx context.Context, subjectMappingID string) (int64, error) {
	return q.removeAllActionsFromSubjectMapping(ctx, subjectMappingID)
}

// GetActionsByNamesRow exports the getActionsByNamesRow type
type GetActionsByNamesRow = getActionsByNamesRow

// Registered Resources exports

// CreateRegisteredResourceParams exports the createRegisteredResourceParams type
type CreateRegisteredResourceParams = createRegisteredResourceParams

// GetRegisteredResourceParams exports the getRegisteredResourceParams type
type GetRegisteredResourceParams = getRegisteredResourceParams

// GetRegisteredResourceRow exports the getRegisteredResourceRow type
type GetRegisteredResourceRow = getRegisteredResourceRow

// ListRegisteredResourcesParams exports the listRegisteredResourcesParams type
type ListRegisteredResourcesParams = listRegisteredResourcesParams

// ListRegisteredResourcesRow exports the listRegisteredResourcesRow type
type ListRegisteredResourcesRow = listRegisteredResourcesRow

// UpdateRegisteredResourceParams exports the updateRegisteredResourceParams type
type UpdateRegisteredResourceParams = updateRegisteredResourceParams

// CreateRegisteredResource exports the createRegisteredResource method
func (q *Queries) CreateRegisteredResource(ctx context.Context, arg CreateRegisteredResourceParams) (string, error) {
	return q.createRegisteredResource(ctx, arg)
}

// GetRegisteredResource exports the getRegisteredResource method
func (q *Queries) GetRegisteredResource(ctx context.Context, arg GetRegisteredResourceParams) (GetRegisteredResourceRow, error) {
	return q.getRegisteredResource(ctx, arg)
}

// ListRegisteredResources exports the listRegisteredResources method
func (q *Queries) ListRegisteredResources(ctx context.Context, arg ListRegisteredResourcesParams) ([]ListRegisteredResourcesRow, error) {
	return q.listRegisteredResources(ctx, arg)
}

// UpdateRegisteredResource exports the updateRegisteredResource method
func (q *Queries) UpdateRegisteredResource(ctx context.Context, arg UpdateRegisteredResourceParams) (int64, error) {
	return q.updateRegisteredResource(ctx, arg)
}

// DeleteRegisteredResource exports the deleteRegisteredResource method
func (q *Queries) DeleteRegisteredResource(ctx context.Context, id string) (int64, error) {
	return q.deleteRegisteredResource(ctx, id)
}

// Registered Resource Values exports

// CreateRegisteredResourceValueParams exports the createRegisteredResourceValueParams type
type CreateRegisteredResourceValueParams = createRegisteredResourceValueParams

// GetRegisteredResourceValueParams exports the getRegisteredResourceValueParams type
type GetRegisteredResourceValueParams = getRegisteredResourceValueParams

// GetRegisteredResourceValueRow exports the getRegisteredResourceValueRow type
type GetRegisteredResourceValueRow = getRegisteredResourceValueRow

// ListRegisteredResourceValuesParams exports the listRegisteredResourceValuesParams type
type ListRegisteredResourceValuesParams = listRegisteredResourceValuesParams

// ListRegisteredResourceValuesRow exports the listRegisteredResourceValuesRow type
type ListRegisteredResourceValuesRow = listRegisteredResourceValuesRow

// UpdateRegisteredResourceValueParams exports the updateRegisteredResourceValueParams type
type UpdateRegisteredResourceValueParams = updateRegisteredResourceValueParams

// CreateRegisteredResourceValue exports the createRegisteredResourceValue method
func (q *Queries) CreateRegisteredResourceValue(ctx context.Context, arg CreateRegisteredResourceValueParams) (string, error) {
	return q.createRegisteredResourceValue(ctx, arg)
}

// GetRegisteredResourceValue exports the getRegisteredResourceValue method
func (q *Queries) GetRegisteredResourceValue(ctx context.Context, arg GetRegisteredResourceValueParams) (GetRegisteredResourceValueRow, error) {
	return q.getRegisteredResourceValue(ctx, arg)
}

// ListRegisteredResourceValues exports the listRegisteredResourceValues method
func (q *Queries) ListRegisteredResourceValues(ctx context.Context, arg ListRegisteredResourceValuesParams) ([]ListRegisteredResourceValuesRow, error) {
	return q.listRegisteredResourceValues(ctx, arg)
}

// UpdateRegisteredResourceValue exports the updateRegisteredResourceValue method
func (q *Queries) UpdateRegisteredResourceValue(ctx context.Context, arg UpdateRegisteredResourceValueParams) (int64, error) {
	return q.updateRegisteredResourceValue(ctx, arg)
}

// DeleteRegisteredResourceValue exports the deleteRegisteredResourceValue method
func (q *Queries) DeleteRegisteredResourceValue(ctx context.Context, id string) (int64, error) {
	return q.deleteRegisteredResourceValue(ctx, id)
}

// Registered Resource Action Attribute Values exports

// CreateRegisteredResourceActionAttributeValueParams exports the createRegisteredResourceActionAttributeValueParams type
type CreateRegisteredResourceActionAttributeValueParams = createRegisteredResourceActionAttributeValueParams

// CreateRegisteredResourceActionAttributeValue exports the createRegisteredResourceActionAttributeValue method
func (q *Queries) CreateRegisteredResourceActionAttributeValue(ctx context.Context, arg CreateRegisteredResourceActionAttributeValueParams) (string, error) {
	return q.createRegisteredResourceActionAttributeValue(ctx, arg)
}

// DeleteRegisteredResourceActionAttributeValues exports the deleteRegisteredResourceActionAttributeValues method
func (q *Queries) DeleteRegisteredResourceActionAttributeValues(ctx context.Context, registeredResourceValueID string) (int64, error) {
	return q.deleteRegisteredResourceActionAttributeValues(ctx, registeredResourceValueID)
}

// Resource Mapping Group exports

// CreateResourceMappingGroupParams exports the createResourceMappingGroupParams type
type CreateResourceMappingGroupParams = createResourceMappingGroupParams

// GetResourceMappingGroupRow exports the getResourceMappingGroupRow type
type GetResourceMappingGroupRow = getResourceMappingGroupRow

// ListResourceMappingGroupsParams exports the listResourceMappingGroupsParams type
type ListResourceMappingGroupsParams = listResourceMappingGroupsParams

// ListResourceMappingGroupsRow exports the listResourceMappingGroupsRow type
type ListResourceMappingGroupsRow = listResourceMappingGroupsRow

// UpdateResourceMappingGroupParams exports the updateResourceMappingGroupParams type
type UpdateResourceMappingGroupParams = updateResourceMappingGroupParams

// CreateResourceMappingGroup exports the createResourceMappingGroup method
func (q *Queries) CreateResourceMappingGroup(ctx context.Context, arg CreateResourceMappingGroupParams) (string, error) {
	return q.createResourceMappingGroup(ctx, arg)
}

// GetResourceMappingGroup exports the getResourceMappingGroup method
func (q *Queries) GetResourceMappingGroup(ctx context.Context, id string) (GetResourceMappingGroupRow, error) {
	return q.getResourceMappingGroup(ctx, id)
}

// ListResourceMappingGroups exports the listResourceMappingGroups method
func (q *Queries) ListResourceMappingGroups(ctx context.Context, arg ListResourceMappingGroupsParams) ([]ListResourceMappingGroupsRow, error) {
	return q.listResourceMappingGroups(ctx, arg)
}

// UpdateResourceMappingGroup exports the updateResourceMappingGroup method
func (q *Queries) UpdateResourceMappingGroup(ctx context.Context, arg UpdateResourceMappingGroupParams) (int64, error) {
	return q.updateResourceMappingGroup(ctx, arg)
}

// DeleteResourceMappingGroup exports the deleteResourceMappingGroup method
func (q *Queries) DeleteResourceMappingGroup(ctx context.Context, id string) (int64, error) {
	return q.deleteResourceMappingGroup(ctx, id)
}

// Resource Mapping exports

// CreateResourceMappingParams exports the createResourceMappingParams type
type CreateResourceMappingParams = createResourceMappingParams

// GetResourceMappingRow exports the getResourceMappingRow type
type GetResourceMappingRow = getResourceMappingRow

// ListResourceMappingsParams exports the listResourceMappingsParams type
type ListResourceMappingsParams = listResourceMappingsParams

// ListResourceMappingsRow exports the listResourceMappingsRow type
type ListResourceMappingsRow = listResourceMappingsRow

// ListResourceMappingsByFullyQualifiedGroupParams exports the listResourceMappingsByFullyQualifiedGroupParams type
type ListResourceMappingsByFullyQualifiedGroupParams = listResourceMappingsByFullyQualifiedGroupParams

// ListResourceMappingsByFullyQualifiedGroupRow exports the listResourceMappingsByFullyQualifiedGroupRow type
type ListResourceMappingsByFullyQualifiedGroupRow = listResourceMappingsByFullyQualifiedGroupRow

// UpdateResourceMappingParams exports the updateResourceMappingParams type
type UpdateResourceMappingParams = updateResourceMappingParams

// CreateResourceMapping exports the createResourceMapping method
func (q *Queries) CreateResourceMapping(ctx context.Context, arg CreateResourceMappingParams) (string, error) {
	return q.createResourceMapping(ctx, arg)
}

// GetResourceMapping exports the getResourceMapping method
func (q *Queries) GetResourceMapping(ctx context.Context, id string) (GetResourceMappingRow, error) {
	return q.getResourceMapping(ctx, id)
}

// ListResourceMappings exports the listResourceMappings method
func (q *Queries) ListResourceMappings(ctx context.Context, arg ListResourceMappingsParams) ([]ListResourceMappingsRow, error) {
	return q.listResourceMappings(ctx, arg)
}

// ListResourceMappingsByFullyQualifiedGroup exports the listResourceMappingsByFullyQualifiedGroup method
func (q *Queries) ListResourceMappingsByFullyQualifiedGroup(ctx context.Context, arg ListResourceMappingsByFullyQualifiedGroupParams) ([]ListResourceMappingsByFullyQualifiedGroupRow, error) {
	return q.listResourceMappingsByFullyQualifiedGroup(ctx, arg)
}

// UpdateResourceMapping exports the updateResourceMapping method
func (q *Queries) UpdateResourceMapping(ctx context.Context, arg UpdateResourceMappingParams) (int64, error) {
	return q.updateResourceMapping(ctx, arg)
}

// DeleteResourceMapping exports the deleteResourceMapping method
func (q *Queries) DeleteResourceMapping(ctx context.Context, id string) (int64, error) {
	return q.deleteResourceMapping(ctx, id)
}

// Obligation-related exports

// CreateObligationParams exports the createObligationParams type
type CreateObligationParams = createObligationParams

// GetObligationParams exports the getObligationParams type
type GetObligationParams = getObligationParams

// GetObligationRow exports the getObligationRow type
type GetObligationRow = getObligationRow

// ListObligationsParams exports the listObligationsParams type
type ListObligationsParams = listObligationsParams

// ListObligationsRow exports the listObligationsRow type
type ListObligationsRow = listObligationsRow

// UpdateObligationParams exports the updateObligationParams type
type UpdateObligationParams = updateObligationParams

// GetObligationsByFQNsRow exports the getObligationsByFQNsRow type
type GetObligationsByFQNsRow = getObligationsByFQNsRow

// CreateObligation exports the createObligation method
func (q *Queries) CreateObligation(ctx context.Context, arg CreateObligationParams) (string, error) {
	return q.createObligation(ctx, arg)
}

// GetObligation exports the getObligation method
func (q *Queries) GetObligation(ctx context.Context, arg GetObligationParams) (GetObligationRow, error) {
	return q.getObligation(ctx, arg)
}

// ListObligations exports the listObligations method
func (q *Queries) ListObligations(ctx context.Context, arg ListObligationsParams) ([]ListObligationsRow, error) {
	return q.listObligations(ctx, arg)
}

// UpdateObligation exports the updateObligation method
func (q *Queries) UpdateObligation(ctx context.Context, arg UpdateObligationParams) (int64, error) {
	return q.updateObligation(ctx, arg)
}

// DeleteObligation exports the deleteObligation method
func (q *Queries) DeleteObligation(ctx context.Context, id string) (int64, error) {
	return q.deleteObligation(ctx, id)
}

// GetObligationsByFQNs exports the getObligationsByFQNs method
func (q *Queries) GetObligationsByFQNs(ctx context.Context, namespaceFqns, names string) ([]GetObligationsByFQNsRow, error) {
	return q.getObligationsByFQNs(ctx)
}

// Obligation Value-related exports

// CreateObligationValueParams exports the createObligationValueParams type
type CreateObligationValueParams = createObligationValueParams

// GetObligationValueParams exports the getObligationValueParams type
type GetObligationValueParams = getObligationValueParams

// GetObligationValueRow exports the getObligationValueRow type
type GetObligationValueRow = getObligationValueRow

// UpdateObligationValueParams exports the updateObligationValueParams type
type UpdateObligationValueParams = updateObligationValueParams

// GetObligationValuesByFQNsRow exports the getObligationValuesByFQNsRow type
type GetObligationValuesByFQNsRow = getObligationValuesByFQNsRow

// CreateObligationValue exports the createObligationValue method
func (q *Queries) CreateObligationValue(ctx context.Context, arg CreateObligationValueParams) (string, error) {
	return q.createObligationValue(ctx, arg)
}

// GetObligationValue exports the getObligationValue method
func (q *Queries) GetObligationValue(ctx context.Context, arg GetObligationValueParams) (GetObligationValueRow, error) {
	return q.getObligationValue(ctx, arg)
}

// UpdateObligationValue exports the updateObligationValue method
func (q *Queries) UpdateObligationValue(ctx context.Context, arg UpdateObligationValueParams) (int64, error) {
	return q.updateObligationValue(ctx, arg)
}

// DeleteObligationValue exports the deleteObligationValue method
func (q *Queries) DeleteObligationValue(ctx context.Context, id string) (int64, error) {
	return q.deleteObligationValue(ctx, id)
}

// GetObligationValuesByFQNs exports the getObligationValuesByFQNs method
func (q *Queries) GetObligationValuesByFQNs(ctx context.Context, namespaceFqns, names, values string) ([]GetObligationValuesByFQNsRow, error) {
	return q.getObligationValuesByFQNs(ctx)
}

// Obligation Trigger-related exports

// CreateObligationTriggerParams exports the createObligationTriggerParams type
type CreateObligationTriggerParams = createObligationTriggerParams

// ListObligationTriggersParams exports the listObligationTriggersParams type
type ListObligationTriggersParams = listObligationTriggersParams

// ListObligationTriggersRow exports the listObligationTriggersRow type
type ListObligationTriggersRow = listObligationTriggersRow

// CreateObligationTrigger exports the createObligationTrigger method
func (q *Queries) CreateObligationTrigger(ctx context.Context, arg CreateObligationTriggerParams) (string, error) {
	return q.createObligationTrigger(ctx, arg)
}

// ListObligationTriggers exports the listObligationTriggers method
func (q *Queries) ListObligationTriggers(ctx context.Context, arg ListObligationTriggersParams) ([]ListObligationTriggersRow, error) {
	return q.listObligationTriggers(ctx, arg)
}

// DeleteObligationTrigger exports the deleteObligationTrigger method
func (q *Queries) DeleteObligationTrigger(ctx context.Context, id string) (int64, error) {
	return q.deleteObligationTrigger(ctx, id)
}

// DeleteAllObligationTriggersForValue exports the deleteAllObligationTriggersForValue method
func (q *Queries) DeleteAllObligationTriggersForValue(ctx context.Context, obligationValueID string) (int64, error) {
	return q.deleteAllObligationTriggersForValue(ctx, obligationValueID)
}

// RotatePublicKeyForAttributeValueParams exports the rotatePublicKeyForAttributeValueParams type
type RotatePublicKeyForAttributeValueParams = rotatePublicKeyForAttributeValueParams

// RotatePublicKeyForAttributeValue exports the rotatePublicKeyForAttributeValue method
func (q *Queries) RotatePublicKeyForAttributeValue(ctx context.Context, arg RotatePublicKeyForAttributeValueParams) ([]string, error) {
	return q.rotatePublicKeyForAttributeValue(ctx, arg)
}

// RotatePublicKeyForNamespaceParams exports the rotatePublicKeyForNamespaceParams type
type RotatePublicKeyForNamespaceParams = rotatePublicKeyForNamespaceParams

// RotatePublicKeyForNamespace exports the rotatePublicKeyForNamespace method
func (q *Queries) RotatePublicKeyForNamespace(ctx context.Context, arg RotatePublicKeyForNamespaceParams) ([]string, error) {
	return q.rotatePublicKeyForNamespace(ctx, arg)
}

// RotatePublicKeyForAttributeDefinitionParams exports the rotatePublicKeyForAttributeDefinitionParams type
type RotatePublicKeyForAttributeDefinitionParams = rotatePublicKeyForAttributeDefinitionParams

// RotatePublicKeyForAttributeDefinition exports the rotatePublicKeyForAttributeDefinition method
func (q *Queries) RotatePublicKeyForAttributeDefinition(ctx context.Context, arg RotatePublicKeyForAttributeDefinitionParams) ([]string, error) {
	return q.rotatePublicKeyForAttributeDefinition(ctx, arg)
}

// KAS Registry exports

// ListKeyAccessServersParams exports the listKeyAccessServersParams type
type ListKeyAccessServersParams = listKeyAccessServersParams

// ListKeyAccessServersRow exports the listKeyAccessServersRow type
type ListKeyAccessServersRow = listKeyAccessServersRow

// ListKeyAccessServers exports the listKeyAccessServers method
func (q *Queries) ListKeyAccessServers(ctx context.Context, arg ListKeyAccessServersParams) ([]ListKeyAccessServersRow, error) {
	return q.listKeyAccessServers(ctx, arg)
}

// GetKeyAccessServerParams exports the getKeyAccessServerParams type
type GetKeyAccessServerParams = getKeyAccessServerParams

// GetKeyAccessServerRow exports the getKeyAccessServerRow type
type GetKeyAccessServerRow = getKeyAccessServerRow

// GetKeyAccessServer exports the getKeyAccessServer method
func (q *Queries) GetKeyAccessServer(ctx context.Context, arg GetKeyAccessServerParams) (GetKeyAccessServerRow, error) {
	return q.getKeyAccessServer(ctx, arg)
}

// CreateKeyAccessServerParams exports the createKeyAccessServerParams type
type CreateKeyAccessServerParams = createKeyAccessServerParams

// CreateKeyAccessServer exports the createKeyAccessServer method
func (q *Queries) CreateKeyAccessServer(ctx context.Context, arg CreateKeyAccessServerParams) (string, error) {
	return q.createKeyAccessServer(ctx, arg)
}

// UpdateKeyAccessServerParams exports the updateKeyAccessServerParams type
type UpdateKeyAccessServerParams = updateKeyAccessServerParams

// UpdateKeyAccessServer exports the updateKeyAccessServer method
func (q *Queries) UpdateKeyAccessServer(ctx context.Context, arg UpdateKeyAccessServerParams) (int64, error) {
	return q.updateKeyAccessServer(ctx, arg)
}

// DeleteKeyAccessServer exports the deleteKeyAccessServer method
func (q *Queries) DeleteKeyAccessServer(ctx context.Context, id string) (int64, error) {
	return q.deleteKeyAccessServer(ctx, id)
}

// ListKeyAccessServerGrantsParams exports the listKeyAccessServerGrantsParams type
type ListKeyAccessServerGrantsParams = listKeyAccessServerGrantsParams

// ListKeyAccessServerGrantsRow exports the listKeyAccessServerGrantsRow type
type ListKeyAccessServerGrantsRow = listKeyAccessServerGrantsRow

// ListKeyAccessServerGrants exports the listKeyAccessServerGrants method
func (q *Queries) ListKeyAccessServerGrants(ctx context.Context, arg ListKeyAccessServerGrantsParams) ([]ListKeyAccessServerGrantsRow, error) {
	return q.listKeyAccessServerGrants(ctx, arg)
}

// Key-related exports

// GetKeyParams exports the getKeyParams type
type GetKeyParams = getKeyParams

// GetKeyRow exports the getKeyRow type
type GetKeyRow = getKeyRow

// GetKey exports the getKey method
func (q *Queries) GetKey(ctx context.Context, arg GetKeyParams) (GetKeyRow, error) {
	return q.getKey(ctx, arg)
}

// ListKeysParams exports the listKeysParams type
type ListKeysParams = listKeysParams

// ListKeysRow exports the listKeysRow type
type ListKeysRow = listKeysRow

// ListKeys exports the listKeys method
func (q *Queries) ListKeys(ctx context.Context, arg ListKeysParams) ([]ListKeysRow, error) {
	return q.listKeys(ctx, arg)
}

// CreateKeyParams exports the createKeyParams type
type CreateKeyParams = createKeyParams

// CreateKey exports the createKey method
func (q *Queries) CreateKey(ctx context.Context, arg CreateKeyParams) (string, error) {
	return q.createKey(ctx, arg)
}

// UpdateKeyParams exports the updateKeyParams type
type UpdateKeyParams = updateKeyParams

// UpdateKey exports the updateKey method
func (q *Queries) UpdateKey(ctx context.Context, arg UpdateKeyParams) (int64, error) {
	return q.updateKey(ctx, arg)
}

// DeleteKey exports the deleteKey method
func (q *Queries) DeleteKey(ctx context.Context, id string) (int64, error) {
	return q.deleteKey(ctx, id)
}

// GetBaseKey exports the getBaseKey method
func (q *Queries) GetBaseKey(ctx context.Context) (interface{}, error) {
	return q.getBaseKey(ctx)
}

// SetBaseKey exports the setBaseKey method
func (q *Queries) SetBaseKey(ctx context.Context, keyAccessServerKeyID interface{}) (int64, error) {
	// The generated code expects sql.NullString, so we need to convert
	return q.setBaseKey(ctx, toNullString(keyAccessServerKeyID))
}

// ListKeyMappingsParams exports the listKeyMappingsParams type
type ListKeyMappingsParams = listKeyMappingsParams

// ListKeyMappingsRow exports the listKeyMappingsRow type
type ListKeyMappingsRow = listKeyMappingsRow

// ListKeyMappings exports the listKeyMappings method
func (q *Queries) ListKeyMappings(ctx context.Context, arg ListKeyMappingsParams) ([]ListKeyMappingsRow, error) {
	return q.listKeyMappings(ctx, arg)
}
