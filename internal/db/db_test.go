package db

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	acrev1 "github.com/opentdf/opentdf-v2-poc/gen/acre/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/stretchr/testify/assert"
)

var (
	//nolint:gochecknoglobals // Test data and should be reintialized for each test
	resourceDescriptor = &commonv1.ResourceDescriptor{
		Name:        "relto",
		Namespace:   "opentdf",
		Version:     1,
		Fqn:         "http://opentdf.com/attr/relto",
		Labels:      map[string]string{"origin": "Country of Origin"},
		Description: "The relto attribute is used to describe the relationship of the resource to the country of origin.",
		Type:        commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM,
	}

	//nolint:gochecknoglobals // Test data and should be reintialized for each test
	testResource = &acrev1.Synonyms{
		Terms: []string{"relto", "rel-to", "rel_to"},
	}
)

func Test_RunMigrations_Returns_Expected_Applied(t *testing.T) {
	client := &Client{
		PgxIface: nil,
		config: Config{
			RunMigrations: false,
		},
	}

	applied, err := client.RunMigrations()

	assert.Nil(t, err)
	assert.Equal(t, 0, applied)
}

func Test_RunMigrations_Returns_Error_When_PGX_Iface_Is_Nil(t *testing.T) {
	client := &Client{
		PgxIface: nil,
		config: Config{
			RunMigrations: true,
		},
	}

	applied, err := client.RunMigrations()

	assert.ErrorContains(t, err, "failed to cast pgxpool.Pool")
	assert.Equal(t, 0, applied)
}

type BadPGX struct{}

func (b BadPGX) Acquire(_ context.Context) (*pgxpool.Conn, error) { return &pgxpool.Conn{}, nil }
func (b BadPGX) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (b BadPGX) QueryRow(context.Context, string, ...any) pgx.Row        { return nil }
func (b BadPGX) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }
func (b BadPGX) Ping(context.Context) error                              { return nil }
func (b BadPGX) Close()                                                  {}
func (b BadPGX) Config() *pgxpool.Config                                 { return nil }

func Test_RunMigrations_Returns_Error_When_PGX_Iface_Is_Wrong_Type(t *testing.T) {
	client := &Client{
		PgxIface: &BadPGX{},
		config: Config{
			RunMigrations: true,
		},
	}

	applied, err := client.RunMigrations()

	assert.ErrorContains(t, err, "failed to cast pgxpool.Pool")
	assert.Equal(t, 0, applied)
}

func Test_CreateResourceSQL_Returns_Expected_SQL_Statement(t *testing.T) {
	// Copy the test data so we don't modify it
	descriptor := resourceDescriptor
	resource := testResource

	sql, args, err := createResourceSQL(descriptor, resource)

	assert.Nil(t, err)
	assert.Equal(t, "INSERT INTO opentdf.resources (name,namespace,version,fqn,labels,description,policytype,resource) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)", sql)
	assert.Equal(t, []interface{}{descriptor.Name, descriptor.Namespace, descriptor.Version, descriptor.Fqn, descriptor.Labels, descriptor.Description, descriptor.Type.String(), resource}, args)
}

func Test_ListResourceSQL_Returns_Expected_SQL_Statement(t *testing.T) {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}
	sql, args, err := listResourceSQL(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(), selector)

	assert.Nil(t, err)
	assert.Equal(t, "SELECT id, resource FROM opentdf.resources WHERE policytype = $1 AND namespace = $2 AND version = $3", sql)
	assert.Equal(t, []interface{}{commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(), selector.Namespace, int32(1)}, args)
}

func Test_ListResourceSQL_Returns_Expected_SQL_Statement_With_Selector_Labels(t *testing.T) {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Selector: &commonv1.ResourceSelector_LabelSelector_{
			LabelSelector: &commonv1.ResourceSelector_LabelSelector{
				Labels: map[string]string{"origin": "Country of Origin"},
			},
		},
	}

	bLabels, err := json.Marshal(selector.Selector.(*commonv1.ResourceSelector_LabelSelector_).LabelSelector.Labels)
	if err != nil {
		t.Errorf("marshal error was not expected: %s", err.Error())
	}

	sql, args, err := listResourceSQL(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(), selector)

	assert.Nil(t, err)
	assert.Equal(t, "SELECT id, resource FROM opentdf.resources WHERE policytype = $1 AND namespace = $2 AND labels @> $3::jsonb", sql)
	assert.Equal(t, []interface{}{commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(), selector.Namespace, bLabels}, args)
}

func Test_ListResourceSQL_Returns_Expected_SQL_Statement_With_Selector_Name(t *testing.T) {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Selector: &commonv1.ResourceSelector_Name{
			Name: "relto",
		},
	}
	sql, args, err := listResourceSQL(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(), selector)

	assert.Nil(t, err)
	assert.Equal(t, "SELECT id, resource FROM opentdf.resources WHERE policytype = $1 AND namespace = $2 AND name = $3", sql)
	assert.Equal(t, []interface{}{commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(), selector.Namespace, selector.Selector.(*commonv1.ResourceSelector_Name).Name}, args)
}

func Test_GetResourceSQL_Returns_Expected_SQL_Statement(t *testing.T) {
	sql, args, err := getResourceSQL(1, commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String())

	assert.Nil(t, err)
	assert.Equal(t, "SELECT id, resource FROM opentdf.resources WHERE id = $1 AND policytype = $2", sql)
	assert.Equal(t, []interface{}{int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String()}, args)
}

func Test_UpdateResourceSQL_Returns_Expected_SQL_Statement(t *testing.T) {
	// Copy the test data so we don't modify it
	descriptor := resourceDescriptor
	resource := testResource

	sql, args, err := updateResourceSQL(descriptor, resource, commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String())

	assert.Nil(t, err)
	assert.Equal(t, "UPDATE opentdf.resources SET name = $1, namespace = $2, version = $3, description = $4, fqn = $5, labels = $6, policyType = $7, resource = $8 WHERE id = $9", sql)
	assert.Equal(t, []interface{}{descriptor.Name, descriptor.Namespace, descriptor.Version, descriptor.Description, descriptor.Fqn,
		descriptor.Labels, commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(), resource, descriptor.Id}, args)
}

func Test_DeleteResourceSQL_Returns_Expected_SQL_Statement(t *testing.T) {
	sql, args, err := deleteResourceSQL(1, commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String())

	assert.Nil(t, err)
	assert.Equal(t, "DELETE FROM opentdf.resources WHERE id = $1 AND policytype = $2", sql)
	assert.Equal(t, []interface{}{int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String()}, args)
}

func Test_BuildURL_Returns_Expected_Connection_String(t *testing.T) {
	c := Config{
		Host:     "localhost",
		Port:     5432,
		Database: "opentdf",
		User:     "postgres",
		Password: "postgres",
		SslMode:  "disable",
	}

	url := c.buildURL()

	assert.Equal(t, "postgres://postgres:postgres@localhost:5432/opentdf?sslmode=disable", url)
}
