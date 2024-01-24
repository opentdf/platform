package integration

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"gopkg.in/yaml.v2"
)

var fixtureFilename = "testdata/fixtures.yaml"

type fixtureMetadata struct {
	TableName string   `yaml:"table_name"`
	Columns   []string `yaml:"columns"`
}
type fixtureData struct {
	Namespaces struct {
		Metadata fixtureMetadata `yaml:"metadata"`
		Data     map[string]struct {
			Id   string `yaml:"id"`
			Name string `yaml:"name"`
		} `yaml:"data"`
	} `yaml:"namespaces"`
	Attributes struct {
		Metadata fixtureMetadata `yaml:"metadata"`
		Data     map[string]struct {
			Id          string `yaml:"id"`
			NamespaceId string `yaml:"namespace_id"`
			Name        string `yaml:"name"`
			Rule        string `yaml:"rule"`
		} `yaml:"data"`
	} `yaml:"attributes"`
	AttributeValues struct {
		Metadata fixtureMetadata `yaml:"metadata"`
		Data     map[string]struct {
			Id                    string   `yaml:"id"`
			AttributeDefinitionId string   `yaml:"attribute_definition_id"`
			Value                 string   `yaml:"value"`
			Members               []string `yaml:"members"`
		} `yaml:"data"`
	} `yaml:"attribute_values"`
	SubjectMappings struct {
		Metadata fixtureMetadata `yaml:"metadata"`
		Data     map[string]struct {
			Id                     string   `yaml:"id"`
			Operator               string   `yaml:"operator"`
			SubjectAttribute       string   `yaml:"subject_attribute"`
			SubjectAttributeValues []string `yaml:"subject_attribute_values"`
		} `yaml:"data"`
	} `yaml:"subject_mappings"`
}

type Fixtures struct {
	db *db.Client
	d  fixtureData
}

func NewFixture(dbClient *db.Client) Fixtures {
	f := Fixtures{
		db: dbClient,
	}

	slog.Info("🏠 loading fixtures")
	c, err := os.ReadFile(fixtureFilename)
	if err != nil {
		slog.Error("could not read "+fixtureFilename, slog.String("error", err.Error()))
		panic(err)
	}

	if err := yaml.Unmarshal(c, &f.d); err != nil {
		slog.Error("could not unmarshal "+fixtureFilename, slog.String("error", err.Error()))
		panic(err)
	}

	return f
}

func (f *Fixtures) provisionData() {
	slog.Info("📦 provisioning namespace data", slog.String("table", f.d.Namespaces.Metadata.TableName))
	var namespaceRows int64
	for key, d := range f.d.Namespaces.Data {
		namespaceRows += f.execInsert(
			key,
			f.d.Namespaces.Metadata.TableName,
			f.d.Namespaces.Metadata.Columns,
			[]string{
				dbStringWrap(d.Id),
				dbStringWrap(d.Name),
			},
		)
	}

	slog.Info("📦 provisioning attribute data", slog.String("table", f.d.Attributes.Metadata.TableName))
	var attributeRows int64
	for key, d := range f.d.Attributes.Data {
		attributeRows += f.execInsert(
			key,
			f.d.Attributes.Metadata.TableName,
			f.d.Attributes.Metadata.Columns,
			[]string{
				dbStringWrap(d.Id),
				dbStringWrap(d.NamespaceId),
				dbStringWrap(d.Name),
				dbStringWrap(d.Rule),
			},
		)
	}

	slog.Info("📦 provisioning attribute value data", slog.String("table", f.d.AttributeValues.Metadata.TableName))
	var attributeValueRows int64
	for key, d := range f.d.AttributeValues.Data {
		attributeValueRows += f.execInsert(
			key,
			f.d.AttributeValues.Metadata.TableName,
			f.d.AttributeValues.Metadata.Columns,
			[]string{
				dbStringWrap(d.Id),
				dbStringWrap(d.AttributeDefinitionId),
				dbStringWrap(d.Value),
				dbUUIDArrayWrap(d.Members),
			},
		)
	}

	slog.Info("📦 provisioning subject mapping data", slog.String("table", f.d.SubjectMappings.Metadata.TableName))
	var subjectMappingRows int64
	for key, d := range f.d.SubjectMappings.Data {
		subjectMappingRows += f.execInsert(
			key,
			f.d.SubjectMappings.Metadata.TableName,
			f.d.SubjectMappings.Metadata.Columns,
			[]string{
				dbStringWrap(d.Id),
				dbStringWrap(d.Operator),
				dbStringWrap(d.SubjectAttribute),
				dbStringArrayWrap(d.SubjectAttributeValues),
			},
		)
	}

	slog.Info("📦 provisioned fixtures data", slog.Int64("namespace_rows", namespaceRows), slog.Int64("attribute_rows", attributeRows), slog.Int64("attribute_value_rows", attributeValueRows), slog.Int64("subject_mapping_rows", subjectMappingRows))
}

func dbStringArrayWrap(values []string) string {
	// if len(values) == 0 {
	// 	return "null"
	// }
	var vs []string
	for _, v := range values {
		vs = append(vs, dbStringWrap(v))
	}
	return "ARRAY [" + strings.Join(vs, ",") + "]"
}

func dbUUIDArrayWrap(v []string) string {
	return "(" + dbStringArrayWrap(v) + ")" + "::uuid[]"
}

func dbStringWrap(v string) string {
	return "'" + v + "'"
}

func dbTableName(v string) string {
	return db.Schema + "." + v
}

func (f *Fixtures) execInsert(key string, table string, columns []string, values []string) int64 {
	sql := "INSERT INTO " + dbTableName(table) + " (" + strings.Join(columns, ",") + ") VALUES (" + strings.Join(values, ",") + ")"
	pconn, err := f.db.Exec(context.Background(), sql)
	if err != nil {
		slog.Error("could not provision data", slog.String("table_name", table), slog.String("error", err.Error()))
		panic(err)
	}
	return pconn.RowsAffected()
}

func (f *Fixtures) truncateAllTables() {
	slog.Info("🗑  truncating all tables")
	sql := "TRUNCATE TABLE " +
		dbTableName(f.d.Namespaces.Metadata.TableName) + ", " +
		dbTableName(f.d.Attributes.Metadata.TableName) + ", " +
		dbTableName(f.d.AttributeValues.Metadata.TableName) + ", " +
		dbTableName(f.d.SubjectMappings.Metadata.TableName) + " CASCADE"

	_, err := f.db.Exec(context.Background(), sql)
	if err != nil {
		slog.Error("could not truncate tables", slog.String("error", err.Error()))
		panic(err)
	}
}
