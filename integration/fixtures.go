package integration

import (
	"log/slog"
	"os"

	"gopkg.in/yaml.v2"
)

var fixtureFilename = "fixtures.yaml"
var fixtureData FixtureData

type FixtureMetadata struct {
	TableName string   `yaml:"table_name"`
	Columns   []string `yaml:"columns"`
}

type FixtureDataNamespace struct {
	Id   string `yaml:"id"`
	Name string `yaml:"name"`
}

type FixtureDataAttribute struct {
	Id          string `yaml:"id"`
	NamespaceId string `yaml:"namespace_id"`
	Name        string `yaml:"name"`
	Rule        string `yaml:"rule"`
}

type FixtureDataAttributeValue struct {
	Id                    string   `yaml:"id"`
	AttributeDefinitionId string   `yaml:"attribute_definition_id"`
	Value                 string   `yaml:"value"`
	Members               []string `yaml:"members"`
}

type FixtureDataSubjectMapping struct {
	Id                     string   `yaml:"id"`
	AttributeValueId       string   `yaml:"attribute_value_id"`
	Operator               string   `yaml:"operator"`
	SubjectAttribute       string   `yaml:"subject_attribute"`
	SubjectAttributeValues []string `yaml:"subject_attribute_values"`
}

type FixtureData struct {
	Namespaces struct {
		Metadata FixtureMetadata                 `yaml:"metadata"`
		Data     map[string]FixtureDataNamespace `yaml:"data"`
	} `yaml:"namespaces"`
	Attributes struct {
		Metadata FixtureMetadata                 `yaml:"metadata"`
		Data     map[string]FixtureDataAttribute `yaml:"data"`
	} `yaml:"attributes"`
	AttributeValues struct {
		Metadata FixtureMetadata                      `yaml:"metadata"`
		Data     map[string]FixtureDataAttributeValue `yaml:"data"`
	} `yaml:"attribute_values"`
	SubjectMappings struct {
		Metadata FixtureMetadata                      `yaml:"metadata"`
		Data     map[string]FixtureDataSubjectMapping `yaml:"data"`
	} `yaml:"subject_mappings"`
}

func loadFixtureData() {
	c, err := os.ReadFile(fixtureFilename)
	if err != nil {
		slog.Error("could not read "+fixtureFilename, slog.String("error", err.Error()))
		panic(err)
	}

	if err := yaml.Unmarshal(c, &fixtureData); err != nil {
		slog.Error("could not unmarshal "+fixtureFilename, slog.String("error", err.Error()))
		panic(err)
	}
}

type Fixtures struct {
	db DBInterface
}

func NewFixture(db DBInterface) Fixtures {
	return Fixtures{
		db: db,
	}
}

func (f *Fixtures) GetNamespaceKey(key string) FixtureDataNamespace {
	if fixtureData.Namespaces.Data[key].Id == "" {
		slog.Error("could not find namespace", slog.String("id", key))
		panic("could not find namespace")
	}
	return fixtureData.Namespaces.Data[key]
}

func (f *Fixtures) GetAttributeKey(key string) FixtureDataAttribute {
	if fixtureData.Attributes.Data[key].Id == "" {
		slog.Error("could not find attributes", slog.String("id", key))
		panic("could not find attributes")
	}
	return fixtureData.Attributes.Data[key]
}

func (f *Fixtures) GetAttributeValueKey(key string) FixtureDataAttributeValue {
	if fixtureData.AttributeValues.Data[key].Id == "" {
		slog.Error("could not find attribute-values", slog.String("id", key))
		panic("could not find attribute-values")
	}
	return fixtureData.AttributeValues.Data[key]
}

func (f *Fixtures) GetSubjectMappingKey(key string) FixtureDataSubjectMapping {
	if fixtureData.SubjectMappings.Data[key].Id == "" {
		slog.Error("could not find subject-mappings", slog.String("id", key))
		panic("could not find subject-mappings")
	}
	return fixtureData.SubjectMappings.Data[key]
}

func (f *Fixtures) Provision() {
	slog.Info("📦 running migrations in schema", slog.String("schema", f.db.schema))
	f.db.Client.RunMigrations()

	slog.Info("📦 provisioning namespace data")
	n := f.provisionNamespace()
	slog.Info("📦 provisioning attribute data")
	a := f.provisionAttribute()
	slog.Info("📦 provisioning attribute value data")
	aV := f.provisionAttributeValues()
	slog.Info("📦 provisioning subject mapping data")
	sM := f.provisionSubjectMappings()

	slog.Info("📦 provisioned fixtures data",
		slog.Int64("namespaces", n),
		slog.Int64("attributes", a),
		slog.Int64("attribute_values", aV),
		slog.Int64("subject_mappings", sM),
	)
}

func (f *Fixtures) TearDown() {
	slog.Info("🗑  dropping schema", slog.String("schema", f.db.schema))
	if err := f.db.DropSchema(); err != nil {
		slog.Error("could not truncate tables", slog.String("error", err.Error()))
		panic(err)
	}
}

func (f *Fixtures) provisionNamespace() int64 {
	var values [][]string
	for _, d := range fixtureData.Namespaces.Data {
		values = append(values,
			[]string{
				f.db.StringWrap(d.Id),
				f.db.StringWrap(d.Name),
			},
		)
	}
	return f.provision(fixtureData.Namespaces.Metadata.TableName, fixtureData.Namespaces.Metadata.Columns, values)
}

func (f *Fixtures) provisionAttribute() int64 {
	var values [][]string
	for _, d := range fixtureData.Attributes.Data {
		values = append(values, []string{
			f.db.StringWrap(d.Id),
			f.db.StringWrap(d.NamespaceId),
			f.db.StringWrap(d.Name),
			f.db.StringWrap(d.Rule),
		})
	}
	return f.provision(fixtureData.Attributes.Metadata.TableName, fixtureData.Attributes.Metadata.Columns, values)
}

func (f *Fixtures) provisionAttributeValues() int64 {
	var values [][]string
	for _, d := range fixtureData.AttributeValues.Data {
		values = append(values, []string{
			f.db.StringWrap(d.Id),
			f.db.StringWrap(d.AttributeDefinitionId),
			f.db.StringWrap(d.Value),
			f.db.UUIDArrayWrap(d.Members),
		})
	}
	return f.provision(fixtureData.AttributeValues.Metadata.TableName, fixtureData.AttributeValues.Metadata.Columns, values)
}

func (f *Fixtures) provisionSubjectMappings() int64 {
	var values [][]string
	for _, d := range fixtureData.SubjectMappings.Data {
		values = append(values, []string{
			f.db.StringWrap(d.Id),
			f.db.UUIDWrap(d.AttributeValueId),
			f.db.StringWrap(d.Operator),
			f.db.StringWrap(d.SubjectAttribute),
			f.db.StringArrayWrap(d.SubjectAttributeValues),
		})
	}
	return f.provision(fixtureData.SubjectMappings.Metadata.TableName, fixtureData.SubjectMappings.Metadata.Columns, values)
}

func (f *Fixtures) provision(t string, c []string, v [][]string) (rows int64) {
	var err error
	rows, err = f.db.ExecInsert(t, c, v...)
	if err != nil {
		slog.Error("⛔️ 📦 issue with insert into table - check fixtures.yaml for issues", slog.String("table", t))
		panic("issue with insert into table")
	}
	if rows == 0 {
		slog.Error("⛔️ 📦 no rows provisioned - check fixtures.yaml for issues", slog.String("table", t), slog.Int("expected", len(v)))
		panic("no rows provisioned")
	}
	if rows != int64(len(v)) {
		slog.Error("⛔️ 📦 incorrect number of rows provisioned - check fixtures.yaml for issues", slog.String("table", t), slog.Int("expected", len(v)), slog.Int64("actual", rows))
		panic("incorrect number of rows provisioned")
	}
	return rows
}
