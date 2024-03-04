package fixtures

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v2"
)

var (
	fixtureFilename = "fixtures.yaml"
	fixtureData     FixtureData
)

type FixtureMetadata struct {
	TableName string   `yaml:"table_name"`
	Columns   []string `yaml:"columns"`
}

type FixtureDataNamespace struct {
	Id     string `yaml:"id"`
	Name   string `yaml:"name"`
	Active bool   `yaml:"active"`
}

type FixtureDataAttribute struct {
	Id          string `yaml:"id"`
	NamespaceId string `yaml:"namespace_id"`
	Name        string `yaml:"name"`
	Rule        string `yaml:"rule"`
	Active      bool   `yaml:"active"`
}

type FixtureDataAttributeKeyAccessServer struct {
	AttributeID       string `yaml:"attribute_id"`
	KeyAccessServerID string `yaml:"key_access_server_id"`
}

type FixtureDataAttributeValue struct {
	Id                    string   `yaml:"id"`
	AttributeDefinitionId string   `yaml:"attribute_definition_id"`
	Value                 string   `yaml:"value"`
	Members               []string `yaml:"members"`
	Active                bool     `yaml:"active"`
}

type FixtureDataAttributeValueKeyAccessServer struct {
	ValueID           string `yaml:"value_id"`
	KeyAccessServerID string `yaml:"key_access_server_id"`
}

type FixtureDataSubjectMapping struct {
	Id                          string   `yaml:"id"`
	AttributeValueId            string   `yaml:"attribute_value_id"`
	Actions                     []string `yaml:"actions"`
	SubjectConditionSetPivotIds []string `yaml:"subject_condition_set_pivot_ids"`
}

type FixtureSubjectMappingConditionSetPivot struct {
	Id                    string `yaml:"id"`
	SubjectMappingId      string `yaml:"subject_mapping_id"`
	SubjectConditionSetId string `yaml:"subject_condition_set_id"`
}

type SubjectConditionSet struct {
	Id        string `yaml:"id"`
	Name      string `yaml:"name"`
	Condition struct {
		SubjectSets []struct {
			ConditionGroups []struct {
				BooleanOperator string `yaml:"boolean_operator" json:"boolean_operator"`
				Conditions      []struct {
					SubjectExternalField  string   `yaml:"subject_external_field" json:"subject_external_field"`
					Operator              string   `yaml:"operator" json:"operator"`
					SubjectExternalValues []string `yaml:"subject_external_values" json:"subject_external_values"`
				} `yaml:"conditions" json:"conditions"`
			} `yaml:"condition_groups" json:"condition_groups"`
		} `yaml:"subject_sets" json:"subject_sets"`
	} `yaml:"condition" json:"condition"`
}

type FixtureDataResourceMapping struct {
	Id               string   `yaml:"id"`
	AttributeValueId string   `yaml:"attribute_value_id"`
	Terms            []string `yaml:"terms"`
}

type FixtureDataKasRegistry struct {
	Id     string `yaml:"id"`
	Uri    string `yaml:"uri"`
	PubKey struct {
		Remote string `yaml:"remote" json:"remote,omitempty"`
		Local  string `yaml:"local" json:"local,omitempty"`
	} `yaml:"public_key" json:"public_key"`
}

type FixtureData struct {
	Namespaces struct {
		Metadata FixtureMetadata                 `yaml:"metadata"`
		Data     map[string]FixtureDataNamespace `yaml:"data"`
	} `yaml:"attribute_namespaces"`
	Attributes struct {
		Metadata FixtureMetadata                 `yaml:"metadata"`
		Data     map[string]FixtureDataAttribute `yaml:"data"`
	} `yaml:"attributes"`
	AttributeKeyAccessServer []FixtureDataAttributeKeyAccessServer `yaml:"attribute_key_access_servers"`
	AttributeValues          struct {
		Metadata FixtureMetadata                      `yaml:"metadata"`
		Data     map[string]FixtureDataAttributeValue `yaml:"data"`
	} `yaml:"attribute_values"`
	AttributeValueKeyAccessServer []FixtureDataAttributeValueKeyAccessServer `yaml:"attribute_value_key_access_servers"`
	SubjectMappings               struct {
		Metadata FixtureMetadata                      `yaml:"metadata"`
		Data     map[string]FixtureDataSubjectMapping `yaml:"data"`
	} `yaml:"subject_mappings"`
	SubjectMappingConditionSetPivot struct {
		Metadata FixtureMetadata                                   `yaml:"metadata"`
		Data     map[string]FixtureSubjectMappingConditionSetPivot `yaml:"data"`
	} `yaml:"subject_mapping_condition_set_pivot"`
	SubjectConditionSet struct {
		Metadata FixtureMetadata                `yaml:"metadata"`
		Data     map[string]SubjectConditionSet `yaml:"data"`
	} `yaml:"subject_condition_set"`
	ResourceMappings struct {
		Metadata FixtureMetadata                       `yaml:"metadata"`
		Data     map[string]FixtureDataResourceMapping `yaml:"data"`
	} `yaml:"resource_mappings"`
	KasRegistries struct {
		Metadata FixtureMetadata                   `yaml:"metadata"`
		Data     map[string]FixtureDataKasRegistry `yaml:"data"`
	} `yaml:"kas_registry"`
}

func LoadFixtureData(file string) {
	c, err := os.ReadFile(file)
	if err != nil {
		slog.Error("could not read "+fixtureFilename, slog.String("error", err.Error()))
		panic(err)
	}

	if err := yaml.Unmarshal(c, &fixtureData); err != nil {
		slog.Error("could not unmarshal "+fixtureFilename, slog.String("error", err.Error()))
		panic(err)
	}
	fmt.Println(fixtureData)
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

func (f *Fixtures) GetResourceMappingKey(key string) FixtureDataResourceMapping {
	if fixtureData.ResourceMappings.Data[key].Id == "" {
		slog.Error("could not find resource-mappings", slog.String("id", key))
		panic("could not find resource-mappings")
	}
	return fixtureData.ResourceMappings.Data[key]
}

func (f *Fixtures) GetKasRegistryKey(key string) FixtureDataKasRegistry {
	if fixtureData.KasRegistries.Data[key].Id == "" {
		slog.Error("could not find kas-registry", slog.String("id", key))
		panic("could not find kas-registry")
	}
	return fixtureData.KasRegistries.Data[key]
}

func (f *Fixtures) Provision() {
	slog.Info("📦 running migrations in schema", slog.String("schema", f.db.Schema))
	_, err := f.db.Client.RunMigrations(context.Background())
	if err != nil {
		panic(err)
	}

	slog.Info("📦 provisioning namespace data")
	n := f.provisionNamespace()
	slog.Info("📦 provisioning attribute data")
	a := f.provisionAttribute()
	slog.Info("📦 provisioning attribute value data")
	aV := f.provisionAttributeValues()
	slog.Info("📦 provisioning subject mapping data")
	sM := f.provisionSubjectMappings()
	slog.Info("📦 provisioning subject condition set data")
	sc := f.provisionSubjectConditionSet()
	slog.Info("📦 provisioning subject mapping condition set pivot data")
	smPivot := f.provisionSubjectMappingConditionSetPivot()
	slog.Info("📦 provisioning resource mapping data")
	rM := f.provisionResourceMappings()
	slog.Info("📦 provisioning kas registry data")
	kas := f.provisionKasRegistry()
	slog.Info("📦 provisioning attribute key access server data")
	akas := f.provisionAttributeKeyAccessServer()
	slog.Info("📦 provisioning attribute value key access server data")
	avkas := f.provisionAttributeValueKeyAccessServer()

	slog.Info("📦 provisioned fixtures data",
		slog.Int64("namespaces", n),
		slog.Int64("attributes", a),
		slog.Int64("attribute_values", aV),
		slog.Int64("subject_mappings", sM),
		slog.Int64("subject_mapping_condition_set_pivot", smPivot),
		slog.Int64("subject_condition_set", sc),
		slog.Int64("resource_mappings", rM),
		slog.Int64("kas_registry", kas),
		slog.Int64("attribute_key_access_server", akas),
		slog.Int64("attribute_value_key_access_server", avkas),
	)
	slog.Info("📚 indexing FQNs for fixtures")
	f.db.PolicyClient.AttrFqnReindex()
	slog.Info("📚 successfully indexed FQNs")
}

func (f *Fixtures) TearDown() {
	slog.Info("🗑  dropping schema", slog.String("schema", f.db.Schema))
	if err := f.db.DropSchema(); err != nil {
		slog.Error("could not truncate tables", slog.String("error", err.Error()))
		panic(err)
	}
}

func (f *Fixtures) provisionNamespace() int64 {
	values := make([][]string, 0, len(fixtureData.Namespaces.Data))
	for _, d := range fixtureData.Namespaces.Data {
		values = append(values,
			[]string{
				f.db.StringWrap(d.Id),
				f.db.StringWrap(d.Name),
				f.db.BoolWrap(d.Active),
			},
		)
	}
	return f.provision(fixtureData.Namespaces.Metadata.TableName, fixtureData.Namespaces.Metadata.Columns, values)
}

func (f *Fixtures) provisionAttribute() int64 {
	values := make([][]string, 0, len(fixtureData.Attributes.Data))
	for _, d := range fixtureData.Attributes.Data {
		values = append(values, []string{
			f.db.StringWrap(d.Id),
			f.db.StringWrap(d.NamespaceId),
			f.db.StringWrap(d.Name),
			f.db.StringWrap(d.Rule),
			f.db.BoolWrap(d.Active),
		})
	}
	return f.provision(fixtureData.Attributes.Metadata.TableName, fixtureData.Attributes.Metadata.Columns, values)
}

func (f *Fixtures) provisionAttributeValues() int64 {
	values := make([][]string, 0, len(fixtureData.AttributeValues.Data))
	for _, d := range fixtureData.AttributeValues.Data {
		values = append(values, []string{
			f.db.StringWrap(d.Id),
			f.db.StringWrap(d.AttributeDefinitionId),
			f.db.StringWrap(d.Value),
			f.db.UUIDArrayWrap(d.Members),
			f.db.BoolWrap(d.Active),
		})
	}
	return f.provision(fixtureData.AttributeValues.Metadata.TableName, fixtureData.AttributeValues.Metadata.Columns, values)
}

func (f *Fixtures) provisionSubjectMappings() int64 {
	values := make([][]string, 0, len(fixtureData.SubjectMappings.Data))
	for _, d := range fixtureData.SubjectMappings.Data {
		values = append(values, []string{
			f.db.StringWrap(d.Id),
			f.db.UUIDWrap(d.AttributeValueId),
			f.db.StringArrayWrap(d.Actions),
			f.db.UUIDArrayWrap(d.SubjectConditionSetPivotIds),
		})
	}
	return f.provision(fixtureData.SubjectMappings.Metadata.TableName, fixtureData.SubjectMappings.Metadata.Columns, values)
}

func (f *Fixtures) provisionSubjectMappingConditionSetPivot() int64 {
	values := make([][]string, 0, len(fixtureData.SubjectMappingConditionSetPivot.Data))
	for _, d := range fixtureData.SubjectMappingConditionSetPivot.Data {
		values = append(values, []string{
			f.db.StringWrap(d.Id),
			f.db.StringWrap(d.SubjectMappingId),
			f.db.StringWrap(d.SubjectConditionSetId),
		})
	}
	return f.provision(fixtureData.SubjectMappingConditionSetPivot.Metadata.TableName, fixtureData.SubjectMappingConditionSetPivot.Metadata.Columns, values)
}

func (f *Fixtures) provisionSubjectConditionSet() int64 {
	values := make([][]string, 0, len(fixtureData.SubjectConditionSet.Data))
	for _, d := range fixtureData.SubjectConditionSet.Data {
		var conditionJSON []byte
		conditionJSON, err := json.Marshal(d.Condition)
		if err != nil {
			slog.Error("⛔️ 📦 issue with subject condition set JSON - check fixtures.yaml for issues")
			panic("issue with subject condition set JSON")
		}

		values = append(values, []string{
			f.db.StringWrap(d.Id),
			f.db.StringWrap(d.Name),
			f.db.StringWrap(string(conditionJSON)),
		})
	}
	return f.provision(fixtureData.SubjectConditionSet.Metadata.TableName, fixtureData.SubjectConditionSet.Metadata.Columns, values)
}

func (f *Fixtures) provisionResourceMappings() int64 {
	values := make([][]string, 0, len(fixtureData.ResourceMappings.Data))
	for _, d := range fixtureData.ResourceMappings.Data {
		values = append(values, []string{
			f.db.StringWrap(d.Id),
			f.db.StringWrap(d.AttributeValueId),
			f.db.StringArrayWrap(d.Terms),
		})
	}
	return f.provision(fixtureData.ResourceMappings.Metadata.TableName, fixtureData.ResourceMappings.Metadata.Columns, values)
}

func (f *Fixtures) provisionKasRegistry() int64 {
	values := make([][]string, 0, len(fixtureData.KasRegistries.Data))
	for _, d := range fixtureData.KasRegistries.Data {
		v := []string{
			f.db.StringWrap(d.Id),
			f.db.StringWrap(d.Uri),
		}

		if pubKeyJSON, err := json.Marshal(d.PubKey); err != nil {
			slog.Error("⛔️ 📦 issue with KAS registry public key JSON - check fixtures.yaml for issues")
			panic("issue with KAS registry public key JSON")
		} else {
			v = append(v, f.db.StringWrap(string(pubKeyJSON)))
		}
		values = append(values, v)
	}
	return f.provision(fixtureData.KasRegistries.Metadata.TableName, fixtureData.KasRegistries.Metadata.Columns, values)
}

func (f *Fixtures) provisionAttributeKeyAccessServer() int64 {
	values := make([][]string, 0, len(fixtureData.AttributeKeyAccessServer))
	for _, d := range fixtureData.AttributeKeyAccessServer {
		values = append(values, []string{
			f.db.StringWrap(d.AttributeID),
			f.db.StringWrap(d.KeyAccessServerID),
		})
	}
	return f.provision("attribute_definition_key_access_grants", []string{"attribute_definition_id", "key_access_server_id"}, values)
}

func (f *Fixtures) provisionAttributeValueKeyAccessServer() int64 {
	values := make([][]string, 0, len(fixtureData.AttributeValueKeyAccessServer))
	for _, d := range fixtureData.AttributeValueKeyAccessServer {
		values = append(values, []string{
			f.db.StringWrap(d.ValueID),
			f.db.StringWrap(d.KeyAccessServerID),
		})
	}
	return f.provision("attribute_value_key_access_grants", []string{"attribute_value_id", "key_access_server_id"}, values)
}

func (f *Fixtures) provision(t string, c []string, v [][]string) int64 {
	rows, err := f.db.ExecInsert(t, c, v...)
	if err != nil {
		slog.Error("⛔️ 📦 issue with insert into table - check fixtures.yaml for issues", slog.String("table", t), slog.Any("err", err))
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
