package fixtures

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/opentdf/platform/service/policy"
	"gopkg.in/yaml.v2"
)

var (
	fixtureFilename = "policy_fixtures.yaml"
	fixtureData     FixtureData
)

type FixtureMetadata struct {
	TableName string   `yaml:"table_name"`
	Columns   []string `yaml:"columns"`
}

type FixtureDataNamespace struct {
	ID     string `yaml:"id"`
	Name   string `yaml:"name"`
	Active bool   `yaml:"active"`
}

type FixtureDataAttribute struct {
	ID          string `yaml:"id"`
	NamespaceID string `yaml:"namespace_id"`
	Name        string `yaml:"name"`
	Rule        string `yaml:"rule"`
	Active      bool   `yaml:"active"`
}

type FixtureDataAttributeKeyAccessServer struct {
	AttributeID       string `yaml:"attribute_id"`
	KeyAccessServerID string `yaml:"key_access_server_id"`
}

type FixtureDataAttributeValue struct {
	ID                    string   `yaml:"id"`
	AttributeDefinitionID string   `yaml:"attribute_definition_id"`
	Value                 string   `yaml:"value"`
	Members               []string `yaml:"members"`
	Active                bool     `yaml:"active"`
}

type FixtureDataValueMember struct {
	ID       string `yaml:"id"`
	ValueID  string `yaml:"value_id"`
	MemberID string `yaml:"member_id"`
}

type FixtureDataAttributeValueKeyAccessServer struct {
	ValueID           string `yaml:"value_id"`
	KeyAccessServerID string `yaml:"key_access_server_id"`
}

type FixtureDataSubjectMapping struct {
	ID               string `yaml:"id"`
	AttributeValueID string `yaml:"attribute_value_id"`
	Actions          []struct {
		Standard string `yaml:"standard" json:"standard,omitempty"`
		Custom   string `yaml:"custom" json:"custom,omitempty"`
	} `yaml:"actions"`
	SubjectConditionSetID string `yaml:"subject_condition_set_id"`
}

type SubjectConditionSet struct {
	ID        string `yaml:"id"`
	Condition struct {
		SubjectSets []struct {
			ConditionGroups []struct {
				BooleanOperator string `yaml:"boolean_operator" json:"boolean_operator"`
				Conditions      []struct {
					SubjectExternalSelectorValue string   `yaml:"subject_external_selector_value" json:"subject_external_selector_value"`
					Operator                     string   `yaml:"operator" json:"operator"`
					SubjectExternalValues        []string `yaml:"subject_external_values" json:"subject_external_values"`
				} `yaml:"conditions" json:"conditions"`
			} `yaml:"condition_groups" json:"condition_groups"`
		} `yaml:"subject_sets" json:"subject_sets"`
	} `yaml:"condition" json:"condition"`
}

type FixtureDataResourceMapping struct {
	ID               string   `yaml:"id"`
	AttributeValueID string   `yaml:"attribute_value_id"`
	Terms            []string `yaml:"terms"`
}

type FixtureDataKasRegistry struct {
	ID     string `yaml:"id"`
	URI    string `yaml:"uri"`
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
	ValueMembers struct {
		Metadata FixtureMetadata                   `yaml:"metadata"`
		Data     map[string]FixtureDataValueMember `yaml:"data"`
	} `yaml:"attribute_value_members"`
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
	slog.Info("Fully loaded fixtures", slog.Any("fixtureData", fixtureData))
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
	ns, ok := fixtureData.Namespaces.Data[key]
	if !ok || ns.ID == "" {
		slog.Error("could not find namespace", slog.String("id", key))
		panic("could not find namespace fixture: " + key)
	}
	return ns
}

func (f *Fixtures) GetAttributeKey(key string) FixtureDataAttribute {
	a, ok := fixtureData.Attributes.Data[key]
	if !ok || a.ID == "" {
		slog.Error("could not find attributes", slog.String("id", key))
		panic("could not find attribute fixture: " + key)
	}
	return a
}

func (f *Fixtures) GetAttributeValueKey(key string) FixtureDataAttributeValue {
	av, ok := fixtureData.AttributeValues.Data[key]
	if !ok || av.ID == "" {
		slog.Error("could not find attribute-values", slog.String("id", key))
		panic("could not find attribute-value fixture: " + key)
	}
	return av
}

func (f *Fixtures) GetValueMemberKey(key string) FixtureDataValueMember {
	if fixtureData.ValueMembers.Data[key].ID == "" {
		slog.Error("could not find value-members", slog.String("id", key))
		panic("could not find value-members")
	}
	return fixtureData.ValueMembers.Data[key]
}

func (f *Fixtures) GetSubjectMappingKey(key string) FixtureDataSubjectMapping {
	sm, ok := fixtureData.SubjectMappings.Data[key]
	if !ok || sm.ID == "" {
		slog.Error("could not find subject-mappings", slog.String("id", key))
		panic("could not find subject-mapping fixture: " + key)
	}
	return sm
}

func (f *Fixtures) GetSubjectConditionSetKey(key string) SubjectConditionSet {
	scs, ok := fixtureData.SubjectConditionSet.Data[key]
	if !ok || scs.ID == "" {
		slog.Error("could not find subject-condition-set", slog.String("id", key))
		panic("could not find subject-condition-set fixture: " + key)
	}
	return scs
}

func (f *Fixtures) GetResourceMappingKey(key string) FixtureDataResourceMapping {
	rm, ok := fixtureData.ResourceMappings.Data[key]
	if !ok || rm.ID == "" {
		slog.Error("could not find resource-mappings", slog.String("id", key))
		panic("could not find resource-mapping fixture: " + key)
	}
	return rm
}

func (f *Fixtures) GetKasRegistryKey(key string) FixtureDataKasRegistry {
	kasr, ok := fixtureData.KasRegistries.Data[key]
	if !ok || kasr.ID == "" {
		slog.Error("could not find kas-registry", slog.String("id", key))
		panic("could not find kas-registry fixture: " + key)
	}
	return kasr
}

func (f *Fixtures) Provision() {
	slog.Info("📦 running migrations in schema", slog.String("schema", f.db.Schema))
	_, err := f.db.Client.RunMigrations(context.Background(), policy.Migrations)
	if err != nil {
		panic(err)
	}

	slog.Info("📦 provisioning namespace data")
	n := f.provisionNamespace()
	slog.Info("📦 provisioning attribute data")
	a := f.provisionAttribute()
	slog.Info("📦 provisioning attribute value data")
	aV := f.provisionAttributeValues()
	slog.Info("📦 provisioning value member data")
	vM := f.provisionValueMembers()
	slog.Info("📦 provisioning subject condition set data")
	sc := f.provisionSubjectConditionSet()
	slog.Info("📦 provisioning subject mapping data")
	sM := f.provisionSubjectMappings()
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
		slog.Int64("attribute_value_members", vM),
		slog.Int64("subject_mappings", sM),
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
				f.db.StringWrap(d.ID),
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
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.NamespaceID),
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
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.AttributeDefinitionID),
			f.db.StringWrap(d.Value),
			f.db.UUIDArrayWrap(d.Members),
			f.db.BoolWrap(d.Active),
		})
	}
	return f.provision(fixtureData.AttributeValues.Metadata.TableName, fixtureData.AttributeValues.Metadata.Columns, values)
}

func (f *Fixtures) provisionValueMembers() int64 {
	values := make([][]string, 0, len(fixtureData.ValueMembers.Data))
	for _, d := range fixtureData.ValueMembers.Data {
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.ValueID),
			f.db.StringWrap(d.MemberID),
		})
	}
	return f.provision(fixtureData.ValueMembers.Metadata.TableName, fixtureData.ValueMembers.Metadata.Columns, values)
}

func (f *Fixtures) provisionSubjectConditionSet() int64 {
	values := make([][]string, 0, len(fixtureData.SubjectConditionSet.Data))
	for _, d := range fixtureData.SubjectConditionSet.Data {
		var conditionJSON []byte
		conditionJSON, err := json.Marshal(d.Condition.SubjectSets)
		if err != nil {
			slog.Error("⛔️ 📦 issue with subject condition set JSON - check policy_fixtures.yaml for issues")
			panic("issue with subject condition set JSON")
		}

		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(string(conditionJSON)),
		})
	}
	return f.provision(fixtureData.SubjectConditionSet.Metadata.TableName, fixtureData.SubjectConditionSet.Metadata.Columns, values)
}

func (f *Fixtures) provisionSubjectMappings() int64 {
	values := make([][]string, 0, len(fixtureData.SubjectMappings.Data))
	for _, d := range fixtureData.SubjectMappings.Data {
		var actionsJSON []byte
		actionsJSON, err := json.Marshal(d.Actions)
		if err != nil {
			slog.Error("⛔️ 📦 issue with subject mapping actions JSON - check policy_fixtures.yaml for issues")
			panic("issue with subject mapping actions JSON")
		}

		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.UUIDWrap(d.AttributeValueID),
			f.db.UUIDWrap(d.SubjectConditionSetID),
			f.db.StringWrap(string(actionsJSON)),
		})
	}
	return f.provision(fixtureData.SubjectMappings.Metadata.TableName, fixtureData.SubjectMappings.Metadata.Columns, values)
}

func (f *Fixtures) provisionResourceMappings() int64 {
	values := make([][]string, 0, len(fixtureData.ResourceMappings.Data))
	for _, d := range fixtureData.ResourceMappings.Data {
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.AttributeValueID),
			f.db.StringArrayWrap(d.Terms),
		})
	}
	return f.provision(fixtureData.ResourceMappings.Metadata.TableName, fixtureData.ResourceMappings.Metadata.Columns, values)
}

func (f *Fixtures) provisionKasRegistry() int64 {
	values := make([][]string, 0, len(fixtureData.KasRegistries.Data))
	for _, d := range fixtureData.KasRegistries.Data {
		v := []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.URI),
		}

		pubKeyJSON, err := json.Marshal(d.PubKey)
		if err != nil {
			slog.Error("⛔️ 📦 issue with KAS registry public key JSON - check policy_fixtures.yaml for issues")
			panic("issue with KAS registry public key JSON")
		}
		v = append(v, f.db.StringWrap(string(pubKeyJSON)))
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
		slog.Error("⛔️ 📦 issue with insert into table - check policy_fixtures.yaml for issues", slog.String("table", t), slog.Any("err", err))
		panic("issue with insert into table")
	}
	if rows == 0 {
		slog.Error("⛔️ 📦 no rows provisioned - check policy_fixtures.yaml for issues", slog.String("table", t), slog.Int("expected", len(v)))
		panic("no rows provisioned")
	}
	if rows != int64(len(v)) {
		slog.Error("⛔️ 📦 incorrect number of rows provisioned - check policy_fixtures.yaml for issues", slog.String("table", t), slog.Int("expected", len(v)), slog.Int64("actual", rows))
		panic("incorrect number of rows provisioned")
	}
	return rows
}
