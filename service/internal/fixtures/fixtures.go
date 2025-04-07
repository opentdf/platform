package fixtures

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"

	policypb "github.com/opentdf/platform/protocol/go/policy"
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
	ID                    string `yaml:"id"`
	AttributeDefinitionID string `yaml:"attribute_definition_id"`
	Value                 string `yaml:"value"`
	Active                bool   `yaml:"active"`
}

type FixtureDataAttributeValueKeyAccessServer struct {
	ValueID           string `yaml:"value_id"`
	KeyAccessServerID string `yaml:"key_access_server_id"`
}

type FixtureDataSubjectMapping struct {
	ID                    string `yaml:"id"`
	AttributeValueID      string `yaml:"attribute_value_id"`
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

type FixtureDataAction struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	IsStandard bool   `yaml:"is_standard"`
}

// Relation table intermediating subject mappings and actions
type FixtureDataSubjectMappingsActionRelation struct {
	SubjectMappingID string `yaml:"subject_mapping_id"`
	ActionName       string `yaml:"action_name"`
}

type FixtureDataResourceMappingGroup struct {
	ID          string `yaml:"id"`
	NamespaceID string `yaml:"namespace_id"`
	Name        string `yaml:"name"`
}

type FixtureDataResourceMapping struct {
	ID               string   `yaml:"id"`
	AttributeValueID string   `yaml:"attribute_value_id"`
	Terms            []string `yaml:"terms"`
	GroupID          string   `yaml:"group_id"`
}

type FixtureDataKasRegistry struct {
	ID     string `yaml:"id"`
	URI    string `yaml:"uri"`
	PubKey struct {
		Remote string                    `yaml:"remote" json:"remote,omitempty"`
		Cached *policypb.KasPublicKeySet `yaml:"cached" json:"cached,omitempty"`
	} `yaml:"public_key" json:"public_key"`
	Name string `yaml:"name"`
}

type FixtureDataValueKeyMap struct {
	ValueID string `yaml:"value_id"`
	KeyID   string `yaml:"key_id"`
}

type FixtureDataDefinitionKeyMap struct {
	DefinitionID string `yaml:"definition_id"`
	KeyID        string `yaml:"key_id"`
}

type FixtureDataNamespaceKeyMap struct {
	NamespaceID string `yaml:"namespace_id"`
	KeyID       string `yaml:"key_id"`
}

type FixtureDataRegisteredResource struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

type FixtureDataRegisteredResourceValue struct {
	ID                   string `yaml:"id"`
	RegisteredResourceID string `yaml:"registered_resource_id"`
	Value                string `yaml:"value"`
}

type FixtureDataKasRegistryKey struct {
	ID                string `yaml:"id"`
	KeyAccessServerID string `yaml:"key_access_server_id"`
	KeyAlgorithm      string `yaml:"key_algorithm"`
	KeyID             string `yaml:"key_id"`
	KeyMode           string `yaml:"key_mode"`
	KeyStatus         string `yaml:"key_status"`
	PrivateKeyCtx     string `yaml:"private_key_ctx"`
	PublicKeyCtx      string `yaml:"public_key_ctx"`
	ProviderConfigID  string `yaml:"provider_config_id"`
}

type FixtureDataProviderConfig struct {
	ID             string `yaml:"id"`
	ProviderName   string `yaml:"provider_name"`
	ProviderConfig string `yaml:"config"`
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
	CustomActions struct {
		Metadata FixtureMetadata              `yaml:"metadata"`
		Data     map[string]FixtureDataAction `yaml:"data"`
	} `yaml:"custom_actions"`
	SubjectMappingActions struct {
		Metadata FixtureMetadata                                     `yaml:"metadata"`
		Data     map[string]FixtureDataSubjectMappingsActionRelation `yaml:"data"`
	} `yaml:"subject_mapping_actions_relation"`
	SubjectConditionSet struct {
		Metadata FixtureMetadata                `yaml:"metadata"`
		Data     map[string]SubjectConditionSet `yaml:"data"`
	} `yaml:"subject_condition_set"`
	ResourceMappingGroups struct {
		Metadata FixtureMetadata                            `yaml:"metadata"`
		Data     map[string]FixtureDataResourceMappingGroup `yaml:"data"`
	} `yaml:"resource_mapping_groups"`
	ResourceMappings struct {
		Metadata FixtureMetadata                       `yaml:"metadata"`
		Data     map[string]FixtureDataResourceMapping `yaml:"data"`
	} `yaml:"resource_mappings"`
	KasRegistries struct {
		Metadata FixtureMetadata                   `yaml:"metadata"`
		Data     map[string]FixtureDataKasRegistry `yaml:"data"`
	} `yaml:"kas_registry"`
	ValueKeyMap struct {
		Metadata FixtureMetadata          `yaml:"metadata"`
		Data     []FixtureDataValueKeyMap `yaml:"data"`
	} `yaml:"value_key_map"`
	DefinitionKeyMap struct {
		Metadata FixtureMetadata               `yaml:"metadata"`
		Data     []FixtureDataDefinitionKeyMap `yaml:"data"`
	} `yaml:"definition_key_map"`
	NamespaceKeyMap struct {
		Metadata FixtureMetadata              `yaml:"metadata"`
		Data     []FixtureDataNamespaceKeyMap `yaml:"data"`
	} `yaml:"namespace_key_map"`
	RegisteredResources struct {
		Metadata FixtureMetadata                          `yaml:"metadata"`
		Data     map[string]FixtureDataRegisteredResource `yaml:"data"`
	} `yaml:"registered_resources"`
	RegisteredResourceValues struct {
		Metadata FixtureMetadata                               `yaml:"metadata"`
		Data     map[string]FixtureDataRegisteredResourceValue `yaml:"data"`
	} `yaml:"registered_resource_values"`
	KasRegistryKeys struct {
		Metadata FixtureMetadata                      `yaml:"metadata"`
		Data     map[string]FixtureDataKasRegistryKey `yaml:"data"`
	} `yaml:"kas_registry_keys"`
	ProviderConfigs struct {
		Metadata FixtureMetadata                      `yaml:"metadata"`
		Data     map[string]FixtureDataProviderConfig `yaml:"data"`
	} `yaml:"provider_configs"`
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
	db           DBInterface
	MigratedData struct {
		// name -> id
		StandardActions map[string]string
	}
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

// Migration adds standard actions [create, read, update, delete] to the database
func (f *Fixtures) loadMigratedStandardActions() {
	actions := make(map[string]string)
	rows, err := f.db.Client.Query(context.Background(), "SELECT id, name FROM actions WHERE is_standard = TRUE", nil)
	if err != nil {
		slog.Error("could not get standard actions", slog.String("error", err.Error()))
		panic("could not get standard actions")
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			slog.Error("could not scan standard actions", slog.String("error", err.Error()))
			panic("could not scan standard actions")
		}
		actions[name] = id
	}
	if err := rows.Err(); err != nil {
		slog.Error("could not get standard actions", slog.String("error", err.Error()))
		panic("could not get standard actions")
	}
	if len(actions) == 0 {
		slog.Error("could not find standard actions")
		panic("could not find standard actions")
	}
	slog.Info("found standard actions", slog.Any("actions", actions))
	// add standard actions to fixtureData
	f.MigratedData.StandardActions = actions
}

func (f *Fixtures) GetStandardAction(name string) *policypb.Action {
	id, ok := f.MigratedData.StandardActions[name]
	if !ok {
		slog.Error("could not find standard action", slog.String("name", name))
		panic("could not find standard action: " + name)
	}
	return &policypb.Action{
		Id:   id,
		Name: name,
	}
}

func (f *Fixtures) GetCustomActionKey(key string) FixtureDataAction {
	a, ok := fixtureData.CustomActions.Data[key]
	if !ok || a.ID == "" {
		slog.Error("could not find actions", slog.String("id", key))
		panic("could not find action fixture: " + key)
	}
	return a
}

func (f *Fixtures) GetResourceMappingGroupKey(key string) FixtureDataResourceMappingGroup {
	rmGroup, ok := fixtureData.ResourceMappingGroups.Data[key]
	if !ok || rmGroup.ID == "" {
		slog.Error("could not find resource-mapping-groups", slog.String("id", key))
		panic("could not find resource-mapping-group fixture: " + key)
	}
	return rmGroup
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

func (f *Fixtures) GetKasRegistryServerKeys(key string) FixtureDataKasRegistryKey {
	kasr, ok := fixtureData.KasRegistryKeys.Data[key]
	if !ok || kasr.ID == "" {
		slog.Error("could not find kas-registry", slog.String("id", key))
		panic("could not find kas-registry fixture: " + key)
	}
	return kasr
}

func (f *Fixtures) GetValueMap(key string) []FixtureDataValueKeyMap {
	var vkms []FixtureDataValueKeyMap
	for _, vkm := range fixtureData.ValueKeyMap.Data {
		if vkm.KeyID == key {
			vkms = append(vkms, vkm)
		}
	}
	return vkms
}

func (f *Fixtures) GetDefinitionKeyMap(key string) []FixtureDataDefinitionKeyMap {
	var dkms []FixtureDataDefinitionKeyMap
	for _, dkm := range fixtureData.DefinitionKeyMap.Data {
		if dkm.KeyID == key {
			dkms = append(dkms, dkm)
		}
	}
	return dkms
}

func (f *Fixtures) GetNamespaceKeyMap(key string) []FixtureDataNamespaceKeyMap {
	var nkms []FixtureDataNamespaceKeyMap
	for _, nkm := range fixtureData.NamespaceKeyMap.Data {
		if nkm.KeyID == key {
			nkms = append(nkms, nkm)
		}
	}
	return nkms
}

func (f *Fixtures) GetRegisteredResourceKey(key string) FixtureDataRegisteredResource {
	rr, ok := fixtureData.RegisteredResources.Data[key]
	if !ok || rr.ID == "" {
		slog.Error("could not find registered resource", slog.String("id", key))
		panic("could not find registered resource fixture: " + key)
	}
	return rr
}

func (f *Fixtures) GetRegisteredResourceValueKey(key string) FixtureDataRegisteredResourceValue {
	rv, ok := fixtureData.RegisteredResourceValues.Data[key]
	if !ok || rv.ID == "" {
		slog.Error("could not find registered resource value", slog.String("id", key))
		panic("could not find registered resource value fixture: " + key)
	}
	return rv
}

func (f *Fixtures) Provision() {
	slog.Info("📦 running migrations in schema", slog.String("schema", f.db.Schema))
	_, err := f.db.Client.RunMigrations(context.Background(), policy.Migrations)
	if err != nil {
		panic(err)
	}

	slog.Info("📦 retrieving migration-inserted standard actions")
	f.loadMigratedStandardActions()
	slog.Info("📦 provisioning namespace data")
	n := f.provisionNamespace()
	slog.Info("📦 provisioning attribute data")
	a := f.provisionAttribute()
	slog.Info("📦 provisioning attribute value data")
	aV := f.provisionAttributeValues()
	slog.Info("📦 provisioning subject condition set data")
	sc := f.provisionSubjectConditionSet()
	slog.Info("📦 provisioning subject mapping data")
	sM := f.provisionSubjectMappings()
	slog.Info("📦 provisioning resource mapping group data")
	rmg := f.provisionResourceMappingGroups()
	slog.Info("📦 provisioning custom actions data")
	actions := f.provisionCustomActions()
	slog.Info("📦 provisioning subject mapping actions relationships data")
	relatedSmActions := f.provisionSubjectMappingActionsRelations()
	slog.Info("📦 provisioning resource mapping data")
	rm := f.provisionResourceMappings()
	slog.Info("📦 provisioning kas registry data")
	kas := f.provisionKasRegistry()
	slog.Info("📦 provisioning attribute key access server data")
	akas := f.provisionAttributeKeyAccessServer()
	slog.Info("📦 provisioning attribute value key access server data")
	avkas := f.provisionAttributeValueKeyAccessServer()
	//slog.Info("📦 provisioning public keys")
	//pk := f.provisionPublicKeys()
	//slog.Info("📦 provisioning value key map")
	//vkm := f.provisionValueKeyMap()
	//slog.Info("📦 provisioning definition key map")
	//dkm := f.provisionDefinitionKeyMap()
	//slog.Info("📦 provisioning namespace key map")
	//nkm := f.provisionNamespaceKeyMap()
	slog.Info("📦 provisioning registered resources")
	rr := f.provisionRegisteredResources()
	slog.Info("📦 provisioning registered resource values")
	rrv := f.provisionRegisteredResourceValues()
	slog.Info("📦 provisioning provider configs")
	pcs := f.provisionProviderConfigs()
	slog.Info("📦 provisioning keys for kas registry")
	kasKeys := f.provisionKasRegistryKeys()

	slog.Info("📦 provisioned fixtures data",
		slog.Int64("namespaces", n),
		slog.Int64("attributes", a),
		slog.Int64("attribute_values", aV),
		slog.Int64("subject_mappings", sM),
		slog.Int64("subject_condition_set", sc),
		slog.Int64("actions", actions),
		slog.Int64("subject_mapping_actions", relatedSmActions),
		slog.Int64("resource_mapping_groups", rmg),
		slog.Int64("resource_mappings", rm),
		slog.Int64("kas_registry", kas),
		slog.Int64("attribute_key_access_server", akas),
		slog.Int64("attribute_value_key_access_server", avkas),
		slog.Int64("public_keys", pk),
		//slog.Int64("value_key_map", vkm),
		//slog.Int64("definition_key_map", dkm),
		//slog.Int64("namespace_key_map", nkm),
		slog.Int64("registered_resources", rr),
		slog.Int64("registered_resource_values", rrv),
		slog.Int64("provider_configs", pcs),
		slog.Int64("kas_registry_keys", kasKeys),
	)
	slog.Info("📚 indexing FQNs for fixtures")
	f.db.PolicyClient.AttrFqnReindex(context.Background())
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
			f.db.BoolWrap(d.Active),
		})
	}
	return f.provision(fixtureData.AttributeValues.Metadata.TableName, fixtureData.AttributeValues.Metadata.Columns, values)
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
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.UUIDWrap(d.AttributeValueID),
			f.db.UUIDWrap(d.SubjectConditionSetID),
		})
	}
	return f.provision(fixtureData.SubjectMappings.Metadata.TableName, fixtureData.SubjectMappings.Metadata.Columns, values)
}

func (f *Fixtures) provisionCustomActions() int64 {
	values := make([][]string, 0, len(fixtureData.CustomActions.Data))
	for _, d := range fixtureData.CustomActions.Data {
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.Name),
			f.db.BoolWrap(d.IsStandard),
		})
	}
	return f.provision(fixtureData.CustomActions.Metadata.TableName, fixtureData.CustomActions.Metadata.Columns, values)
}

func (f *Fixtures) provisionSubjectMappingActionsRelations() int64 {
	values := make([][]string, 0, len(fixtureData.SubjectMappingActions.Data))
	for _, d := range fixtureData.SubjectMappingActions.Data {
		var actionID string
		if id, ok := f.MigratedData.StandardActions[d.ActionName]; ok {
			actionID = id
		} else {
			actionID = f.GetCustomActionKey(d.ActionName).ID
		}
		values = append(values,
			[]string{
				f.db.StringWrap(d.SubjectMappingID),
				f.db.StringWrap(actionID),
			},
		)
	}
	return f.provision(fixtureData.SubjectMappingActions.Metadata.TableName, fixtureData.SubjectMappingActions.Metadata.Columns, values)
}

func (f *Fixtures) provisionResourceMappingGroups() int64 {
	values := make([][]string, 0, len(fixtureData.ResourceMappingGroups.Data))
	for _, d := range fixtureData.ResourceMappingGroups.Data {
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.NamespaceID),
			f.db.StringWrap(d.Name),
		})
	}
	return f.provision(fixtureData.ResourceMappingGroups.Metadata.TableName, fixtureData.ResourceMappingGroups.Metadata.Columns, values)
}

func (f *Fixtures) provisionResourceMappings() int64 {
	values := make([][]string, 0, len(fixtureData.ResourceMappings.Data))
	for _, d := range fixtureData.ResourceMappings.Data {
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.AttributeValueID),
			f.db.StringArrayWrap(d.Terms),
			f.db.StringWrap(d.GroupID),
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
			f.db.StringWrap(d.Name),
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

func (f *Fixtures) provisionProviderConfigs() int64 {
	values := make([][]string, 0, len(fixtureData.ProviderConfigs.Data))
	for _, d := range fixtureData.ProviderConfigs.Data {
		providerConfigJSON, err := base64.StdEncoding.DecodeString(d.ProviderConfig)
		if err != nil {
			slog.Error("⛔️ 📦 issue with provider config JSON - check policy_fixtures.yaml for issues")
			panic("issue with provider config JSON")
		}
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.ProviderName),
			f.db.StringWrap(string(providerConfigJSON)),
		})
	}

	return f.provision(fixtureData.ProviderConfigs.Metadata.TableName, fixtureData.ProviderConfigs.Metadata.Columns, values)
}

func (f *Fixtures) provisionKasRegistryKeys() int64 {
	values := make([][]string, 0, len(fixtureData.KasRegistryKeys.Data))
	for _, d := range fixtureData.KasRegistryKeys.Data {
		pubCtx, err := base64.StdEncoding.DecodeString(d.PublicKeyCtx)
		if err != nil {
			slog.Error("⛔️ 📦 issue with kas registry public key context - check policy_fixtures.yaml for issues")
			panic("issue with kas registry public key context")
		}
		privateCtx, err := base64.StdEncoding.DecodeString(d.PrivateKeyCtx)
		if err != nil {
			slog.Error("⛔️ 📦 issue with kas registry private key context - check policy_fixtures.yaml for issues")
			panic("issue with kas registry private key context")
		}
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.KeyAccessServerID),
			f.db.StringWrap(d.KeyAlgorithm),
			f.db.StringWrap(d.KeyID),
			f.db.StringWrap(d.KeyMode),
			f.db.StringWrap(d.KeyStatus),
			f.db.StringWrap(string(privateCtx)),
			f.db.StringWrap(string(pubCtx)),
			f.db.StringWrap(d.ProviderConfigID),
		})
	}

	return f.provision(fixtureData.KasRegistryKeys.Metadata.TableName, fixtureData.KasRegistryKeys.Metadata.Columns, values)
}

// func (f *Fixtures) provisionValueKeyMap() int64 {
// 	values := make([][]string, 0, len(fixtureData.ValueKeyMap.Data))
// 	for _, d := range fixtureData.ValueKeyMap.Data {
// 		values = append(values, []string{
// 			f.db.StringWrap(d.ValueID),
// 			f.db.StringWrap(d.KeyID),
// 		})
// 	}
// 	return f.provision(fixtureData.ValueKeyMap.Metadata.TableName, fixtureData.ValueKeyMap.Metadata.Columns, values)
// }

// func (f *Fixtures) provisionDefinitionKeyMap() int64 {
// 	values := make([][]string, 0, len(fixtureData.DefinitionKeyMap.Data))
// 	for _, d := range fixtureData.DefinitionKeyMap.Data {
// 		values = append(values, []string{
// 			f.db.StringWrap(d.DefinitionID),
// 			f.db.StringWrap(d.KeyID),
// 		})
// 	}
// 	return f.provision(fixtureData.DefinitionKeyMap.Metadata.TableName, fixtureData.DefinitionKeyMap.Metadata.Columns, values)
// }

// func (f *Fixtures) provisionNamespaceKeyMap() int64 {
// 	values := make([][]string, 0, len(fixtureData.NamespaceKeyMap.Data))
// 	for _, d := range fixtureData.NamespaceKeyMap.Data {
// 		values = append(values, []string{
// 			f.db.StringWrap(d.NamespaceID),
// 			f.db.StringWrap(d.KeyID),
// 		})
// 	}
// 	return f.provision(fixtureData.NamespaceKeyMap.Metadata.TableName, fixtureData.NamespaceKeyMap.Metadata.Columns, values)
// }

func (f *Fixtures) provisionRegisteredResources() int64 {
	values := make([][]string, 0, len(fixtureData.RegisteredResources.Data))
	for _, d := range fixtureData.RegisteredResources.Data {
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.Name),
		})
	}
	return f.provision(fixtureData.RegisteredResources.Metadata.TableName, fixtureData.RegisteredResources.Metadata.Columns, values)
}

func (f *Fixtures) provisionRegisteredResourceValues() int64 {
	values := make([][]string, 0, len(fixtureData.RegisteredResourceValues.Data))
	for _, d := range fixtureData.RegisteredResourceValues.Data {
		values = append(values, []string{
			f.db.StringWrap(d.ID),
			f.db.StringWrap(d.RegisteredResourceID),
			f.db.StringWrap(d.Value),
		})
	}
	return f.provision(fixtureData.RegisteredResourceValues.Metadata.TableName, fixtureData.RegisteredResourceValues.Metadata.Columns, values)
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
