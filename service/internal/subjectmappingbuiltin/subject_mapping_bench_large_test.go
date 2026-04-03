package subjectmappingbuiltin_test

import (
	"fmt"
	"testing"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/subjectmappingbuiltin"
	"google.golang.org/protobuf/types/known/structpb"
)

// Helper to generate attribute mappings with configurable size
func generateAttributeMappings(attrCount, smPerAttr, condsPerSM int) map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue {
	mappings := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, attrCount)

	for i := 0; i < attrCount; i++ {
		valueFQN := fmt.Sprintf("https://demo.org/attr/attr%d/value/val%d", i, i)

		subjectMappings := make([]*policy.SubjectMapping, smPerAttr)
		for j := 0; j < smPerAttr; j++ {
			conditions := make([]*policy.Condition, condsPerSM)
			for k := 0; k < condsPerSM; k++ {
				conditions[k] = &policy.Condition{
					SubjectExternalSelectorValue: ".attributes.groups[]",
					Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
					SubjectExternalValues:        []string{fmt.Sprintf("group%d", k)},
				}
			}

			subjectMappings[j] = &policy.SubjectMapping{
				SubjectConditionSet: &policy.SubjectConditionSet{
					SubjectSets: []*policy.SubjectSet{
						{
							ConditionGroups: []*policy.ConditionGroup{
								{
									BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
									Conditions:      conditions,
								},
							},
						},
					},
				},
				Actions: []*policy.Action{
					{Name: "read"},
					{Name: "write"},
				},
			}
		}

		mappings[valueFQN] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value: &policy.Value{
				SubjectMappings: subjectMappings,
			},
		}
	}

	return mappings
}

// Helper to generate entity with groups
func generateEntity(groupCount int) map[string]interface{} {
	groups := make([]interface{}, groupCount)
	for i := 0; i < groupCount; i++ {
		groups[i] = fmt.Sprintf("group%d", i)
	}
	return map[string]interface{}{
		"attributes": map[string]interface{}{
			"groups":     groups,
			"department": "Engineering",
			"level":      "Senior",
		},
	}
}

// Benchmark EvaluateCondition with larger value sets
func BenchmarkEvaluateCondition_IN_Large(b *testing.B) {
	// 50 possible values, entity has 20 groups
	entity := generateEntity(20)
	flatEntity, _ := flattening.Flatten(entity)

	possibleValues := make([]string, 50)
	for i := 0; i < 50; i++ {
		possibleValues[i] = fmt.Sprintf("possibleGroup%d", i)
	}

	condition := &policy.Condition{
		SubjectExternalSelectorValue: ".attributes.groups[]",
		Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		SubjectExternalValues:        possibleValues,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = subjectmappingbuiltin.EvaluateCondition(condition, flatEntity)
	}
}

// Benchmark EvaluateCondition with matching values (hit case)
func BenchmarkEvaluateCondition_IN_Hit(b *testing.B) {
	entity := generateEntity(20)
	flatEntity, _ := flattening.Flatten(entity)

	// Include "group5" which exists in the entity
	possibleValues := []string{"unknownGroup1", "unknownGroup2", "unknownGroup3", "unknownGroup4", "group5"}

	condition := &policy.Condition{
		SubjectExternalSelectorValue: ".attributes.groups[]",
		Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		SubjectExternalValues:        possibleValues,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = subjectmappingbuiltin.EvaluateCondition(condition, flatEntity)
	}
}

// Benchmark EvaluateSubjectMappings with many attribute mappings
func BenchmarkEvaluateSubjectMappings_LargeAttrCount(b *testing.B) {
	mappings := generateAttributeMappings(50, 2, 3) // 50 attrs, 2 SMs each, 3 conditions each
	entity := generateEntity(10)
	additionalProps, _ := structpb.NewStruct(entity)
	entityRep := &entityresolution.EntityRepresentation{
		AdditionalProps: []*structpb.Struct{additionalProps},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = subjectmappingbuiltin.EvaluateSubjectMappings(mappings, entityRep)
	}
}

// Benchmark EvaluateSubjectMappings with repeated subject sets (cache benefit)
func BenchmarkEvaluateSubjectMappings_RepeatedSubjectSets(b *testing.B) {
	// Create shared subject sets that will be reused
	sharedConditionGroup := &policy.ConditionGroup{
		BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
		Conditions: []*policy.Condition{
			{
				SubjectExternalSelectorValue: ".attributes.groups[]",
				Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
				SubjectExternalValues:        []string{"group0", "group1"},
			},
		},
	}
	sharedSubjectSet := &policy.SubjectSet{
		ConditionGroups: []*policy.ConditionGroup{sharedConditionGroup},
	}

	// Create 20 attribute mappings that all reference the same subject set
	mappings := make(map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, 20)
	for i := 0; i < 20; i++ {
		valueFQN := fmt.Sprintf("https://demo.org/attr/attr%d/value/val%d", i, i)
		mappings[valueFQN] = &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
			Value: &policy.Value{
				SubjectMappings: []*policy.SubjectMapping{
					{
						SubjectConditionSet: &policy.SubjectConditionSet{
							SubjectSets: []*policy.SubjectSet{sharedSubjectSet, sharedSubjectSet}, // Duplicate references
						},
						Actions: []*policy.Action{{Name: "read"}},
					},
				},
			},
		}
	}

	entity := generateEntity(10)
	additionalProps, _ := structpb.NewStruct(entity)
	entityRep := &entityresolution.EntityRepresentation{
		AdditionalProps: []*structpb.Struct{additionalProps},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = subjectmappingbuiltin.EvaluateSubjectMappings(mappings, entityRep)
	}
}

// Benchmark EvaluateSubjectMappingsWithActions
func BenchmarkEvaluateSubjectMappingsWithActions_LargeAttrCount(b *testing.B) {
	mappings := generateAttributeMappings(50, 2, 3)
	entity := generateEntity(10)
	additionalProps, _ := structpb.NewStruct(entity)
	entityRep := &entityresolutionV2.EntityRepresentation{
		OriginalId:      "test-entity",
		AdditionalProps: []*structpb.Struct{additionalProps},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = subjectmappingbuiltin.EvaluateSubjectMappingsWithActions(mappings, entityRep)
	}
}

// Benchmark multiple entities
func BenchmarkEvaluateSubjectMappingMultipleEntitiesWithActions(b *testing.B) {
	mappings := generateAttributeMappings(20, 2, 2)

	entities := make([]*entityresolutionV2.EntityRepresentation, 10)
	for i := 0; i < 10; i++ {
		entity := generateEntity(5 + i) // Different group counts
		additionalProps, _ := structpb.NewStruct(entity)
		entities[i] = &entityresolutionV2.EntityRepresentation{
			OriginalId:      fmt.Sprintf("entity-%d", i),
			AdditionalProps: []*structpb.Struct{additionalProps},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = subjectmappingbuiltin.EvaluateSubjectMappingMultipleEntitiesWithActions(mappings, entities)
	}
}
