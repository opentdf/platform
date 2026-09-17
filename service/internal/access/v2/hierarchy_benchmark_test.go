package access

import (
	"fmt"
	"log/slog"
	"testing"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
)

func BenchmarkDecisionHierarchy(b *testing.B) {
	for _, values := range []int{1000, 6000} {
		b.Run(fmt.Sprintf("values=%d/resources=1000", values), func(b *testing.B) {
			const def = "https://scale.example/attr/clearance"
			attr := &policy.Attribute{Fqn: def, Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, Values: make([]*policy.Value, values)}
			for i := range attr.GetValues() {
				attr.Values[i] = &policy.Value{Fqn: fmt.Sprintf("%s/value/%d", def, i)}
			}
			mappings := []*policy.SubjectMapping{{Id: "mapping", AttributeValue: attr.GetValues()[0], SubjectConditionSet: clientIDInConditionSet("abc"), Actions: []*policy.Action{{Name: "read"}}}}
			log := slog.New(slog.DiscardHandler)
			l := &logger.Logger{Logger: log, Audit: audit.CreateAuditLogger(*log)}
			pdp, err := NewPolicyDecisionPoint(b.Context(), l, []*policy.Attribute{attr}, mappings, nil, false, false)
			if err != nil {
				b.Fatal(err)
			}
			resources := make([]*authzV2.Resource, 1000)
			for i := range resources {
				resources[i] = attrValueResource(attr.GetValues()[values-1].GetFqn())[0]
				resources[i].EphemeralId = fmt.Sprintf("resource-%d", i)
			}
			representation := entityRepWithClientID("abc")
			action := &policy.Action{Name: "read"}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decision, _, err := pdp.GetDecision(b.Context(), representation, action, resources)
				if err != nil {
					b.Fatal(err)
				}
				if !decision.AllPermitted || len(decision.Results) != len(resources) {
					b.Fatal("unexpected decision")
				}
			}
		})
	}
}
