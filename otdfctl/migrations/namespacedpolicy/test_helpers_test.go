package namespacedpolicy

import "github.com/opentdf/platform/protocol/go/policy"

func testNamespace(fqn string) *policy.Namespace {
	return &policy.Namespace{
		Fqn: fqn,
	}
}

func testAttributeValue(fqn string, namespace *policy.Namespace) *policy.Value {
	return &policy.Value{
		Fqn: fqn,
		Attribute: &policy.Attribute{
			Namespace: namespace,
		},
	}
}

func testActionAttributeValue(actionID, actionName string, attributeValue *policy.Value) *policy.RegisteredResourceValue_ActionAttributeValue {
	return &policy.RegisteredResourceValue_ActionAttributeValue{
		Action: &policy.Action{
			Id:   actionID,
			Name: actionName,
		},
		AttributeValue: attributeValue,
	}
}

func testRegisteredResourceValue(value string, aavs ...*policy.RegisteredResourceValue_ActionAttributeValue) *policy.RegisteredResourceValue {
	return &policy.RegisteredResourceValue{
		Value:                 value,
		ActionAttributeValues: aavs,
	}
}

func testRegisteredResource(id, name string, values ...*policy.RegisteredResourceValue) *policy.RegisteredResource {
	return &policy.RegisteredResource{
		Id:     id,
		Name:   name,
		Values: values,
	}
}
