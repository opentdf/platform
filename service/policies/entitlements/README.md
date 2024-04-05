# OpenTDF Platform OPA rego policies

## Testing

Use `../policies_test.go` for testing rego functions

A failed assertation will appear below.  The second Error Trace is the test case with the failure.

```text
=== RUN   TestRegoConditionSimple
compile.go:3116: conditions-test.rego:9: comprehension index: no index vars
compile.go:3086: conditions-test.rego:11: comprehension index: unsafe vars: [__local0__ __local33__]
compile.go:3086: conditions-test.rego:13: comprehension index: unsafe vars: [__local1__ __local34__]
compile.go:3116: entitlements.rego:5: comprehension index: no index vars
    policies_test.go:221: 
        	Error Trace:	/Users/abc/Projects/opentdf/platform/policies/policies_test.go:221
        	            				/Users/abc/Projects/opentdf/platform/policies/policies_test.go:198
        	Error:      	Not equal: 
        	            	expected: false
        	            	actual  : true
        	Test:       	TestRegoConditionSimple
--- FAIL: TestRegoConditionSimple (0.00s)
```

An invalid input JSON will appear as

```text
=== RUN   TestRegoConditionSimple
    policies_test.go:198: 
        	Error Trace:	/Users/abc/Projects/opentdf/platform/policies/policies_test.go:198
        	Error:      	Received unexpected error:
        	            	invalid character 'a' looking for beginning of object key string
        	Test:       	TestRegoConditionSimple
```

An invalid .rego will appear as

```text
=== RUN   TestRegoConditionSimple
    policies_test.go:220: 
        	Error Trace:	/Users/pflynn/Projects/opentdf/platform/policies/policies_test.go:220
        	            				/Users/pflynn/Projects/opentdf/platform/policies/policies_test.go:202
        	Error:      	Received unexpected error:
        	            	3 errors occurred
        	            	entitlements.rego:6: rego_parse_error: var cannot be used for rule name
```

## entitlements.rego

This is the default rego policy that will parse a JWT,
traverse the subject mappings, and return the entitlements.

## entitlements-keycloak.rego

This is a rego policy for calling Keycloak to get an entity representation,
traverse the subject mappings, and return the entitlements.
