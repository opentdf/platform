package idpplugin

import (

	// "github.com/okta/okta-sdk-golang/v2/okta"
	"bytes"
	"encoding/json"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"github.com/opentdf/platform/protocol/go/authorization"
	"google.golang.org/protobuf/encoding/protojson"
)

func KeycloakBuiltins() {
	rego.RegisterBuiltin2(&rego.Function{
		Name:             "keycloak.resolve.entities",
		Decl:             types.NewFunction(types.Args(types.A, types.A), types.A),
		Memoize:          true,
		Nondeterministic: true,
	}, func(ctx rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
		var requestMap map[string]interface{}
		var configMap map[string]interface{}

		if err := ast.As(a.Value, &requestMap); err != nil {
			return nil, err
		} else if err := ast.As(b.Value, &configMap); err != nil {
			return nil, err
		}

		var request = authorization.IdpPluginRequest{}
		var config = authorization.IdpConfig{}

		reqJson, err := json.Marshal(requestMap)
		if err != nil {
			return nil, err
		}
		confJson, err := json.Marshal(configMap)
		if err != nil {
			return nil, err
		}

		err = protojson.Unmarshal(reqJson, &request)
		if err != nil {
			return nil, err
		}
		err = protojson.Unmarshal(confJson, &config)
		if err != nil {
			return nil, err
		}

		var resp, errresp = EntityResolution(ctx.Context, &request, &config)
		if errresp != nil {
			return nil, errresp
		}
		respJson, err := protojson.Marshal(resp)
		if err != nil {
			return nil, err
		}
		reader := bytes.NewReader(respJson)
		v, err := ast.ValueFromReader(reader)
		if err != nil {
			return nil, err
		}
		return ast.NewTerm(v), nil
	},
	)
}
