package idpplugin

import (
	"bytes"
	"encoding/json"

	"github.com/arkavo-org/opentdf-platform/protocol/go/authorization"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
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

		reqJSON, err := json.Marshal(requestMap)
		if err != nil {
			return nil, err
		}
		confJSON, err := json.Marshal(configMap)
		if err != nil {
			return nil, err
		}

		err = protojson.Unmarshal(reqJSON, &request)
		if err != nil {
			return nil, err
		}
		err = protojson.Unmarshal(confJSON, &config)
		if err != nil {
			return nil, err
		}

		var resp, errresp = EntityResolution(ctx.Context, &request, &config)
		if errresp != nil {
			return nil, errresp
		}
		respJSON, err := protojson.Marshal(resp)
		if err != nil {
			return nil, err
		}
		reader := bytes.NewReader(respJSON)
		v, err := ast.ValueFromReader(reader)
		if err != nil {
			return nil, err
		}
		return ast.NewTerm(v), nil
	},
	)
}
