package access

import (
	"testing"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/stretchr/testify/require"
)

func TestEntityMetadataFromIdentifierToken(t *testing.T) {
	identifier := &authzV2.EntityIdentifier{
		Identifier: &authzV2.EntityIdentifier_Token{
			Token: &entity.Token{
				Metadata: map[string]string{
					"sub": "user-1",
				},
			},
		},
	}

	metadata := entityMetadataFromIdentifier(identifier)
	require.Equal(t, map[string]string{
		"sub": "user-1",
	}, metadata)
}

func TestEntityMetadataFromIdentifierEntityChain(t *testing.T) {
	identifier := &authzV2.EntityIdentifier{
		Identifier: &authzV2.EntityIdentifier_EntityChain{
			EntityChain: &entity.EntityChain{
				Entities: []*entity.Entity{
					{
						EphemeralId: "entity-a",
						Metadata: map[string]string{
							"role": "admin",
						},
					},
					{
						Metadata: map[string]string{
							"dept": "finance",
						},
					},
					{
						EphemeralId: "entity-c",
					},
				},
			},
		},
	}

	metadata := entityMetadataFromIdentifier(identifier)
	require.Equal(t, map[string]map[string]string{
		"entity-a": {
			"role": "admin",
		},
		"entity-1": {
			"dept": "finance",
		},
	}, metadata)
}

func TestResourceMetadataFromResources(t *testing.T) {
	resources := []*authzV2.Resource{
		{
			EphemeralId: "resource-a",
			Metadata: map[string]string{
				"file_name": "a.txt",
			},
		},
		{
			Metadata: map[string]string{
				"file_name": "b.txt",
			},
		},
		{
			EphemeralId: "resource-c",
		},
	}

	metadata := resourceMetadataFromResources(resources)
	require.Equal(t, map[string]map[string]string{
		"resource-a": {
			"file_name": "a.txt",
		},
		"resource-1": {
			"file_name": "b.txt",
		},
	}, metadata)
}
