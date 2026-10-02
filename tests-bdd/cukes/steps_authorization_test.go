package cukes

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConvertInterfaceToAny_PlainClaimsJSON(t *testing.T) {
	anyMsg, err := ConvertInterfaceToAny([]byte(`{"userName":"diana","department":"engineering"}`))
	require.NoError(t, err)

	var claimsStruct structpb.Struct
	require.NoError(t, anyMsg.UnmarshalTo(&claimsStruct))

	claims := claimsStruct.AsMap()
	require.Equal(t, "diana", claims["userName"])
	require.Equal(t, "engineering", claims["department"])
}
