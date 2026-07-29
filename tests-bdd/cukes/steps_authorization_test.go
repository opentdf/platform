package cukes

import (
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestConvertInterfaceToAny_PlainClaimsJSON(t *testing.T) {
	anyMsg, err := ConvertInterfaceToAny([]byte(`{"userName":"diana","department":"engineering"}`))
	if err != nil {
		t.Fatalf("ConvertInterfaceToAny() error = %v", err)
	}

	var claimsStruct structpb.Struct
	if err := anyMsg.UnmarshalTo(&claimsStruct); err != nil {
		t.Fatalf("UnmarshalTo(structpb.Struct) error = %v", err)
	}

	claims := claimsStruct.AsMap()
	if got := claims["userName"]; got != "diana" {
		t.Fatalf("expected userName diana, got %v", got)
	}
	if got := claims["department"]; got != "engineering" {
		t.Fatalf("expected department engineering, got %v", got)
	}
}
