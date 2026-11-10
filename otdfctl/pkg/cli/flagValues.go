package cli

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/spf13/cobra"
)

type FlagsStringSliceOptions struct {
	Min int
	Max int
}

type flagHelper struct {
	cmd *cobra.Command
}

func newFlagHelper(cmd *cobra.Command) *flagHelper {
	return &flagHelper{cmd: cmd}
}

func (f flagHelper) GetRequiredString(flag string) string {
	v := f.cmd.Flag(flag).Value.String()
	if v == "" {
		ExitWithError("Flag '--"+flag+"' is required", nil)
	}
	return v
}

func (f flagHelper) GetRequiredID(idFlag string) string {
	v := f.GetRequiredString(idFlag)
	id, err := uuid.Parse(v)
	if err != nil {
		ExitWithError(fmt.Sprintf("Flag '--%s' received value '%s' must be a valid UUID", idFlag, v), nil)
	}
	return id.String()
}

func (f flagHelper) GetOptionalID(idFlag string) string {
	p := f.GetOptionalString(idFlag)
	if p == "" {
		return ""
	}
	id, err := uuid.Parse(p)
	if err != nil {
		ExitWithError(fmt.Sprintf("Optional flag '--%s' received value '%s' and must be a valid UUID if used", idFlag, p), nil)
	}
	return id.String()
}

func (f flagHelper) GetOptionalString(flag string) string {
	p := f.cmd.Flag(flag)
	if p == nil {
		return ""
	}
	return p.Value.String()
}

func (f flagHelper) GetStringSlice(flag string, v []string, opts FlagsStringSliceOptions) []string {
	if len(v) < opts.Min {
		ExitWithError(fmt.Sprintf("Flag '--%s' must have at least %d non-empty values", flag, opts.Min), nil)
	}
	if opts.Max > 0 && len(v) > opts.Max {
		ExitWithError(fmt.Sprintf("Flag '--%s' must have at most %d non-empty values", flag, opts.Max), nil)
	}
	return v
}

func (f flagHelper) GetRequiredInt32(flag string) int32 {
	v, e := f.cmd.Flags().GetInt32(flag)
	if e != nil {
		ExitWithError("Flag '--"+flag+"' is required", nil)
	}
	// if v == 0 {
	// 	fmt.Println(ErrorMessage("Flag "+flag+" must be greater than 0", nil))
	// 	os.Exit(1)
	// }
	return v
}

func (f flagHelper) GetOptionalInt32(flag string) int32 {
	v, _ := f.cmd.Flags().GetInt32(flag)
	return v
}

func (f flagHelper) GetOptionalBool(flag string) bool {
	v, _ := f.cmd.Flags().GetBool(flag)
	return v
}

func (f flagHelper) GetRequiredBool(flag string) bool {
	v, e := f.cmd.Flags().GetBool(flag)
	if e != nil {
		ExitWithError("Flag '--"+flag+"' is required", nil)
	}
	return v
}

// Transforms into enum value and defaults to active state
func GetState(cmd *cobra.Command) common.ActiveStateEnum {
	state := common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE
	stateFlag := strings.ToUpper(cmd.Flag("state").Value.String())
	if stateFlag != "" {
		switch stateFlag {
		case "INACTIVE":
			state = common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE
		case "ANY":
			state = common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY
		}
	}
	return state
}

// func (f flagHelper) GetStructSlice(flag string, v []StructFlag[T], opts flagHelperStringSliceOptions) ([]StructFlag[T], err) {
// 	if len(v) < opts.Min {
// 		fmt.Println(ErrorMessage(fmt.Sprintf("Flag %s must have at least %d non-empty values", flag, opts.Min), nil))
// 		os.Exit(1)
// 	}
// 	if opts.Max > 0 && len(v) > opts.Max {
// 		fmt.Println(ErrorMessage(fmt.Sprintf("Flag %s must have at most %d non-empty values", flag, opts.Max), nil))
// 		os.Exit(1)
// 	}
// 	return v
// }

// type StructFlag[T any] struct {
// 	Val T
// }

// func (this StructFlag[T]) String() string {
// 	b, _ := json.Marshal(this)
// 	return string(b)
// }

// func (this StructFlag[T]) Set(s string) error {
// 	return json.Unmarshal([]byte(s), this)
// }
