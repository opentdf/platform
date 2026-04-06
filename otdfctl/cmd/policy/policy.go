package policy

import (
	"strings"

	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/spf13/cobra"
)

var (
	metadataLabels        []string
	defaultListFlagLimit  int32 = 300
	defaultListFlagOffset int32 = 0

	Cmd = &cobra.Command{
		Use:   man.Docs.GetDoc("policy").Use,
		Short: man.Docs.GetDoc("policy").Short,
		Long:  man.Docs.GetDoc("policy").Long,
	}
)

func getMetadataRows(m *common.Metadata) [][]string {
	if m != nil {
		metadata := cli.ConstructMetadata(m)
		metadataRows := [][]string{
			{"Created At", metadata["Created At"]},
			{"Updated At", metadata["Updated At"]},
		}
		if m.Labels != nil {
			metadataRows = append(metadataRows, []string{"Labels", metadata["Labels"]})
		}
		return metadataRows
	}
	return nil
}

const keyValLength = 2

func getMetadataMutable(labels []string) *common.MetadataMutable {
	metadata := common.MetadataMutable{}
	if len(labels) > 0 {
		metadata.Labels = map[string]string{}
		for _, label := range labels {
			kv := strings.Split(label, "=")
			if len(kv) != keyValLength {
				cli.ExitWithError("Invalid label format", nil)
			}
			metadata.Labels[kv[0]] = kv[1]
		}
		return &metadata
	}
	return nil
}

func getMetadataUpdateBehavior() common.MetadataUpdateEnum {
	if forceReplaceMetadataLabels {
		return common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE
	}
	return common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND
}

// Adds reusable create/update label flags to a Policy command and the optional force-replace-labels flag for updates only
func injectLabelFlags(cmd *cobra.Command, isUpdate bool) {
	cmd.Flags().StringSliceVarP(&metadataLabels, "label", "l", []string{}, "Optional metadata 'labels' in the format: key=value")
	if isUpdate {
		cmd.Flags().BoolVar(&forceReplaceMetadataLabels, "force-replace-labels", false, "Destructively replace entire set of existing metadata 'labels' with any provided to this command")
	}
}

// Adds reusable limit/offset flags to a Policy LIST command
func injectListPaginationFlags(listDoc *man.Doc) {
	listDoc.Flags().Int32P(
		listDoc.GetDocFlag("limit").Name,
		listDoc.GetDocFlag("limit").Shorthand,
		defaultListFlagLimit,
		listDoc.GetDocFlag("limit").Description,
	)
	listDoc.Flags().Int32P(
		listDoc.GetDocFlag("offset").Name,
		listDoc.GetDocFlag("offset").Shorthand,
		defaultListFlagOffset,
		listDoc.GetDocFlag("offset").Description,
	)
}

func InitCommands() {
	initActionsCommands()
	initAttributesCommands()
	initAttributeValuesCommands()
	initNamespacesCommands()
	initSubjectConditionSetsCommands()
	initSubjectMappingsCommands()
	initObligationsCommands()
	initResourceMappingsCommands()
	initResourceMappingGroupsCommands()
	initRegisteredResourcesCommands()
	initKeyManagementCommands()
	initKeyManagementProviderCommands()
	initKASRegistryCommands()
	initKASKeysCommands()
	initKASGrantsCommands()
	initBaseKeysCommands()
}
