package policy

import (
	"encoding/json"
	"fmt"

	"github.com/evertras/bubble-table/table"
	"github.com/google/uuid"
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/spf13/cobra"
)

var (
	actionFlagValues []string
	selectors        []string
)

func policyGetSubjectMapping(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")

	mapping, err := h.GetSubjectMapping(cmd.Context(), id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find subject mapping (%s)", id)
		cli.ExitWithError(errMsg, err)
	}
	var actionsJSON []byte
	if actionsJSON, err = json.Marshal(mapping.GetActions()); err != nil {
		cli.ExitWithError("Error marshalling subject mapping actions", err)
	}

	var subjectSetsJSON []byte
	if subjectSetsJSON, err = json.Marshal(mapping.GetSubjectConditionSet().GetSubjectSets()); err != nil {
		cli.ExitWithError("Error marshalling subject condition set", err)
	}

	rows := [][]string{
		{"Id", mapping.GetId()},
		{"Attribute Value: Id", mapping.GetAttributeValue().GetId()},
		{"Attribute Value: Value", mapping.GetAttributeValue().GetValue()},
		{"Actions", string(actionsJSON)},
		{"Subject Condition Set: Id", mapping.GetSubjectConditionSet().GetId()},
		{"Subject Condition Set", string(subjectSetsJSON)},
	}
	if mdRows := getMetadataRows(mapping.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, mapping.GetId(), t, mapping)
}

func policyListSubjectMappings(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")

	resp, err := h.ListSubjectMappings(cmd.Context(), limit, offset)
	if err != nil {
		cli.ExitWithError("Failed to get subject mappings", err)
	}
	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("value_id", "Attribute Value Id", cli.FlexColumnWidthFour),
		table.NewFlexColumn("value_fqn", "Attibribute Value FQN", cli.FlexColumnWidthFour),
		table.NewFlexColumn("actions", "Actions", cli.FlexColumnWidthTwo),
		table.NewFlexColumn("subject_condition_set_id", "Subject Condition Set: Id", cli.FlexColumnWidthFour),
		table.NewFlexColumn("subject_condition_set", "Subject Condition Set", cli.FlexColumnWidthThree),
	)
	rows := []table.Row{}
	for _, sm := range resp.GetSubjectMappings() {
		var actionsJSON []byte
		if actionsJSON, err = json.Marshal(sm.GetActions()); err != nil {
			cli.ExitWithError("Error marshalling subject mapping actions", err)
		}

		var subjectSetsJSON []byte
		if subjectSetsJSON, err = json.Marshal(sm.GetSubjectConditionSet().GetSubjectSets()); err != nil {
			cli.ExitWithError("Error marshalling subject condition set", err)
		}

		rows = append(rows, table.NewRow(table.RowData{
			"id":                       sm.GetId(),
			"value_id":                 sm.GetAttributeValue().GetId(),
			"value_fqn":                sm.GetAttributeValue().GetFqn(),
			"actions":                  string(actionsJSON),
			"subject_condition_set_id": sm.GetSubjectConditionSet().GetId(),
			"subject_condition_set":    string(subjectSetsJSON),
		}))
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func policyCreateSubjectMapping(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	attrValueID := c.Flags.GetRequiredID("attribute-value-id")
	actionFlagValues = c.Flags.GetStringSlice("action", actionFlagValues, cli.FlagsStringSliceOptions{Min: 0})
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})
	existingSCSId := c.Flags.GetOptionalID("subject-condition-set-id")
	// NOTE: labels within a new Subject Condition Set created on a SM creation are not supported
	newScsJSON := c.Flags.GetOptionalString("subject-condition-set-new")

	// validations
	if len(actionFlagValues) == 0 {
		cli.ExitWithError("At least one Action [--action] is required", nil)
	}
	if existingSCSId == "" && newScsJSON == "" {
		cli.ExitWithError("At least one Subject Condition Set flag [--subject-condition-set-id, --subject-condition-set-new] must be provided", nil)
	}

	actions := make([]*policy.Action, len(actionFlagValues))
	for i, a := range actionFlagValues {
		action := &policy.Action{}
		_, err := uuid.Parse(a)
		if err != nil {
			action.Name = a
		} else {
			action.Id = a
		}
		actions[i] = action
	}

	var scs *subjectmapping.SubjectConditionSetCreate
	if newScsJSON != "" {
		ss, err := unmarshalSubjectSetsProto([]byte(newScsJSON))
		if err != nil {
			cli.ExitWithError("Error unmarshalling subject sets", err)
		}
		scs = &subjectmapping.SubjectConditionSetCreate{
			SubjectSets: ss,
		}
	}

	mapping, err := h.CreateNewSubjectMapping(cmd.Context(), attrValueID, actions, existingSCSId, scs, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create subject mapping", err)
	}

	var actionsJSON []byte
	if actionsJSON, err = json.Marshal(mapping.GetActions()); err != nil {
		cli.ExitWithError("Error marshalling subject mapping actions", err)
	}

	var subjectSetsJSON []byte
	if mapping.GetSubjectConditionSet() != nil {
		if subjectSetsJSON, err = json.Marshal(mapping.GetSubjectConditionSet().GetSubjectSets()); err != nil {
			cli.ExitWithError("Error marshalling subject condition set", err)
		}
	}

	rows := [][]string{
		{"Id", mapping.GetId()},
		{"Attribute Value Id", mapping.GetAttributeValue().GetId()},
		{"Actions", string(actionsJSON)},
		{"Subject Condition Set: Id", mapping.GetSubjectConditionSet().GetId()},
		{"Subject Condition Set", string(subjectSetsJSON)},
	}

	if mdRows := getMetadataRows(mapping.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, mapping.GetId(), t, mapping)
}

func policyDeleteSubjectMapping(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	force := c.Flags.GetOptionalBool("force")

	sm, err := h.GetSubjectMapping(cmd.Context(), id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find subject mapping (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	cli.ConfirmAction(cli.ActionDelete, "subject mapping", sm.GetId(), force)

	deleted, err := h.DeleteSubjectMapping(cmd.Context(), id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to delete subject mapping (%s)", id)
		cli.ExitWithError(errMsg, err)
	}
	rows := [][]string{{"Id", sm.GetId()}}
	if mdRows := getMetadataRows(deleted.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, deleted)
}

func policyUpdateSubjectMapping(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	actionFlagValues = c.Flags.GetStringSlice("action", actionFlagValues, cli.FlagsStringSliceOptions{Min: 0})
	scsID := c.Flags.GetOptionalID("subject-condition-set-id")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	var actions []*policy.Action
	if len(actionFlagValues) > 0 {
		for _, a := range actionFlagValues {
			action := &policy.Action{}
			_, err := uuid.Parse(a)
			if err != nil {
				action.Name = a
			} else {
				action.Id = a
			}
			actions = append(actions, action)
		}
	}

	updated, err := h.UpdateSubjectMapping(
		cmd.Context(),
		id,
		scsID,
		actions,
		getMetadataMutable(metadataLabels),
		getMetadataUpdateBehavior(),
	)
	if err != nil {
		cli.ExitWithError("Failed to update subject mapping", err)
	}
	rows := [][]string{{"Id", id}}
	if mdRows := getMetadataRows(updated.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)

	common.HandleSuccess(cmd, id, t, updated)
}

func policyMatchSubjectMappings(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	subject := c.Flags.GetOptionalString("subject")
	selectors = c.Flags.GetStringSlice("selector", selectors, cli.FlagsStringSliceOptions{Min: 0})

	if len(selectors) > 0 && subject != "" {
		cli.ExitWithError("Must provide either '--subject' or '--selector' flag values, not both", nil)
	}

	if subject != "" {
		flattened, err := handlers.FlattenSubjectContext(subject)
		if err != nil {
			cli.ExitWithError("Could not process '--subject' value", err)
		}
		for _, item := range flattened {
			selectors = append(selectors, item.Key)
		}
	}

	matched, err := h.MatchSubjectMappings(cmd.Context(), selectors)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to match subject mappings with selectors %v", selectors), err)
	}

	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("subject_attrval_id", "Subject AttrVal: Id", cli.FlexColumnWidthFour),
		table.NewFlexColumn("subject_attrval_value", "Subject AttrVal: Value", cli.FlexColumnWidthThree),
		table.NewFlexColumn("actions", "Actions", cli.FlexColumnWidthTwo),
		table.NewFlexColumn("subject_condition_set_id", "Subject Condition Set: Id", cli.FlexColumnWidthFour),
		table.NewFlexColumn("subject_condition_set", "Subject Condition Set", cli.FlexColumnWidthThree),
	)
	rows := []table.Row{}
	for _, sm := range matched {
		var actionsJSON []byte
		if actionsJSON, err = json.Marshal(sm.GetActions()); err != nil {
			cli.ExitWithError("Error marshalling subject mapping actions", err)
		}

		var subjectSetsJSON []byte
		if subjectSetsJSON, err = json.Marshal(sm.GetSubjectConditionSet().GetSubjectSets()); err != nil {
			cli.ExitWithError("Error marshalling subject condition set", err)
		}
		metadata := cli.ConstructMetadata(sm.GetMetadata())

		rows = append(rows, table.NewRow(table.RowData{
			"id":                       sm.GetId(),
			"subject_attrval_id":       sm.GetAttributeValue().GetId(),
			"subject_attrval_value":    sm.GetAttributeValue().GetValue(),
			"actions":                  string(actionsJSON),
			"subject_condition_set_id": sm.GetSubjectConditionSet().GetId(),
			"subject_condition_set":    string(subjectSetsJSON),
			"labels":                   metadata["Labels"],
			"created_at":               metadata["Created At"],
			"updated_at":               metadata["Updated At"],
		}))
	}
	t = t.WithRows(rows)
	common.HandleSuccess(cmd, "", t, matched)
}

func initSubjectMappingsCommands() {
	getDoc := man.Docs.GetCommand("policy/subject-mappings/get",
		man.WithRun(policyGetSubjectMapping),
	)
	getDoc.Flags().StringP(
		getDoc.GetDocFlag("id").Name,
		getDoc.GetDocFlag("id").Shorthand,
		getDoc.GetDocFlag("id").Default,
		getDoc.GetDocFlag("id").Description,
	)

	listDoc := man.Docs.GetCommand("policy/subject-mappings/list",
		man.WithRun(policyListSubjectMappings),
	)
	injectListPaginationFlags(listDoc)

	createDoc := man.Docs.GetCommand("policy/subject-mappings/create",
		man.WithRun(policyCreateSubjectMapping),
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("attribute-value-id").Name,
		createDoc.GetDocFlag("attribute-value-id").Shorthand,
		createDoc.GetDocFlag("attribute-value-id").Default,
		createDoc.GetDocFlag("attribute-value-id").Description,
	)
	// deprecated
	createDoc.Flags().StringSliceVarP(
		&[]string{},
		createDoc.GetDocFlag("action-standard").Name,
		createDoc.GetDocFlag("action-standard").Shorthand,
		[]string{},
		createDoc.GetDocFlag("action-standard").Description,
	)
	// deprecated
	createDoc.Flags().StringSliceVarP(
		&[]string{},
		createDoc.GetDocFlag("action-custom").Name,
		createDoc.GetDocFlag("action-custom").Shorthand,
		[]string{},
		createDoc.GetDocFlag("action-custom").Description,
	)
	createDoc.Flags().StringSliceVarP(
		&actionFlagValues,
		createDoc.GetDocFlag("action").Name,
		createDoc.GetDocFlag("action").Shorthand,
		[]string{},
		createDoc.GetDocFlag("action").Description,
	)
	createDoc.Flags().String(
		createDoc.GetDocFlag("subject-condition-set-id").Name,
		createDoc.GetDocFlag("subject-condition-set-id").Default,
		createDoc.GetDocFlag("subject-condition-set-id").Description,
	)
	createDoc.Flags().String(
		createDoc.GetDocFlag("subject-condition-set-new").Name,
		createDoc.GetDocFlag("subject-condition-set-new").Default,
		createDoc.GetDocFlag("subject-condition-set-new").Description,
	)
	injectLabelFlags(&createDoc.Command, false)

	updateDoc := man.Docs.GetCommand("policy/subject-mappings/update",
		man.WithRun(policyUpdateSubjectMapping),
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("id").Name,
		updateDoc.GetDocFlag("id").Shorthand,
		updateDoc.GetDocFlag("id").Default,
		updateDoc.GetDocFlag("id").Description,
	)
	// deprecated
	updateDoc.Flags().StringSliceVarP(
		&[]string{},
		updateDoc.GetDocFlag("action-standard").Name,
		updateDoc.GetDocFlag("action-standard").Shorthand,
		[]string{},
		updateDoc.GetDocFlag("action-standard").Description,
	)
	updateDoc.Flags().StringSliceVarP(
		&[]string{},
		updateDoc.GetDocFlag("action-custom").Name,
		updateDoc.GetDocFlag("action-custom").Shorthand,
		[]string{},
		updateDoc.GetDocFlag("action-custom").Description,
	)
	updateDoc.Flags().StringSliceVarP(
		&actionFlagValues,
		updateDoc.GetDocFlag("action").Name,
		updateDoc.GetDocFlag("action").Shorthand,
		[]string{},
		updateDoc.GetDocFlag("action").Description,
	)
	updateDoc.Flags().String(
		updateDoc.GetDocFlag("subject-condition-set-id").Name,
		updateDoc.GetDocFlag("subject-condition-set-id").Default,
		updateDoc.GetDocFlag("subject-condition-set-id").Description,
	)
	injectLabelFlags(&updateDoc.Command, true)

	deleteDoc := man.Docs.GetCommand("policy/subject-mappings/delete",
		man.WithRun(policyDeleteSubjectMapping),
	)
	deleteDoc.Flags().StringP(
		deleteDoc.GetDocFlag("id").Name,
		deleteDoc.GetDocFlag("id").Shorthand,
		deleteDoc.GetDocFlag("id").Default,
		deleteDoc.GetDocFlag("id").Description,
	)
	deleteDoc.Flags().Bool(
		deleteDoc.GetDocFlag("force").Name,
		false,
		deleteDoc.GetDocFlag("force").Description,
	)

	matchDoc := man.Docs.GetCommand("policy/subject-mappings/match",
		man.WithRun(policyMatchSubjectMappings),
	)
	matchDoc.Flags().StringP(
		matchDoc.GetDocFlag("subject").Name,
		matchDoc.GetDocFlag("subject").Shorthand,
		matchDoc.GetDocFlag("subject").Default,
		matchDoc.GetDocFlag("subject").Description,
	)
	matchDoc.Flags().StringSliceVarP(
		&selectors,
		matchDoc.GetDocFlag("selector").Name,
		matchDoc.GetDocFlag("selector").Shorthand,
		[]string{},
		matchDoc.GetDocFlag("selector").Description,
	)

	doc := man.Docs.GetCommand("policy/subject-mappings",
		man.WithSubcommands(
			createDoc,
			getDoc,
			listDoc,
			updateDoc,
			deleteDoc,
			matchDoc,
		),
	)
	subjectMappingCmd := &doc.Command
	Cmd.AddCommand(subjectMappingCmd)
}
