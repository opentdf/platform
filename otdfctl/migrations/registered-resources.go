//nolint:forbidigo // migration output requires direct terminal printing for interactive prompts and styled output
package migrations

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/charmbracelet/huh"
	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
)

const (
	optSkipResource = "skip-resource"
	optAbortAll     = "abort-all"
)

// MigrationHandler defines the handler methods needed for registered resource migration.
// handlers.Handler satisfies this interface implicitly.
type MigrationHandler interface {
	ListRegisteredResources(ctx context.Context, limit, offset int32, namespace string) (*registeredresources.ListRegisteredResourcesResponse, error)
	ListRegisteredResourceValues(ctx context.Context, resourceID string, limit, offset int32) (*registeredresources.ListRegisteredResourceValuesResponse, error)
	CreateRegisteredResource(ctx context.Context, namespace, name string, values []string, metadata *common.MetadataMutable) (*policy.RegisteredResource, error)
	CreateRegisteredResourceValue(ctx context.Context, resourceID string, value string, actionAttributeValues []*registeredresources.ActionAttributeValue, metadata *common.MetadataMutable) (*policy.RegisteredResourceValue, error)
	DeleteRegisteredResource(ctx context.Context, id string) error
	ListNamespaces(ctx context.Context, state common.ActiveStateEnum, limit, offset int32) (*namespaces.ListNamespacesResponse, error)
}

// MigrationPrompter abstracts interactive prompts so they can be mocked in tests.
type MigrationPrompter interface {
	// ConfirmBackup prompts the user to confirm they have taken a backup.
	ConfirmBackup() (bool, error)

	// SelectBatchNamespace prompts the user to select one namespace for all resources.
	SelectBatchNamespace(nsList []*policy.Namespace) (string, error)

	// SelectResourceNamespace prompts the user to select a namespace for a specific resource.
	// The returned string may be a namespace FQN/ID, optSkipResource, or optAbortAll.
	SelectResourceNamespace(resourceName string, nsList []*policy.Namespace) (string, error)

	// ConfirmResourceNamespace shows the auto-detected namespace and asks the user to confirm,
	// skip the resource, or abort. Returns the namespace FQN, optSkipResource, or optAbortAll.
	ConfirmResourceNamespace(resourceName, detectedNamespaceFQN string) (string, error)
}

// HuhPrompter implements MigrationPrompter using charmbracelet/huh forms.
type HuhPrompter struct{}

func (p *HuhPrompter) ConfirmBackup() (bool, error) {
	var backupResponse bool
	styles := initMigrationDisplayStyles()

	fmt.Println(styles.styleWarning.Render("WARNING: This operation will delete and re-create registered resources under new namespaces."))
	fmt.Println(styles.styleWarning.Render("It is STRONGLY recommended to take a complete backup of your system before proceeding.\n"))

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[bool]().
				Title("Have you taken a complete backup? (yes/no): ").
				Options(
					huh.NewOption("yes", true),
					huh.NewOption("no", false),
					huh.NewOption("cancel", false),
				).
				Value(&backupResponse),
		),
	)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return false, errors.New("user aborted backup form")
		}
		return false, err
	}
	return backupResponse, nil
}

func (p *HuhPrompter) SelectBatchNamespace(nsList []*policy.Namespace) (string, error) {
	var targetNamespace string
	nsOpts := buildNamespaceOptions(nsList)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select a target namespace for ALL registered resources:").
				Options(nsOpts...).
				Value(&targetNamespace),
		),
	)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return "", errors.New("migration aborted by user")
		}
		return "", fmt.Errorf("namespace selection failed: %w", err)
	}
	return targetNamespace, nil
}

func (p *HuhPrompter) SelectResourceNamespace(resourceName string, nsList []*policy.Namespace) (string, error) {
	nsOpts := buildNamespaceOptions(nsList)
	skipOpt := huh.NewOption("Skip this resource", optSkipResource)
	abortOpt := huh.NewOption("Abort entire migration", optAbortAll)
	nsOptsWithControls := append(append([]huh.Option[string]{}, nsOpts...), skipOpt, abortOpt)

	var targetNamespace string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title(fmt.Sprintf("Select namespace for resource '%s':", resourceName)).
				Options(nsOptsWithControls...).
				Value(&targetNamespace),
		),
	)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return "", huh.ErrUserAborted
		}
		return "", err
	}
	return targetNamespace, nil
}

func (p *HuhPrompter) ConfirmResourceNamespace(resourceName, detectedNamespaceFQN string) (string, error) {
	var choice string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Resource '"+resourceName+"' belongs in namespace '"+detectedNamespaceFQN+"' (detected from AAVs):").
				Options(
					huh.NewOption("Confirm: "+detectedNamespaceFQN, detectedNamespaceFQN),
					huh.NewOption("Skip this resource", optSkipResource),
					huh.NewOption("Abort entire migration", optAbortAll),
				).
				Value(&choice),
		),
	)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return "", huh.ErrUserAborted
		}
		return "", err
	}
	return choice, nil
}

// RegisteredResourceMigrationPlan holds an existing resource with its values and the target namespace.
type RegisteredResourceMigrationPlan struct {
	Resource        *policy.RegisteredResource
	Values          []*policy.RegisteredResourceValue
	TargetNamespace string // namespace FQN or ID to migrate to
	Commit          bool
}

// namespaceDetectionResult holds the result of inspecting a resource's AAVs for namespace info.
type namespaceDetectionResult struct {
	Deterministic string   // single namespace FQN if all AAVs agree
	Conflicting   []string // distinct FQNs when AAVs reference multiple namespaces
	Undetermined  bool     // AAVs exist but namespace data unavailable
	NoAAVs        bool     // resource has no AAVs at all
}

// extractNamespaceFQNFromValue attempts to derive the namespace FQN from an attribute value.
func extractNamespaceFQNFromValue(val *policy.Value) string {
	// Primary: full chain Value → Attribute → Namespace
	if ns := val.GetAttribute().GetNamespace(); ns != nil {
		if fqn := ns.GetFqn(); fqn != "" {
			return fqn
		}
	}
	// Fallback: parse from the value's own FQN (e.g. "https://example.com/attr/color/value/red")
	if fqn := val.GetFqn(); fqn != "" {
		if parsed, err := identifier.Parse[*identifier.FullyQualifiedAttribute](fqn); err == nil && parsed.Namespace != "" {
			return "https://" + parsed.Namespace
		}
	}
	return ""
}

// detectRequiredNamespace inspects a resource's AAVs to determine which namespace it should belong to.
func detectRequiredNamespace(plan RegisteredResourceMigrationPlan) namespaceDetectionResult {
	nsSet := make(map[string]struct{})
	hasAAVs := false

	for _, v := range plan.Values {
		for _, aav := range v.GetActionAttributeValues() {
			hasAAVs = true
			attrVal := aav.GetAttributeValue()
			if attrVal == nil {
				continue
			}
			nsFQN := extractNamespaceFQNFromValue(attrVal)
			if nsFQN != "" {
				nsSet[nsFQN] = struct{}{}
			}
		}
	}

	if !hasAAVs {
		return namespaceDetectionResult{NoAAVs: true}
	}

	if len(nsSet) == 0 {
		return namespaceDetectionResult{Undetermined: true}
	}

	if len(nsSet) == 1 {
		for fqn := range nsSet {
			return namespaceDetectionResult{Deterministic: fqn}
		}
	}

	conflicting := make([]string, 0, len(nsSet))
	for fqn := range nsSet {
		conflicting = append(conflicting, fqn)
	}
	return namespaceDetectionResult{Conflicting: conflicting}
}

// filterNamespacesByFQN returns only the namespaces whose FQN matches one of the given FQNs.
func filterNamespacesByFQN(nsList []*policy.Namespace, fqns []string) []*policy.Namespace {
	fqnSet := make(map[string]struct{}, len(fqns))
	for _, f := range fqns {
		fqnSet[f] = struct{}{}
	}
	var filtered []*policy.Namespace
	for _, ns := range nsList {
		if _, ok := fqnSet[ns.GetFqn()]; ok {
			filtered = append(filtered, ns)
		}
	}
	return filtered
}

// MigrateRegisteredResources is the main entry point for migrating registered resources to namespaces.
func MigrateRegisteredResources(ctx context.Context, h MigrationHandler, prompter MigrationPrompter, commit, interactive bool) error {
	styles := initMigrationDisplayStyles()

	plan, err := buildRegisteredResourcePlan(ctx, h)
	if err != nil {
		return err
	}

	if len(plan) == 0 {
		fmt.Println(styles.styleWarning.Render("No registered resources found that need namespace migration."))
		return nil
	}

	availableNamespaces, err := listAvailableNamespaces(ctx, h)
	if err != nil {
		return err
	}

	if len(availableNamespaces) == 0 {
		return errors.New("no namespaces available - please create at least one namespace before running migration")
	}

	if commit {
		didBackup, err := prompter.ConfirmBackup()
		if err != nil {
			return err
		}
		if !didBackup {
			return errors.New("user did not confirm backup")
		}
	}

	switch {
	case interactive && commit:
		return runInteractiveRegisteredResourceMigration(ctx, h, prompter, styles, plan, availableNamespaces)
	case commit:
		return runBatchRegisteredResourceMigration(ctx, h, prompter, styles, plan, availableNamespaces)
	default:
		displayRegisteredResourcePlan(styles, plan)
		if interactive {
			fmt.Println(styles.styleInfo.Render("\nNote: --interactive without --commit only shows a preview. Add --commit to apply changes."))
		}
	}

	return nil
}

// buildRegisteredResourcePlan fetches all registered resources without namespaces and their values.
func buildRegisteredResourcePlan(ctx context.Context, h MigrationHandler) ([]RegisteredResourceMigrationPlan, error) {
	var (
		plans    []RegisteredResourceMigrationPlan
		offset   int32
		pageSize int32 = 100
	)

	for {
		resp, err := h.ListRegisteredResources(ctx, pageSize, offset, "")
		if err != nil {
			return nil, fmt.Errorf("failed to list registered resources: %w", err)
		}

		resources := resp.GetResources()
		if len(resources) == 0 {
			break
		}

		for _, resource := range resources {
			// Only include resources that have no namespace
			if resource.GetNamespace() != nil && resource.GetNamespace().GetId() != "" {
				continue
			}

			values, err := fetchAllResourceValues(ctx, h, resource.GetId())
			if err != nil {
				return nil, fmt.Errorf("failed to fetch values for resource %s: %w", resource.GetId(), err)
			}

			plans = append(plans, RegisteredResourceMigrationPlan{
				Resource: resource,
				Values:   values,
			})
		}

		qty := len(resources)
		if qty > math.MaxInt32 || offset+int32(qty) < 0 {
			return nil, errors.New("resource count exceeded safe limit")
		}
		offset += int32(qty)

		if int32(qty) < pageSize {
			break
		}
	}

	return plans, nil
}

// fetchAllResourceValues paginates through all values for a resource.
func fetchAllResourceValues(ctx context.Context, h MigrationHandler, resourceID string) ([]*policy.RegisteredResourceValue, error) {
	var (
		allValues []*policy.RegisteredResourceValue
		offset    int32
		pageSize  int32 = 100
	)

	for {
		resp, err := h.ListRegisteredResourceValues(ctx, resourceID, pageSize, offset)
		if err != nil {
			return nil, err
		}

		values := resp.GetValues()
		if len(values) == 0 {
			break
		}

		allValues = append(allValues, values...)

		qty := len(values)
		if qty > math.MaxInt32 || offset+int32(qty) < 0 {
			break
		}
		offset += int32(qty)

		if int32(qty) < pageSize {
			break
		}
	}

	return allValues, nil
}

// listAvailableNamespaces fetches all active namespaces.
func listAvailableNamespaces(ctx context.Context, h MigrationHandler) ([]*policy.Namespace, error) {
	var (
		all      []*policy.Namespace
		offset   int32
		pageSize int32 = 100
	)

	for {
		resp, err := h.ListNamespaces(ctx, common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE, pageSize, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to list namespaces: %w", err)
		}

		nsList := resp.GetNamespaces()
		if len(nsList) == 0 {
			break
		}

		all = append(all, nsList...)

		qty := len(nsList)
		if qty > math.MaxInt32 || offset+int32(qty) < 0 {
			break
		}
		offset += int32(qty)

		if int32(qty) < pageSize {
			break
		}
	}

	return all, nil
}

// buildNamespaceOptions creates huh options from a list of namespaces.
func buildNamespaceOptions(nsList []*policy.Namespace) []huh.Option[string] {
	opts := make([]huh.Option[string], 0, len(nsList))
	for _, ns := range nsList {
		label := ns.GetFqn()
		value := ns.GetFqn()
		if label == "" {
			label = ns.GetName() + " (" + ns.GetId() + ")"
			value = ns.GetId()
		}
		opts = append(opts, huh.NewOption(label, value))
	}
	return opts
}

// displayRegisteredResourcePlan shows a preview of resources that would be migrated.
func displayRegisteredResourcePlan(styles *migrationDisplayStyles, plan []RegisteredResourceMigrationPlan) {
	fmt.Println(styles.styleTitle.Render("\nRegistered Resources Migration Plan"))
	fmt.Println(styles.styleSeparator.Render(styles.separatorText))
	fmt.Printf("%s %d\n\n",
		styles.styleInfo.Render("Resources requiring namespace assignment:"),
		len(plan),
	)

	for i, p := range plan {
		fmt.Printf("%s %s\n",
			styles.styleInfo.Render(fmt.Sprintf("%d. Resource ID:", i+1)),
			styles.styleResourceID.Render(p.Resource.GetId()),
		)
		fmt.Printf("   %s %s\n",
			styles.styleInfo.Render("Name:"),
			styles.styleName.Render(p.Resource.GetName()),
		)
		if len(p.Values) > 0 {
			fmt.Printf("   %s\n", styles.styleInfo.Render("Values:"))
			for _, v := range p.Values {
				aavCount := len(v.GetActionAttributeValues())
				fmt.Printf("     - %s (ID: %s, %d action-attribute mapping(s))\n",
					styles.styleValue.Render(v.GetValue()),
					styles.styleID.Render(v.GetId()),
					aavCount,
				)
			}
		} else {
			fmt.Printf("   %s\n", styles.styleInfo.Render("Values: (none)"))
		}

		detection := detectRequiredNamespace(p)
		switch {
		case detection.Deterministic != "":
			fmt.Printf("   %s %s\n",
				styles.styleInfo.Render("Detected namespace:"),
				styles.styleNamespace.Render(detection.Deterministic),
			)
		case len(detection.Conflicting) > 0:
			fmt.Printf("   %s %v\n",
				styles.styleWarning.Render("CONFLICT - AAVs reference multiple namespaces:"),
				detection.Conflicting,
			)
		case detection.Undetermined:
			fmt.Printf("   %s\n",
				styles.styleWarning.Render("AAVs present but namespace could not be determined"),
			)
		default:
			fmt.Printf("   %s\n",
				styles.styleInfo.Render("No AAVs - namespace can be freely chosen"),
			)
		}

		fmt.Println()
	}

	fmt.Println(styles.styleSeparator.Render(styles.separatorText))
	fmt.Println(styles.styleInfo.Render("\nRun with --commit to assign namespaces in batch mode."))
	fmt.Println(styles.styleInfo.Render("Run with --interactive --commit for per-resource namespace assignment."))
}

type indexedPlan struct {
	index int
	plan  RegisteredResourceMigrationPlan
}

// runBatchRegisteredResourceMigration auto-detects namespaces where possible and prompts for the rest.
func runBatchRegisteredResourceMigration(ctx context.Context, h MigrationHandler, prompter MigrationPrompter, styles *migrationDisplayStyles, plan []RegisteredResourceMigrationPlan, nsList []*policy.Namespace) error {
	displayRegisteredResourcePlan(styles, plan)

	// Phase 1: Auto-detect namespaces
	var needsSelection []indexedPlan

	fmt.Println(styles.styleTitle.Render("\nNamespace Detection:"))
	for i := range plan {
		detection := detectRequiredNamespace(plan[i])
		switch {
		case detection.Deterministic != "":
			plan[i].TargetNamespace = detection.Deterministic
			fmt.Printf("  %s '%s' -> %s (auto-detected from AAVs)\n",
				styles.styleInfo.Render("Resource"),
				styles.styleName.Render(plan[i].Resource.GetName()),
				styles.styleNamespace.Render(detection.Deterministic),
			)
		case len(detection.Conflicting) > 0:
			fmt.Printf("  %s '%s' has AAVs in multiple namespaces: %v\n",
				styles.styleWarning.Render("CONFLICT: Resource"),
				plan[i].Resource.GetName(), detection.Conflicting,
			)
			needsSelection = append(needsSelection, indexedPlan{index: i, plan: plan[i]})
		case detection.Undetermined:
			fmt.Printf("  %s '%s' has AAVs but namespace could not be determined\n",
				styles.styleWarning.Render("WARNING: Resource"),
				plan[i].Resource.GetName(),
			)
			needsSelection = append(needsSelection, indexedPlan{index: i, plan: plan[i]})
		default:
			fmt.Printf("  %s '%s' has no AAVs - needs manual assignment\n",
				styles.styleInfo.Render("Resource"),
				plan[i].Resource.GetName(),
			)
			needsSelection = append(needsSelection, indexedPlan{index: i, plan: plan[i]})
		}
	}

	// Phase 2: Prompt for resources that need selection
	if err := resolveUndetectedNamespaces(styles, prompter, plan, needsSelection, nsList); err != nil {
		return err
	}

	// Phase 3: Execute all migrations
	successCount := 0
	skippedCount := 0
	failedResources := make(map[string]string)

	for _, p := range plan {
		if p.TargetNamespace == "" {
			skippedCount++
			continue
		}
		p.Commit = true

		fmt.Printf("%s %s (%s) to %s...\n",
			styles.styleInfo.Render("Migrating resource"),
			styles.styleName.Render(p.Resource.GetName()),
			styles.styleResourceID.Render(p.Resource.GetId()),
			styles.styleNamespace.Render(p.TargetNamespace),
		)

		if err := commitRegisteredResourceMigration(ctx, h, p); err != nil {
			errMsg := "Failed to migrate resource " + p.Resource.GetId() + ": " + err.Error()
			fmt.Println(styles.styleWarning.Render(errMsg))
			failedResources[p.Resource.GetId()] = err.Error()
		} else {
			fmt.Println(styles.styleAction.Render("  Successfully migrated resource " + p.Resource.GetName()))
			successCount++
		}
	}

	// Print summary
	fmt.Println(styles.styleTitle.Render("\nBatch Migration Summary:"))
	fmt.Printf("  Total Resources: %d\n", len(plan))
	fmt.Printf("  Successfully Migrated: %d\n", successCount)
	fmt.Printf("  Skipped: %d\n", skippedCount)
	fmt.Printf("  Failed: %d\n", len(failedResources))
	if len(failedResources) > 0 {
		fmt.Println(styles.styleWarning.Render("  Failed Resources:"))
		for id, errMsg := range failedResources {
			fmt.Printf("    - Resource ID %s: %s\n", styles.styleResourceID.Render(id), errMsg)
		}
		return fmt.Errorf("%d of %d resources failed to migrate", len(failedResources), len(plan))
	}

	return nil
}

// resolveUndetectedNamespaces prompts for namespace selection on resources where auto-detection was not possible.
func resolveUndetectedNamespaces(styles *migrationDisplayStyles, prompter MigrationPrompter, plan []RegisteredResourceMigrationPlan, needsSelection []indexedPlan, nsList []*policy.Namespace) error {
	if len(needsSelection) == 0 {
		return nil
	}

	allNoAAVs := true
	for _, ip := range needsSelection {
		d := detectRequiredNamespace(ip.plan)
		if !d.NoAAVs {
			allNoAAVs = false
			break
		}
	}

	if allNoAAVs {
		fmt.Printf("\n%s\n", styles.styleInfo.Render(fmt.Sprintf(
			"%d resource(s) have no AAVs and can be freely assigned:", len(needsSelection),
		)))
		batchNs, err := prompter.SelectBatchNamespace(nsList)
		if err != nil {
			return err
		}
		for _, ip := range needsSelection {
			plan[ip.index].TargetNamespace = batchNs
		}
		return nil
	}

	fmt.Printf("\n%s\n", styles.styleInfo.Render(fmt.Sprintf(
		"%d resource(s) need manual namespace selection:", len(needsSelection),
	)))
	for _, ip := range needsSelection {
		detection := detectRequiredNamespace(ip.plan)
		promptNsList := nsList
		if len(detection.Conflicting) > 0 {
			filtered := filterNamespacesByFQN(nsList, detection.Conflicting)
			if len(filtered) > 0 {
				promptNsList = filtered
			}
		}
		ns, err := prompter.SelectResourceNamespace(ip.plan.Resource.GetName(), promptNsList)
		if err != nil {
			return err
		}
		if ns == optAbortAll {
			return errors.New("migration aborted by user")
		}
		if ns == optSkipResource {
			continue // TargetNamespace remains empty
		}
		plan[ip.index].TargetNamespace = ns
	}
	return nil
}

// runInteractiveRegisteredResourceMigration prompts per-resource for namespace assignment.
func runInteractiveRegisteredResourceMigration(ctx context.Context, h MigrationHandler, prompter MigrationPrompter, styles *migrationDisplayStyles, plan []RegisteredResourceMigrationPlan, nsList []*policy.Namespace) error {
	fmt.Println(styles.styleInfo.Render("Interactive mode: processing resources one by one..."))

	var (
		successCount    int
		skippedCount    int
		aborted         bool
		failedResources = make(map[string]string)
	)

	for i, p := range plan {
		fmt.Println(styles.styleSeparator.Render(styles.separatorText))
		fmt.Printf("%s %s (%s %s)\n",
			styles.styleTitle.Render(fmt.Sprintf("Resource %d/%d:", i+1, len(plan))),
			styles.styleName.Render(p.Resource.GetName()),
			styles.styleInfo.Render("ID:"),
			styles.styleResourceID.Render(p.Resource.GetId()),
		)

		if len(p.Values) > 0 {
			fmt.Printf("  %s\n", styles.styleInfo.Render("Values:"))
			for _, v := range p.Values {
				aavCount := len(v.GetActionAttributeValues())
				fmt.Printf("    - %s (%d action-attribute mapping(s))\n",
					styles.styleValue.Render(v.GetValue()),
					aavCount,
				)
			}
		}

		detection := detectRequiredNamespace(p)

		var targetNamespace string
		var promptErr error

		switch {
		case detection.Deterministic != "":
			fmt.Printf("  %s %s\n",
				styles.styleInfo.Render("Detected required namespace from AAVs:"),
				styles.styleNamespace.Render(detection.Deterministic),
			)
			targetNamespace, promptErr = prompter.ConfirmResourceNamespace(p.Resource.GetName(), detection.Deterministic)
		case len(detection.Conflicting) > 0:
			fmt.Println(styles.styleWarning.Render(fmt.Sprintf(
				"  WARNING: Resource '%s' has AAVs referencing multiple namespaces: %v",
				p.Resource.GetName(), detection.Conflicting,
			)))
			filtered := filterNamespacesByFQN(nsList, detection.Conflicting)
			if len(filtered) == 0 {
				filtered = nsList
			}
			targetNamespace, promptErr = prompter.SelectResourceNamespace(p.Resource.GetName(), filtered)
		case detection.Undetermined:
			fmt.Println(styles.styleWarning.Render(fmt.Sprintf(
				"  WARNING: Resource '%s' has AAVs but namespace could not be determined from server response.",
				p.Resource.GetName(),
			)))
			targetNamespace, promptErr = prompter.SelectResourceNamespace(p.Resource.GetName(), nsList)
		default:
			targetNamespace, promptErr = prompter.SelectResourceNamespace(p.Resource.GetName(), nsList)
		}

		if promptErr != nil {
			if errors.Is(promptErr, huh.ErrUserAborted) {
				fmt.Println(styles.styleWarning.Render("Migration aborted by user."))
				aborted = true
				break
			}
			fmt.Println(styles.styleWarning.Render(fmt.Sprintf("Error during prompt: %v. Skipping resource.", promptErr)))
			skippedCount++
			continue
		}

		switch targetNamespace {
		case optSkipResource:
			fmt.Println(styles.styleInfo.Render(fmt.Sprintf("Skipping resource %s.", p.Resource.GetName())))
			skippedCount++
			continue
		case optAbortAll:
			fmt.Println(styles.styleWarning.Render("Aborting migration."))
			aborted = true
			goto summary
		}

		p.TargetNamespace = targetNamespace
		p.Commit = true

		fmt.Printf("%s %s to namespace %s...\n",
			styles.styleAction.Render("  Migrating"),
			styles.styleName.Render(p.Resource.GetName()),
			styles.styleNamespace.Render(targetNamespace),
		)

		if err := commitRegisteredResourceMigration(ctx, h, p); err != nil {
			errMsg := "Failed to migrate resource " + p.Resource.GetId() + ": " + err.Error()
			fmt.Println(styles.styleWarning.Render(errMsg))
			failedResources[p.Resource.GetId()] = err.Error()
		} else {
			fmt.Println(styles.styleAction.Render("  Successfully migrated resource " + p.Resource.GetName()))
			successCount++
		}
	}

summary:
	fmt.Println(styles.styleTitle.Render("\nInteractive Migration Summary:"))
	fmt.Printf("  Total Resources: %d\n", len(plan))
	fmt.Printf("  Successfully Migrated: %d\n", successCount)
	fmt.Printf("  Skipped: %d\n", skippedCount)
	fmt.Printf("  Failed: %d\n", len(failedResources))
	if len(failedResources) > 0 {
		fmt.Println(styles.styleWarning.Render("  Failed Resources:"))
		for id, errMsg := range failedResources {
			fmt.Printf("    - Resource ID %s: %s\n", styles.styleResourceID.Render(id), errMsg)
		}
	}

	if aborted {
		return errors.New("migration aborted by user")
	}
	if len(failedResources) > 0 {
		return fmt.Errorf("%d of %d resources failed to migrate", len(failedResources), len(plan))
	}

	return nil
}

// commitRegisteredResourceMigration re-creates a resource under a target namespace, then deletes the old one.
func commitRegisteredResourceMigration(ctx context.Context, h MigrationHandler, plan RegisteredResourceMigrationPlan) error {
	if !plan.Commit || plan.TargetNamespace == "" {
		return errors.New("migration plan is not ready for commit")
	}

	resource := plan.Resource

	// Build metadata for the new resource
	var metadata *common.MetadataMutable
	if resource.GetMetadata() != nil && len(resource.GetMetadata().GetLabels()) > 0 {
		metadata = &common.MetadataMutable{
			Labels: resource.GetMetadata().GetLabels(),
		}
	}

	// Step 1: Create new resource under target namespace (without values — we create them individually)
	newResource, err := h.CreateRegisteredResource(ctx, plan.TargetNamespace, resource.GetName(), nil, metadata)
	if err != nil {
		return fmt.Errorf("failed to create resource under namespace %s: %w", plan.TargetNamespace, err)
	}

	// Step 2: Create each value individually, preserving action-attribute mappings
	for _, oldValue := range plan.Values {
		oldAAVs := oldValue.GetActionAttributeValues()
		var aavRequests []*registeredresources.ActionAttributeValue
		if len(oldAAVs) > 0 {
			aavRequests = convertActionAttributeValues(oldAAVs)
		}

		var valueMetadata *common.MetadataMutable
		if oldValue.GetMetadata() != nil && len(oldValue.GetMetadata().GetLabels()) > 0 {
			valueMetadata = &common.MetadataMutable{
				Labels: oldValue.GetMetadata().GetLabels(),
			}
		}

		_, err := h.CreateRegisteredResourceValue(ctx, newResource.GetId(), oldValue.GetValue(), aavRequests, valueMetadata)
		if err != nil {
			return fmt.Errorf("failed to create value %s for resource %s: %w", oldValue.GetValue(), newResource.GetId(), err)
		}
	}

	// Step 3: Delete old resource (cascades to its values)
	if err := h.DeleteRegisteredResource(ctx, resource.GetId()); err != nil {
		return fmt.Errorf("failed to delete old resource %s (new resource %s was created successfully - manual cleanup may be needed): %w",
			resource.GetId(), newResource.GetId(), err)
	}

	return nil
}

// convertActionAttributeValues converts from policy object AAVs to request AAVs.
func convertActionAttributeValues(aavs []*policy.RegisteredResourceValue_ActionAttributeValue) []*registeredresources.ActionAttributeValue {
	result := make([]*registeredresources.ActionAttributeValue, 0, len(aavs))
	for _, aav := range aavs {
		req := &registeredresources.ActionAttributeValue{}

		// Use action ID if available
		if action := aav.GetAction(); action != nil && action.GetId() != "" {
			req.ActionIdentifier = &registeredresources.ActionAttributeValue_ActionId{
				ActionId: action.GetId(),
			}
		}

		// Use attribute value ID if available
		if attrValue := aav.GetAttributeValue(); attrValue != nil && attrValue.GetId() != "" {
			req.AttributeValueIdentifier = &registeredresources.ActionAttributeValue_AttributeValueId{
				AttributeValueId: attrValue.GetId(),
			}
		}

		result = append(result, req)
	}
	return result
}
