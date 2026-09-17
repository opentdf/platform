package cmd

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	osprofiles "github.com/jrschumacher/go-osprofiles"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/otdfctl/pkg/utils"
	"github.com/spf13/cobra"
)

var (
	runningInLinux    = runtime.GOOS == "linux"
	runningInTestMode = config.TestMode == "true"
)

const (
	profileMigrationLongDesc = "Migrate all profiles from keyring to filesystem. " +
		"If you get stuck during your migration due to name collisions across the filesystem/keyring, please" +
		" delete the specific profile from either the filesystem or keyring and run the migration again." +
		" If that still doesn't work, you can remove all profiles from the filesystem via the `delete-all` command."
)

type profileListOutput struct {
	Store    string           `json:"store"`
	Profiles []profileSummary `json:"profiles"`
}

type profileSummary struct {
	Name      string `json:"name"`
	IsDefault bool   `json:"is_default"`
}

type profileGetOutput struct {
	Profile      string `json:"profile"`
	Endpoint     string `json:"endpoint"`
	IsDefault    bool   `json:"is_default"`
	OutputFormat string `json:"output_format"`
	AuthType     string `json:"auth_type,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
}

const storeFlagUsage = "Profile store to use: filesystem or keyring"

// storeFlagCommands are the commands that resolve a driver from --store. Shared
// with the test so a seventh command cannot be added without being covered.
func storeFlagCommands() []*cobra.Command {
	return []*cobra.Command{
		profileListCmd,
		profileGetCmd,
		profileDeleteCmd,
		profileDeleteAllCmd,
		profileSetDefaultCmd,
		profileSetEndpointCmd,
	}
}

func newProfilerFromCLI(c *cli.Cli) *osprofiles.Profiler {
	driverType := getDriverTypeFromUser(c)
	profiler, err := profiles.NewProfiler(string(driverType))
	if err != nil {
		cli.ExitWithError("Error creating profiler", err)
	}

	return profiler
}

func getDriverTypeFromUser(c *cli.Cli) profiles.ProfileDriver {
	driverTypeStr := string(profiles.ProfileDriverDefault)
	store := c.Flags.GetOptionalString("store")
	if len(store) > 0 {
		driverTypeStr = store
	}

	driverType, err := profiles.ToProfileDriver(driverTypeStr)
	if err != nil {
		cli.ExitWithError("Error converting store type", err)
	}

	return driverType
}

var profileCmd = &cobra.Command{
	Use:     "profile",
	Aliases: []string{"profiles", "prof"},
	Short:   "Manage profiles (experimental)",
	Hidden:  runningInLinux && !runningInTestMode,
}

var profileCreateCmd = &cobra.Command{
	Use:     "create <profile> <endpoint>",
	Aliases: []string{"add"},
	Short:   "Create a new profile",
	//nolint:mnd // two args
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)
		profileName := args[0]
		endpoint := args[1]

		setDefault := c.Flags.GetOptionalBool("set-default")
		tlsNoVerify := c.Flags.GetOptionalBool("tls-no-verify")
		outputFormat := c.Flags.GetOptionalString("output-format")
		if !profiles.IsValidOutputFormat(outputFormat) {
			c.ExitWithError("Output format must be either 'styled' or 'json'", nil)
		}

		profileConfig := profiles.ProfileConfig{
			Name:         profileName,
			Endpoint:     endpoint,
			TLSNoVerify:  tlsNoVerify,
			OutputFormat: profiles.NormalizeOutputFormat(outputFormat),
		}
		_, err := profiles.NewOtdfctlProfileStore(profiles.ProfileDriverFileSystem, &profileConfig, setDefault)
		if err != nil {
			c.ExitWithError("Failed to create profile", err)
		}
		c.ExitWithSuccess(fmt.Sprintf("Profile %s created", profileName))
	},
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List profiles",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)
		driverType := getDriverTypeFromUser(c)
		profiler := newProfilerFromCLI(c)

		globalCfg := osprofiles.GetGlobalConfig(profiler)
		defaultProfile := globalCfg.GetDefaultProfile()

		var sb strings.Builder
		fmt.Fprintf(&sb, "Listing profiles from %s\n", driverType)

		out := profileListOutput{
			Store:    string(driverType),
			Profiles: []profileSummary{},
		}
		for _, p := range osprofiles.ListProfiles(profiler) {
			isDefault := p == defaultProfile
			out.Profiles = append(out.Profiles, profileSummary{
				Name:      p,
				IsDefault: isDefault,
			})
			if isDefault {
				fmt.Fprintf(&sb, "* %s\n", p)
				continue
			}
			fmt.Fprintf(&sb, "  %s\n", p)
		}

		c.ExitWith(sb.String(), out, cli.ExitCodeSuccess, os.Stdout)
	},
}

var profileGetCmd = &cobra.Command{
	Use:   "get <profile>",
	Short: "Get a profile value",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)
		profileName := args[0]

		driverType := getDriverTypeFromUser(c)
		profileStore, err := profiles.LoadOtdfctlProfileStore(driverType, profileName)
		if err != nil {
			cli.ExitWithError("Error loading profile store for profile "+profileName, err)
		}

		isDefault := profileStore.IsDefault()

		var auth string
		authType := ""
		clientID := ""
		ac := profileStore.GetAuthCredentials()
		if ac.AuthType == profiles.AuthTypeClientCredentials {
			maskedSecret := "********"
			auth = "client-credentials (" + ac.ClientID + ", " + maskedSecret + ")"
			authType = ac.AuthType
			clientID = ac.ClientID
		}

		t := cli.NewTabular(
			[]string{"Profile", profileStore.Name()},
			[]string{"Endpoint", profileStore.GetEndpoint()},
			[]string{"Is default", strconv.FormatBool(isDefault)},
			[]string{"Output format", profileStore.GetOutputFormat()},
			[]string{"Auth type", auth},
		)

		c.ExitWith(t.View(), profileGetOutput{
			Profile:      profileStore.Name(),
			Endpoint:     profileStore.GetEndpoint(),
			IsDefault:    isDefault,
			OutputFormat: profileStore.GetOutputFormat(),
			AuthType:     authType,
			ClientID:     clientID,
		}, cli.ExitCodeSuccess, os.Stdout)
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:   "delete <profile>",
	Short: "Delete a profile",
	// The Use string has always promised one operand and the handler indexes
	// args[0], but nothing enforced it: `profile delete` with no arguments
	// panicked on the missing index.
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)
		profileName := args[0]

		// TODO: suggest delete-all command to delete all profiles including default
		driverType := getDriverTypeFromUser(c)
		profiler := newProfilerFromCLI(c)

		if err := osprofiles.DeleteProfile[*profiles.ProfileConfig](profiler, profileName); err != nil {
			if errors.Is(err, osprofiles.ErrCannotDeleteDefaultProfile) {
				c.ExitWithWarning("Profile is set as default. Please set another profile as default before deleting.")
			}
			c.ExitWithError("Failed to delete profile", err)
		}
		c.ExitWithMessage(fmt.Sprintf("Deleted profile %s from %s", profileName, driverType), cli.ExitCodeSuccess)
	},
}

var profileDeleteAllCmd = &cobra.Command{
	Use:   "delete-all",
	Short: "Delete all profiles",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)

		force := c.Flags.GetOptionalBool("force")
		driverType := getDriverTypeFromUser(c)
		profiler := newProfilerFromCLI(c)

		profilesList := osprofiles.ListProfiles(profiler)
		if len(profilesList) == 0 {
			c.ExitWithMessage("No profiles found to delete", cli.ExitCodeSuccess)
			return
		}

		cli.ConfirmAction(cli.ActionDelete, fmt.Sprintf("all profiles from %s", driverType), config.AppName, force)

		if err := profiler.DeleteAllProfiles(); err != nil {
			c.ExitWithError("Failed to delete all profiles", err)
		}
		c.ExitWithMessage(fmt.Sprintf("Deleted %d profiles from %s", len(profilesList), driverType), cli.ExitCodeSuccess)
	},
}

var profileSetDefaultCmd = &cobra.Command{
	Use:   "set-default <profile>",
	Short: "Set a profile as default",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)
		profileName := args[0]
		profiler := newProfilerFromCLI(c)

		if err := osprofiles.SetDefaultProfile(profiler, profileName); err != nil {
			c.ExitWithError("Failed to set default profile", err)
		}

		// A fresh profiler, because reading back through the one that just wrote
		// would echo its own in-memory value rather than the store's.
		verifier := newProfilerFromCLI(c)
		if got := osprofiles.GetGlobalConfig(verifier).GetDefaultProfile(); got != profileName {
			c.ExitWithError("Default profile did not persist", fmt.Errorf(
				"default profile is %q after setting it to %q", got, profileName))
		}

		c.ExitWithMessage(fmt.Sprintf("Set profile %s as default", profileName), cli.ExitCodeSuccess)
	},
}

var profileSetEndpointCmd = &cobra.Command{
	Use:   "set-endpoint <profile> <endpoint>",
	Short: "Set a profile value",
	//nolint:mnd // two args
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)
		profileName := args[0]
		endpoint := args[1]
		profiler := newProfilerFromCLI(c)

		store, err := osprofiles.GetProfile[*profiles.ProfileConfig](profiler, profileName)
		if err != nil {
			cli.ExitWithError("Failed to load profile", err)
		}

		p, ok := store.Profile.(*profiles.ProfileConfig)
		if !ok || p == nil {
			cli.ExitWithError("Failed to load profile", errors.New("invalid profile configuration"))
		}

		u, err := utils.NormalizeEndpoint(endpoint)
		if err != nil {
			c.ExitWithError("Failed to set endpoint", err)
		}

		p.Endpoint = u.String()
		if err := store.Save(); err != nil {
			c.ExitWithError("Failed to set endpoint", err)
		}
		c.ExitWithMessage(fmt.Sprintf("Set endpoint %s for profile %s ", endpoint, profileName), cli.ExitCodeSuccess)
	},
}

var profileSetOutputFormatCmd = &cobra.Command{
	Use:   "set-output-format <profile> <format>",
	Short: "Set the preferred output format for a profile",
	Args:  cobra.ExactArgs(2), //nolint:mnd // ignore argument as magic number, self-explanatory
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)
		profileName := args[0]
		format := args[1]

		if !profiles.IsValidOutputFormat(format) {
			c.ExitWithError("Output format must be either 'styled' or 'json'", nil)
		}

		store, err := profiles.LoadOtdfctlProfileStore(profiles.ProfileDriverFileSystem, profileName)
		if err != nil {
			cli.ExitWithError("Failed to load profile", err)
		}

		if err := store.SetOutputFormat(format); err != nil {
			c.ExitWithError("Failed to set output format", err)
		}
		c.ExitWithSuccess(fmt.Sprintf("Set output format to %s for profile %s", format, profileName))
	},
}

var profileMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate all profiles from keyring to filesystem.",
	Long:  profileMigrationLongDesc,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)
		err := profiles.Migrate(profiles.ProfileDriverFileSystem, profiles.ProfileDriverKeyring)
		if err != nil {
			c.ExitWithError("Failed to migrate", err)
		}
		c.ExitWithMessage("Migration complete.", cli.ExitCodeSuccess)
	},
}

var profileKeyringCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Remove all profiles and configuration from the keyring store. Use when migration fails.",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		c := cli.New(cmd, args)

		force := c.Flags.GetOptionalBool("force")
		cli.ConfirmAction(cli.ActionDelete, "all profiles and configuration stored in the keyring", config.AppName, force)

		keyringProfiler, err := osprofiles.New(config.AppName, osprofiles.WithKeyringStore())
		if err != nil {
			c.ExitWithError("Failed to initialize keyring profile store", err)
		}

		if err := keyringProfiler.Cleanup(force); err != nil {
			cli.ExitWithError(profiles.ErrCleaningUpProfiles.Error(), err)
		}
		c.ExitWithMessage("Keyring profile store cleanup complete", cli.ExitCodeSuccess)
	},
}

func InitProfileCommands() {
	profileCreateCmd.Flags().Bool("set-default", false, "Set the profile as default")
	profileCreateCmd.Flags().Bool("tls-no-verify", false, "Disable TLS verification")
	profileCreateCmd.Flags().String("output-format", profiles.OutputStyled, "Preferred output format: styled or json")

	// Every command resolving a driver through getDriverTypeFromUser must
	// register --store; an unregistered lookup returns "" and silently falls
	// back to the default while rejecting the flag as unknown.
	for _, cmd := range storeFlagCommands() {
		cmd.Flags().String("store", string(profiles.ProfileDriverDefault), storeFlagUsage)
	}
	profileDeleteAllCmd.Flags().Bool("force", false, "Skip confirmation prompt")

	profileSetEndpointCmd.Flags().Bool("tls-no-verify", false, "Disable TLS verification")

	RootCmd.AddCommand(profileCmd)

	profileCmd.AddCommand(profileCreateCmd)
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileGetCmd)
	profileCmd.AddCommand(profileDeleteCmd)
	profileCmd.AddCommand(profileDeleteAllCmd)
	profileCmd.AddCommand(profileSetDefaultCmd)
	profileCmd.AddCommand(profileSetEndpointCmd)
	profileCmd.AddCommand(profileSetOutputFormatCmd)
	profileCmd.AddCommand(profileMigrateCmd)
	profileCmd.AddCommand(profileKeyringCleanupCmd)

	profileKeyringCleanupCmd.Flags().Bool("force", false, "Skip confirmation prompt")
}
