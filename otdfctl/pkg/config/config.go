package config

var (
	// Name of the publisher (PascalCase for when it is used in the UI and file system directory names)
	ServicePublisher = "VirtruCorporation"
	// AppName is the name of the application
	// Note: use caution when renaming as it is used in various places within the CLI including for
	// config file naming and in the profile store
	AppName = "otdfctl"

	Version   = "0.29.0" // x-release-please-version
	BuildTime = "1970-01-01T00:00:00Z"
	CommitSha = "0000000"

	// Test mode is used to determine if the application is running in test mode
	//   "true" = running in test mode
	TestMode = ""

	// Test terminal size is a runtime env var to allow for testing of terminal output
	TestTerminalWidth = "TEST_TERMINAL_WIDTH"
)
