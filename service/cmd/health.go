package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/cobra"
)

const (
	healthURLFlag     = "url"
	healthServiceFlag = "service"
	healthTimeoutFlag = "timeout"

	defaultHealthURL     = "http://localhost:8080/healthz"
	defaultHealthTimeout = 5 * time.Second
	servingStatus        = "SERVING"
)

// healthClient does not follow redirects: only the configured endpoint may
// report the platform as serving.
var healthClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func init() {
	rootCmd.AddCommand(newHealthCommand())
}

// newHealthCommand checks a running platform through its /healthz endpoint, so
// that container health checks work on images without a shell or HTTP client.
func newHealthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check the health of a running platform",
		Long: `Query the /healthz endpoint of a running platform and exit with a non-zero
status unless it reports SERVING. Meant for container health checks, which
need a command to run inside the image, for instance with Docker Compose:

  healthcheck:
    test: ["CMD", "/usr/bin/opentdf", "health"]`,
		Args: cobra.NoArgs,
		// A failing check is routine for a health check: no usage text.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			endpoint, err := cmd.Flags().GetString(healthURLFlag)
			if err != nil {
				return err
			}
			service, err := cmd.Flags().GetString(healthServiceFlag)
			if err != nil {
				return err
			}
			timeout, err := cmd.Flags().GetDuration(healthTimeoutFlag)
			if err != nil {
				return err
			}
			status, err := checkHealth(cmd.Context(), endpoint, service, timeout)
			if err != nil {
				return err
			}
			cmd.Println(status)
			return nil
		},
	}
	cmd.Flags().String(healthURLFlag, defaultHealthURL, "health endpoint of the platform")
	cmd.Flags().String(healthServiceFlag, "", `service to check: empty for liveness, "all" for the readiness of every service`)
	cmd.Flags().Duration(healthTimeoutFlag, defaultHealthTimeout, "time to wait for the answer")
	return cmd
}

// checkHealth returns the status reported by the endpoint, or an error unless
// the platform answers 200 with the SERVING status.
func checkHealth(ctx context.Context, endpoint, service string, timeout time.Duration) (string, error) {
	target, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid health endpoint %q: %w", endpoint, err)
	}
	// The flag decides the check, whatever the endpoint's query says: without
	// a service, liveness.
	query := target.Query()
	if service != "" {
		query.Set("service", service)
	} else {
		query.Del("service")
	}
	target.RawQuery = query.Encode()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", fmt.Errorf("invalid health request: %w", err)
	}
	resp, err := healthClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("unexpected health answer (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || body.Status != servingStatus {
		return "", fmt.Errorf("platform is not serving: status %q (HTTP %d)", body.Status, resp.StatusCode)
	}
	return body.Status, nil
}
