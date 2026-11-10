package cukes

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestPlatformHTTPWriteTimeoutIsOptIn(t *testing.T) {
	for _, timeout := range []time.Duration{0, 35 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			configPath, err := createPlatformConfiguration(
				&LocalDevOptions{CukesDir: t.TempDir()}, &LocalDevScenarioOptions{}, true, nil, nil, timeout,
			)
			require.NoError(t, err)
			data, err := os.ReadFile(configPath)
			require.NoError(t, err)
			var config struct {
				Server struct {
					HTTP *struct {
						WriteTimeout string `yaml:"writeTimeout"`
					} `yaml:"http"`
				} `yaml:"server"`
			}
			require.NoError(t, yaml.Unmarshal(data, &config))
			if timeout == 0 {
				require.Nil(t, config.Server.HTTP, "ordinary scenarios must retain the production default")
			} else {
				require.NotNil(t, config.Server.HTTP)
				require.Equal(t, timeout.String(), config.Server.HTTP.WriteTimeout)
			}
		})
	}
}
