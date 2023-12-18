package credentials

import "os"

type Credential struct {
	FromEnv       string `yaml:"fromEnv,omitempty"`
	FromK8sSecret string `yaml:"fromK8sSecret,omitempty"`
}

func (c Credential) Get() string {
	if c.FromEnv != "" {
		return os.Getenv(c.FromEnv)
	}
	return ""
}
