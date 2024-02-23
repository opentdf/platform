package version

import "github.com/opentdf/platform/kas/internal/conf"

type Stat struct {
	Version     string `json:"version"`
	VersionLong string `json:"versionLong"`
	BuildTime   string `json:"buildTime"`
}

func GetVersion() Stat {
	conf.VersionLong = conf.Version + "+" + conf.Sha1
	return Stat{
		Version:     conf.Version,
		VersionLong: conf.VersionLong,
		BuildTime:   conf.BuildTime,
	}
}
