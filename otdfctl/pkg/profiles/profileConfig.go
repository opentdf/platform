package profiles

import (
	"errors"
	"strings"

	osprofiles "github.com/jrschumacher/go-osprofiles"
	"github.com/opentdf/otdfctl/pkg/utils"
)

const (
	OutputJSON   = "json"
	OutputStyled = "styled"
)

type OtdfctlProfileStore struct {
	store    osprofiles.ProfileStore
	config   *ProfileConfig // Pointer to the store.Profile field
	profiler *osprofiles.Profiler
}

type ProfileConfig struct {
	Name            string          `json:"profile"`
	Endpoint        string          `json:"endpoint"`
	TLSNoVerify     bool            `json:"tlsNoVerify"`
	OutputFormat    string          `json:"outputFormat,omitempty"`
	AuthCredentials AuthCredentials `json:"authCredentials"`
}

func (pc *ProfileConfig) GetName() string {
	return pc.Name
}

func NewOtdfctlProfileStore(storeType ProfileDriver, cfg *ProfileConfig, setDefault bool) (*OtdfctlProfileStore, error) {
	if cfg == nil {
		return nil, ErrProfileConfigEmpty
	}

	profiler, err := CreateProfiler(storeType)
	if err != nil {
		return nil, err
	}

	u, err := utils.NormalizeEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	p := &ProfileConfig{
		Name:         cfg.Name,
		Endpoint:     u.String(),
		TLSNoVerify:  cfg.TLSNoVerify,
		OutputFormat: NormalizeOutputFormat(cfg.OutputFormat),
	}
	err = profiler.AddProfile(p, setDefault)
	if err != nil {
		return nil, err
	}

	store, err := osprofiles.UseProfile[*ProfileConfig](profiler, cfg.Name)
	if err != nil {
		return nil, err
	}

	// Cast Profile to ProfileConfig
	pc, ok := store.Profile.(*ProfileConfig)
	if !ok {
		return nil, errors.Join(ErrProfileIncorrectType, err)
	}

	return newProfileStore(profiler, store, pc), nil
}

func LoadOtdfctlProfileStore(storeType ProfileDriver, profileName string) (*OtdfctlProfileStore, error) {
	profiler, err := CreateProfiler(storeType)
	if err != nil {
		return nil, err
	}

	store, err := osprofiles.GetProfile[*ProfileConfig](profiler, profileName)
	if err != nil {
		return nil, err
	}

	pc, ok := store.Profile.(*ProfileConfig)
	if !ok {
		return nil, errors.Join(ErrProfileIncorrectType, err)
	}

	return newProfileStore(profiler, store, pc), nil
}

func newProfileStore(profiler *osprofiles.Profiler, store *osprofiles.ProfileStore, pc *ProfileConfig) *OtdfctlProfileStore {
	ensureProfileDefaults(pc)
	return &OtdfctlProfileStore{
		store:    *store,
		config:   pc,
		profiler: profiler,
	}
}

func ensureProfileDefaults(pc *ProfileConfig) {
	if pc == nil {
		return
	}
	pc.OutputFormat = NormalizeOutputFormat(pc.OutputFormat)
}

func (p *OtdfctlProfileStore) GetEndpoint() string {
	return p.config.Endpoint
}

func (p *OtdfctlProfileStore) SetEndpoint(endpoint string) error {
	u, err := utils.NormalizeEndpoint(endpoint)
	if err != nil {
		return err
	}

	p.config.Endpoint = u.String()
	return p.store.Save()
}

func (p *OtdfctlProfileStore) GetTLSNoVerify() bool {
	return p.config.TLSNoVerify
}

func (p *OtdfctlProfileStore) SetTLSNoVerify(tlsNoVerify bool) error {
	p.config.TLSNoVerify = tlsNoVerify
	return p.store.Save()
}

func (p *OtdfctlProfileStore) GetOutputFormat() string {
	return NormalizeOutputFormat(p.config.OutputFormat)
}

func (p *OtdfctlProfileStore) SetOutputFormat(format string) error {
	p.config.OutputFormat = NormalizeOutputFormat(format)
	return p.store.Save()
}

func (p *OtdfctlProfileStore) Name() string {
	return p.config.Name
}

func (p *OtdfctlProfileStore) IsDefault() bool {
	return p.Name() == osprofiles.GetGlobalConfig(p.profiler).GetDefaultProfile()
}

// NormalizeOutputFormat returns a supported output format. Any unknown value defaults to styled output.
func NormalizeOutputFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case OutputJSON:
		return OutputJSON
	default:
		return OutputStyled
	}
}

// IsValidOutputFormat reports whether the provided format string is supported.
func IsValidOutputFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case OutputJSON, OutputStyled:
		return true
	default:
		return false
	}
}
