package profiles

import (
	"errors"

	osprofiles "github.com/jrschumacher/go-osprofiles"
	"github.com/opentdf/platform/otdfctl/pkg/utils"
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
	AuthCredentials AuthCredentials `json:"authCredentials"`
}

func (pc *ProfileConfig) GetName() string {
	return pc.Name
}

func NewOtdfctlProfileStore(storeType ProfileDriver, config *ProfileConfig, setDefault bool) (*OtdfctlProfileStore, error) {
	profiler, err := CreateProfiler(storeType)
	if err != nil {
		return nil, err
	}

	u, err := utils.NormalizeEndpoint(config.Endpoint)
	if err != nil {
		return nil, err
	}

	p := &ProfileConfig{
		Name:        config.Name,
		Endpoint:    u.String(),
		TLSNoVerify: config.TLSNoVerify,
	}
	err = profiler.AddProfile(p, setDefault)
	if err != nil {
		return nil, err
	}

	store, err := osprofiles.UseProfile[*ProfileConfig](profiler, config.Name)
	if err != nil {
		return nil, err
	}

	// Cast Profile to ProfileConfig
	pc, ok := store.Profile.(*ProfileConfig)
	if !ok {
		return nil, errors.Join(ErrProfileIncorrectType, err)
	}

	return &OtdfctlProfileStore{
		store:    *store,
		config:   pc,
		profiler: profiler,
	}, nil
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

	return &OtdfctlProfileStore{
		store:    *store,
		config:   pc,
		profiler: profiler,
	}, nil
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

func (p *OtdfctlProfileStore) Name() string {
	return p.config.Name
}

func (p *OtdfctlProfileStore) IsDefault() bool {
	return p.Name() == osprofiles.GetGlobalConfig(p.profiler).GetDefaultProfile()
}
