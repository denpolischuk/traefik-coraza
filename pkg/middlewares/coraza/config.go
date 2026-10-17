// Package coraza provides a native Coraza Web Application Firewall middleware.
//
// This is a research-only integration for this Traefik Proxy tree. It is not
// part of upstream Traefik Proxy.
package coraza

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

const typeName = "Coraza"

// Configuration holds the native Coraza Web Application Firewall configuration.
type Configuration struct {
	// Directives is the list of Coraza/ModSecurity directives to load.
	Directives []string `json:"directives,omitempty" toml:"directives,omitempty" yaml:"directives,omitempty" export:"true"`

	// CRSEnabled mounts the embedded OWASP Core Rule Set filesystem so that
	// directives can include files such as @owasp_crs/REQUEST-901-INITIALIZATION.conf.
	CRSEnabled bool `json:"crsEnabled,omitempty" toml:"crsEnabled,omitempty" yaml:"crsEnabled,omitempty" export:"true"`
}

// UnmarshalJSON accepts both JSON booleans and string-encoded booleans for
// crsEnabled, because the dynamic configuration providers may stringify
// plugin values. It also accepts a single string for directives.
func (c *Configuration) UnmarshalJSON(data []byte) error {
	var raw struct {
		Directives json.RawMessage `json:"directives,omitempty"`
		CRSEnabled any             `json:"crsEnabled,omitempty"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if len(raw.Directives) > 0 {
		if err := json.Unmarshal(raw.Directives, &c.Directives); err != nil {
			var directive string
			if errSingle := json.Unmarshal(raw.Directives, &directive); errSingle != nil {
				return err
			}

			c.Directives = []string{directive}
		}
	}

	switch value := raw.CRSEnabled.(type) {
	case nil:
	case bool:
		c.CRSEnabled = value
	case string:
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid crsEnabled value %q: %w", value, err)
		}

		c.CRSEnabled = enabled
	default:
		return fmt.Errorf("invalid crsEnabled type %T", value)
	}

	return nil
}

// Validate checks the configuration.
func (c Configuration) Validate() error {
	if len(c.Directives) == 0 {
		return errors.New("missing directives values")
	}

	return nil
}

func decodeConfiguration(rawConfig map[string]any) (Configuration, error) {
	var config Configuration

	data, err := json.Marshal(rawConfig)
	if err != nil {
		return Configuration{}, fmt.Errorf("marshaling: %w", err)
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return Configuration{}, fmt.Errorf("unmarshalling: %w", err)
	}

	return config, nil
}
