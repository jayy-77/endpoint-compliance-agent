// Package config loads agent configuration from a YAML file (or env vars
// when the file is absent), so deployments don't need to recompile to
// change the ML service URL or alerting thresholds.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config groups everything the agent needs at runtime.
type Config struct {
	Mode      string         `yaml:"mode"` // "oneshot" | "streaming"
	Interval  time.Duration  `yaml:"interval"`
	Baseline  BaselineConfig `yaml:"baseline"`
	ML        MLConfig       `yaml:"ml"`
	Alerting  AlertConfig    `yaml:"alerting"`
	Exporter  ExporterConfig `yaml:"exporter"`
}

type BaselineConfig struct {
	Path string `yaml:"path"`
}

type MLConfig struct {
	URL        string        `yaml:"url"`
	Timeout    time.Duration `yaml:"timeout"`
	Threshold  float64       `yaml:"threshold"`
}

type AlertConfig struct {
	OnAnomaly bool `yaml:"on_anomaly"`
}

type ExporterConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

// Default returns the safe defaults used when no config file is provided.
func Default() Config {
	return Config{
		Mode:     "oneshot",
		Interval: 5 * time.Minute,
		Baseline: BaselineConfig{Path: "compliance_baseline.json"},
		ML: MLConfig{
			URL:       envOr("ML_SERVICE_URL", ""),
			Timeout:   2 * time.Second,
			Threshold: 0.7,
		},
		Alerting: AlertConfig{OnAnomaly: true},
		Exporter: ExporterConfig{
			Enabled: envBool("EXPORTER_ENABLED", false),
			Addr:    envOr("EXPORTER_ADDR", ":9100"),
		},
	}
}

// Load reads a YAML file. Missing path returns Default(); unparseable
// file returns an error so the operator notices.
func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
}
