package config

import (
	"encoding/json"
	"fmt"
	"monitor-blocker/domain/blocker"
	"monitor-blocker/domain/monitor"
	"os"
)

var Props config

type config struct {
	Monitors []monitor.MonitorConfig
	Blockers []blocker.BlockerConfig
}

func Load(configPath string) error {
	f, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("open config failed. Error: %w", err)
	}
	err = json.NewDecoder(f).Decode(&Props)
	if err != nil {
		return fmt.Errorf("load config failed. Error: %w", err)
	}
	return nil
}
