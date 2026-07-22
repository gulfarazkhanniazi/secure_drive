package config

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

var (
	AppConfig  *Config
	configMu   sync.RWMutex
	ConfigPath = "config.yaml" // Can be overridden by tests or init
)

type Config struct {
	Drive struct {
		Device     string `yaml:"device"`
		Mapper     string `yaml:"mapper"`
		MountPoint string `yaml:"mountPoint"`
		KeyFile    string `yaml:"keyFile"`
		DeviceUUID string `yaml:"deviceUUID,omitempty"`
	} `yaml:"drive"`

	Users struct {
		File string `yaml:"file"`
	} `yaml:"users"`

	Security struct {
		ManagerTimeout  int `yaml:"managerTimeout"`
		AutoLockTimeout int `yaml:"autoLockTimeout"`
		SessionTimeout  int `yaml:"sessionTimeout"`
	} `yaml:"security"`

	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`

	Logging struct {
		File string `yaml:"file"`
	} `yaml:"logging"`
}

func LoadConfig(path string) (*Config, error) {
	configMu.Lock()
	defer configMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	// Default session timeout to 900 seconds (15 mins) if not specified or invalid
	if cfg.Security.SessionTimeout <= 0 {
		cfg.Security.SessionTimeout = 900
	}

	return &cfg, nil
}

func GetAutoLockTimeout() int {
	configMu.RLock()
	defer configMu.RUnlock()
	if AppConfig == nil || AppConfig.Security.AutoLockTimeout < 60 {
		return 600 // fallback default
	}
	return AppConfig.Security.AutoLockTimeout
}

func GetSessionTimeout() int {
	configMu.RLock()
	defer configMu.RUnlock()
	if AppConfig == nil || AppConfig.Security.SessionTimeout < 60 {
		return 900 // fallback default (15 minutes)
	}
	return AppConfig.Security.SessionTimeout
}

func GetManagerTimeout() int {
	configMu.RLock()
	defer configMu.RUnlock()
	if AppConfig == nil || AppConfig.Security.ManagerTimeout <= 0 {
		return 300 // fallback default
	}
	return AppConfig.Security.ManagerTimeout
}

func UpdateSecuritySettings(autoLock, session int) (int, int, error) {
	if autoLock < 60 || autoLock > 3600 {
		return 0, 0, fmt.Errorf("auto-lock timeout must be between 60 and 3600 seconds")
	}
	if session < 60 || session > 86400 {
		return 0, 0, fmt.Errorf("session timeout must be between 60 and 86400 seconds")
	}

	configMu.Lock()
	defer configMu.Unlock()

	if AppConfig == nil {
		return 0, 0, fmt.Errorf("config not loaded")
	}

	oldAutoLock := AppConfig.Security.AutoLockTimeout
	oldSession := AppConfig.Security.SessionTimeout

	AppConfig.Security.AutoLockTimeout = autoLock
	AppConfig.Security.SessionTimeout = session

	// Safely save the configuration (atomic write)
	data, err := yaml.Marshal(AppConfig)
	if err != nil {
		AppConfig.Security.AutoLockTimeout = oldAutoLock
		AppConfig.Security.SessionTimeout = oldSession
		return 0, 0, fmt.Errorf("failed to marshal config: %v", err)
	}

	tmpPath := ConfigPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		AppConfig.Security.AutoLockTimeout = oldAutoLock
		AppConfig.Security.SessionTimeout = oldSession
		return 0, 0, fmt.Errorf("failed to write temp config: %v", err)
	}

	if err := os.Rename(tmpPath, ConfigPath); err != nil {
		AppConfig.Security.AutoLockTimeout = oldAutoLock
		AppConfig.Security.SessionTimeout = oldSession
		return 0, 0, fmt.Errorf("failed to rename temp config: %v", err)
	}

	return oldAutoLock, oldSession, nil
}

func UpdateDriveConfig(device, mapper, mountPoint, keyFile, deviceUUID string) error {
	configMu.Lock()
	defer configMu.Unlock()

	if AppConfig == nil {
		AppConfig = &Config{}
	}

	oldDev := AppConfig.Drive.Device
	oldMapper := AppConfig.Drive.Mapper
	oldMount := AppConfig.Drive.MountPoint
	oldKey := AppConfig.Drive.KeyFile
	oldUUID := AppConfig.Drive.DeviceUUID

	AppConfig.Drive.Device = device
	AppConfig.Drive.Mapper = mapper
	AppConfig.Drive.MountPoint = mountPoint
	if keyFile != "" {
		AppConfig.Drive.KeyFile = keyFile
	}
	if deviceUUID != "" {
		AppConfig.Drive.DeviceUUID = deviceUUID
	}

	data, err := yaml.Marshal(AppConfig)
	if err != nil {
		AppConfig.Drive.Device = oldDev
		AppConfig.Drive.Mapper = oldMapper
		AppConfig.Drive.MountPoint = oldMount
		AppConfig.Drive.KeyFile = oldKey
		AppConfig.Drive.DeviceUUID = oldUUID
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	tmpPath := ConfigPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		AppConfig.Drive.Device = oldDev
		AppConfig.Drive.Mapper = oldMapper
		AppConfig.Drive.MountPoint = oldMount
		AppConfig.Drive.KeyFile = oldKey
		AppConfig.Drive.DeviceUUID = oldUUID
		return fmt.Errorf("failed to write temp config: %v", err)
	}

	if err := os.Rename(tmpPath, ConfigPath); err != nil {
		AppConfig.Drive.Device = oldDev
		AppConfig.Drive.Mapper = oldMapper
		AppConfig.Drive.MountPoint = oldMount
		AppConfig.Drive.KeyFile = oldKey
		AppConfig.Drive.DeviceUUID = oldUUID
		return fmt.Errorf("failed to rename temp config: %v", err)
	}

	return nil
}

