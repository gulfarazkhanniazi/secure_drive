package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

var AppConfig *Config

type Config struct {
	Drive struct {
		Device     string `yaml:"device"`
		Mapper     string `yaml:"mapper"`
		MountPoint string `yaml:"mountPoint"`
		KeyFile    string `yaml:"keyFile"`
	} `yaml:"drive"`

	Users struct {
		File string `yaml:"file"`
	} `yaml:"users"`

	Security struct {
		ManagerTimeout  int `yaml:"managerTimeout"`
		AutoLockTimeout int `yaml:"autoLockTimeout"`
	} `yaml:"security"`

	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`

	Logging struct {
		File string `yaml:"file"`
	} `yaml:"logging"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
