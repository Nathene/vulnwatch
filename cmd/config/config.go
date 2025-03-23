package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Version   string
	Database  Database
	LocalRoot string
	Scanning  ScanConfig
}

// Database holds database configuration
type Database struct {
	Driver string
	DSN    string
}

// ScanConfig holds scanning related configuration
type ScanConfig struct {
	SkipUnchanged bool          // Whether to skip unchanged modules
	ScanInterval  time.Duration // How often to scan modules
}

var (
	config *Config
	v      *viper.Viper
)

// initDefaults sets up the default configuration values
func initDefaults(v *viper.Viper) {
	// Version defaults
	v.SetDefault("version", "0.0.1")

	// Database defaults
	v.SetDefault("database.driver", "sqlite")
	v.SetDefault("database.dsn", "vulnwatch.db")

	// Local root defaults to ~/Documents/dev
	homeDir, _ := os.UserHomeDir()
	defaultRoot := filepath.Join(homeDir, "Documents", "dev")
	v.SetDefault("localroot", defaultRoot)

	// Scanning defaults
	v.SetDefault("scanning.skipunchanged", true)
	v.SetDefault("scanning.scaninterval", "24h")
}

// loadFromFile attempts to load configuration from a file
func loadFromFile(v *viper.Viper) error {
	// Look for config in the config directory
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.vulnwatch")
	v.AddConfigPath("/etc/vulnwatch")

	// Set the name of the config file (without extension)
	v.SetConfigName("config")

	// Viper supports multiple formats
	v.SetConfigType("yaml") // you can also specify "json", "toml", etc.

	// Read from config file if it exists
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, let's create a default one
			configDir := "$HOME/.vulnwatch"
			configDir = os.ExpandEnv(configDir)

			if err := os.MkdirAll(configDir, 0755); err != nil {
				return fmt.Errorf("could not create config directory: %w", err)
			}

			configFile := filepath.Join(configDir, "config.yaml")
			return v.WriteConfigAs(configFile)
		}
		return fmt.Errorf("error reading config file: %w", err)
	}
	return nil
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(v *viper.Viper) {
	// Enable environment variable overrides
	v.AutomaticEnv()

	// Map environment variables to config keys
	v.SetEnvPrefix("VULNWATCH") // Prefix for environment variables

	// Replace dots with underscores in environment variables
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Load from .env file if it exists
	_ = v.BindEnv("version", "VERSION")
	_ = v.BindEnv("database.driver", "DATABASE_DRIVER")
	_ = v.BindEnv("database.dsn", "DATABASE_DSN")
	_ = v.BindEnv("localroot", "LOCAL_ROOT")
	_ = v.BindEnv("scanning.skipunchanged", "SCANNING_SKIP_UNCHANGED")
	_ = v.BindEnv("scanning.scaninterval", "SCANNING_INTERVAL")
}

// mapToConfig maps viper values to the Config struct
func mapToConfig(v *viper.Viper) (*Config, error) {
	// Parse the scan interval
	scanIntervalStr := v.GetString("scanning.scaninterval")
	scanInterval, err := time.ParseDuration(scanIntervalStr)
	if err != nil {
		scanInterval = 24 * time.Hour // Default to 24 hours
	}

	// Expand ~ in localroot if needed
	localRoot := v.GetString("localroot")
	if strings.HasPrefix(localRoot, "~") {
		homeDir, _ := os.UserHomeDir()
		localRoot = strings.Replace(localRoot, "~", homeDir, 1)
	}

	return &Config{
		Version: v.GetString("version"),
		Database: Database{
			Driver: v.GetString("database.driver"),
			DSN:    v.GetString("database.dsn"),
		},
		LocalRoot: localRoot,
		Scanning: ScanConfig{
			SkipUnchanged: v.GetBool("scanning.skipunchanged"),
			ScanInterval:  scanInterval,
		},
	}, nil
}

// initialize initializes the configuration
func initialize() error {
	v = viper.New()

	// Set default values
	initDefaults(v)

	// Try to load from config file
	if err := loadFromFile(v); err != nil {
		fmt.Printf("Warning: %v\n", err)
		// Continue even if we can't load from file
	}

	// Load from environment variables
	loadFromEnv(v)

	// Map viper values to our Config struct
	var err error
	config, err = mapToConfig(v)
	return err
}

// Use returns the configuration singleton
func Use() *Config {
	if config == nil {
		if err := initialize(); err != nil {
			log.Fatalf("failed to initialize configuration: %w", err)
		}
	}
	return config
}

// SaveConfig saves the current configuration to file
func SaveConfig() error {
	if v == nil {
		return fmt.Errorf("configuration not initialized")
	}
	return v.WriteConfig()
}

// WatchConfig starts watching the config file for changes
func WatchConfig(onChange func()) {
	if v == nil {
		if err := initialize(); err != nil {
			panic(fmt.Errorf("failed to initialize configuration: %w", err))
		}
	}

	v.WatchConfig()
	v.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
		// Reinitialize the config
		if newConfig, err := mapToConfig(v); err == nil {
			config = newConfig
			if onChange != nil {
				onChange()
			}
		}
	})
}
