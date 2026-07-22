package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"secure-drive/internal/auth"
	"secure-drive/internal/config"
	"secure-drive/internal/drive"
	"secure-drive/internal/logger"
	"secure-drive/internal/server"
)

func checkMultipleBossAccounts(usersPath string) {
	data, err := os.ReadFile(usersPath)
	if err != nil {
		return
	}

	var rawUsers map[string]struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(data, &rawUsers); err != nil {
		return
	}

	bossCount := 0
	for _, u := range rawUsers {
		if strings.ToLower(u.Role) == "boss" {
			bossCount++
		}
	}

	if bossCount > 1 {
		log.Printf("WARNING: multiple Boss-role accounts detected — each can unlock the drive independently without co-signing")
	}
}

func main() {
	var err error

	// Load configuration
	config.AppConfig, err = config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Startup checks: check DeviceUUID config migration status
	drive.CheckConfigMigration(config.AppConfig)

	// Load users
	err = auth.LoadUsers(config.AppConfig.Users.File)
	if err != nil {
		log.Fatalf("Error loading users: %v", err)
	}

	// Startup checks: verify no multiple boss accounts
	checkMultipleBossAccounts(config.AppConfig.Users.File)

	// Startup checks: verify keyfile integrity (Section 7)
	err = drive.VerifyKeyfileIntegrity(config.AppConfig)
	if err != nil {
		log.Fatalf("Keyfile integrity check failed: %v", err)
	}

	// Setup users and check/initialize secrets if empty
	err = auth.SetupUsers(config.AppConfig.Users.File)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize Logger
	logger.InitLogger(config.AppConfig.Logging.File)

	// Audit log application start
	err = logger.Audit.Log(
		"APPLICATION_START",
		"SYSTEM",
		"SUCCESS",
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("===================================")
	fmt.Println("      Secure Drive Service")
	fmt.Println("===================================")

	fmt.Println("\nDrive Configuration")
	fmt.Println("-------------------")
	fmt.Printf("Device          : %s\n", config.AppConfig.Drive.Device)
	fmt.Printf("Mapper          : %s\n", config.AppConfig.Drive.Mapper)
	fmt.Printf("Mount Point     : %s\n", config.AppConfig.Drive.MountPoint)
	fmt.Printf("Key File        : %s\n", config.AppConfig.Drive.KeyFile)

	fmt.Println("\nSecurity")
	fmt.Println("--------")
	fmt.Printf("Manager Timeout : %d seconds\n", config.GetManagerTimeout())
	fmt.Printf("Auto Lock       : %d seconds\n", config.GetAutoLockTimeout())
	fmt.Printf("Session Timeout : %d seconds\n", config.GetSessionTimeout())

	fmt.Println("\nServer")
	fmt.Println("------")
	fmt.Printf("Port            : %d\n", config.AppConfig.Server.Port)

	fmt.Println("\nLogging")
	fmt.Println("-------")
	fmt.Printf("Audit Log       : %s\n", config.AppConfig.Logging.File)

	fmt.Println("\nUsers")
	fmt.Println("-----")
	fmt.Printf("Boss            : %s\n", auth.AppUsers.Boss.Account)
	fmt.Printf("Manager 1       : %s\n", auth.AppUsers.Manager1.Account)
	fmt.Printf("Manager 2       : %s\n", auth.AppUsers.Manager2.Account)

	if drive.IsMockMode() {
		fmt.Println("\nMode            : [MOCK MODE] (macOS/non-Linux or MOCK_MODE=true)")
	} else {
		fmt.Println("\nMode            : [PRODUCTION MODE]")
	}

	fmt.Println("\nProject setup loaded successfully.")

	// Start the background auto-lock daemon
	drive.StartAutoLockDaemon(config.AppConfig)

	// Start background physical drive watcher daemon (Section 3a)
	drive.StartDeviceWatcher(config.AppConfig)

	// Start the web server
	server.StartServer(config.AppConfig)
}

