package main

import (
	"fmt"
	"log"

	"secure-drive/internal/auth"
	"secure-drive/internal/config"
	"secure-drive/internal/drive"
	"secure-drive/internal/logger"
	"secure-drive/internal/server"
)

func main() {
	var err error

	// Load configuration
	config.AppConfig, err = config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Load users
	err = auth.LoadUsers(config.AppConfig.Users.File)
	if err != nil {
		log.Fatalf("Error loading users: %v", err)
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
	fmt.Printf("Manager Timeout : %d seconds\n", config.AppConfig.Security.ManagerTimeout)
	fmt.Printf("Auto Lock       : %d seconds\n", config.AppConfig.Security.AutoLockTimeout)

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

	// Start the web server
	server.StartServer(config.AppConfig)
}
