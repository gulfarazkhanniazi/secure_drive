package drive

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"secure-drive/internal/config"
	"secure-drive/internal/logger"
)

var (
	mu           sync.Mutex
	mockUnlocked bool
	mockMounted  bool
	unlockTime   time.Time
)

func IsMockMode() bool {
	if os.Getenv("MOCK_MODE") == "true" {
		return true
	}
	return runtime.GOOS != "linux"
}

func UnlockDrive(cfg *config.Config) error {
	mu.Lock()
	defer mu.Unlock()

	if IsMockMode() {
		log.Println("[MOCK] Simulating LUKS unlock and mount operations...")
		mockUnlocked = true
		mockMounted = true
		unlockTime = time.Now()
		return nil
	}

	// 1. Verify keyfile exists
	if _, err := os.Stat(cfg.Drive.KeyFile); err != nil {
		return fmt.Errorf("keyfile not found: %s. error: %v", cfg.Drive.KeyFile, err)
	}

	// 2. Open LUKS partition
	cmdOpen := exec.Command("cryptsetup", "open", "--type", "luks", cfg.Drive.Device, cfg.Drive.Mapper, "--key-file", cfg.Drive.KeyFile)
	outputOpen, err := cmdOpen.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cryptsetup open failed: %v (output: %s)", err, string(outputOpen))
	}

	// 3. Ensure mount point directory exists
	if err := os.MkdirAll(cfg.Drive.MountPoint, 0755); err != nil {
		// Rollback open
		exec.Command("cryptsetup", "close", cfg.Drive.Mapper).Run()
		return fmt.Errorf("failed to create mount point directory: %v", err)
	}

	// 4. Mount device
	cmdMount := exec.Command("mount", "/dev/mapper/"+cfg.Drive.Mapper, cfg.Drive.MountPoint)
	outputMount, err := cmdMount.CombinedOutput()
	if err != nil {
		// Rollback open
		exec.Command("cryptsetup", "close", cfg.Drive.Mapper).Run()
		return fmt.Errorf("mount failed: %v (output: %s)", err, string(outputMount))
	}

	unlockTime = time.Now()
	return nil
}

func LockDrive(cfg *config.Config) error {
	mu.Lock()
	defer mu.Unlock()

	if IsMockMode() {
		log.Println("[MOCK] Simulating LUKS unmount and close operations...")
		mockUnlocked = false
		mockMounted = false
		unlockTime = time.Time{}
		return nil
	}

	// 1. Unmount device
	cmdUmount := exec.Command("umount", cfg.Drive.MountPoint)
	outputUmount, err := cmdUmount.CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount failed: %v (output: %s)", err, string(outputUmount))
	}

	// 2. Close LUKS partition
	cmdClose := exec.Command("cryptsetup", "close", cfg.Drive.Mapper)
	outputClose, err := cmdClose.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cryptsetup close failed: %v (output: %s)", err, string(outputClose))
	}

	unlockTime = time.Time{}
	return nil
}

func IsUnlocked(cfg *config.Config) bool {
	if IsMockMode() {
		mu.Lock()
		defer mu.Unlock()
		return mockUnlocked
	}
	status := GetDriveStatus(cfg)
	return status.MapperOpen && status.Mounted
}

func GetUnlockTime() time.Time {
	mu.Lock()
	defer mu.Unlock()
	return unlockTime
}

func StartAutoLockDaemon(cfg *config.Config) {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if !IsUnlocked(cfg) {
				continue
			}

			ut := GetUnlockTime()
			if ut.IsZero() {
				continue
			}

			timeout := time.Duration(cfg.Security.AutoLockTimeout) * time.Second
			if time.Since(ut) >= timeout {
				log.Println("[AUTO-LOCK] Drive has been unlocked longer than timeout. Locking now...")
				err := LockDrive(cfg)
				if err != nil {
					log.Printf("[AUTO-LOCK] Error locking drive: %v\n", err)
					logger.Audit.Log("AUTO_LOCK_FAIL", "SYSTEM", "FAILURE")
				} else {
					log.Println("[AUTO-LOCK] Drive successfully locked.")
					logger.Audit.Log("AUTO_LOCK", "SYSTEM", "SUCCESS")
				}
			}
		}
	}()
}
