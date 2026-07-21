package drive

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"secure-drive/internal/auth"
	"secure-drive/internal/config"
	"secure-drive/internal/logger"
)

var (
	mu                       sync.Mutex
	mockUnlocked             bool
	mockMounted              bool
	unlockTime               time.Time
	mockDeviceExists         = true
	mockMountBusy            = false
	mockFsckFail             = false
	disconnectedUnexpectedly = false

	unlockedBy   string
	unlockedByMu sync.Mutex

	lockReason   string
	lockReasonMu sync.Mutex

	mockUnlockCallsCount     int

	ErrDeviceNotPresent = fmt.Errorf("DEVICE_NOT_PRESENT")
)

func GetMockUnlockCallsCount() int {
	mu.Lock()
	defer mu.Unlock()
	return mockUnlockCallsCount
}

func ResetMockUnlockCallsCount() {
	mu.Lock()
	defer mu.Unlock()
	mockUnlockCallsCount = 0
}

func GetUnlockedBy() string {
	unlockedByMu.Lock()
	defer unlockedByMu.Unlock()
	return unlockedBy
}

func SetUnlockedBy(val string) {
	unlockedByMu.Lock()
	defer unlockedByMu.Unlock()
	unlockedBy = val
}

func GetLockReason() string {
	lockReasonMu.Lock()
	defer lockReasonMu.Unlock()
	return lockReason
}

func SetLockReason(val string) {
	lockReasonMu.Lock()
	defer lockReasonMu.Unlock()
	lockReason = val
}

func FormatLockReason(reason string) string {
	switch reason {
	case "manager1_logout":
		return "Locked automatically — Manager1 logged out"
	case "manager2_logout":
		return "Locked automatically — Manager2 logged out"
	case "manager1_session_expired":
		return "Locked automatically — Manager1 session expired"
	case "manager2_session_expired":
		return "Locked automatically — Manager2 session expired"
	default:
		return ""
	}
}

func IsMockMode() bool {
	if os.Getenv("MOCK_MODE") == "true" {
		return true
	}
	return runtime.GOOS != "linux"
}

func SetMockDeviceExists(exists bool) {
	mu.Lock()
	defer mu.Unlock()
	mockDeviceExists = exists
}

func SetMockMountBusy(busy bool) {
	mu.Lock()
	defer mu.Unlock()
	mockMountBusy = busy
}

func SetMockFsckFail(fail bool) {
	mu.Lock()
	defer mu.Unlock()
	mockFsckFail = fail
}

func IsDisconnectedUnexpectedly() bool {
	mu.Lock()
	defer mu.Unlock()
	return disconnectedUnexpectedly
}

func SetDisconnectedUnexpectedly(val bool) {
	mu.Lock()
	defer mu.Unlock()
	disconnectedUnexpectedly = val
}

func VerifyKeyfileIntegrity(cfg *config.Config) error {
	path := cfg.Drive.KeyFile

	if IsMockMode() {
		// Fallback to local mock keyfile if /etc directory isn't accessible (e.g. on macOS)
		if _, err := os.Stat(path); err != nil {
			localPath := "./mock_keyfile"
			if _, err := os.Stat(localPath); err != nil {
				err := os.WriteFile(localPath, []byte("mock-key-data"), 0600)
				if err != nil {
					return fmt.Errorf("failed to create mock keyfile: %v", err)
				}
			}
			cfg.Drive.KeyFile = localPath
			path = localPath
			log.Printf("[MOCK] Falling back to local mock keyfile: %s\n", path)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("CRITICAL: keyfile missing at %s", path)
		}
		return fmt.Errorf("CRITICAL: failed to stat keyfile: %v", err)
	}

	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		return fmt.Errorf("CRITICAL: keyfile permissions are %o, expected 600 (or stricter) — run: chmod 600 %s", perm, path)
	}

	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		currentUid := uint32(os.Getuid())
		if sys.Uid != 0 && sys.Uid != currentUid {
			return fmt.Errorf("CRITICAL: keyfile is owned by UID %d, must be owned by root (0) or current user (%d)", sys.Uid, currentUid)
		}
	}

	return nil
}

func checkDevicePresence(cfg *config.Config) error {
	if IsMockMode() {
		if !mockDeviceExists {
			return ErrDeviceNotPresent
		}
		return nil
	}

	if _, err := os.Stat(cfg.Drive.Device); err != nil {
		return ErrDeviceNotPresent
	}
	return nil
}

func isMountPointBusy(mountPoint string) (bool, string) {
	if IsMockMode() {
		if mockMountBusy {
			return true, "PID 1234 (mock-process)"
		}
		return false, ""
	}

	cmd := exec.Command("fuser", "-m", mountPoint)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return true, strings.TrimSpace(string(output))
	}
	return false, ""
}

func UnlockDrive(cfg *config.Config, username, userRole string) error {
	mu.Lock()
	defer mu.Unlock()

	// Verify device exists (Section 8 check)
	if err := checkDevicePresence(cfg); err != nil {
		return err
	}

	if strings.ToLower(userRole) == "manager" {
		open, _ := auth.IsManagerGateOpen()
		if !open {
			logger.Audit.Log("ACTION_BLOCKED reason=single_manager_only", username, "FAILURE")
			return fmt.Errorf("Waiting for the other manager to log in")
		}
	}

	if isUnlockedNoLock(cfg) {
		return nil // already unlocked
	}

	if IsMockMode() {
		log.Println("[MOCK] Simulating LUKS unlock and mount operations...")
		if disconnectedUnexpectedly {
			if mockFsckFail {
				logger.Audit.Log("FILESYSTEM_CHECK_FAILED", "SYSTEM", "FAILURE")
				return fmt.Errorf("FILESYSTEM_CHECK_FAILED: mock recovery failure")
			}
			logger.Audit.Log("FILESYSTEM_REPAIRED", "SYSTEM", "SUCCESS")
			disconnectedUnexpectedly = false
		}
		mockUnlocked = true
		mockMounted = true
		unlockTime = time.Now()
		unlockedBy = userRole
		lockReason = ""
		mockUnlockCallsCount++
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

	// 3. E2fsck Auto-recovery check (Section 3c)
	if disconnectedUnexpectedly {
		log.Println("[RECOVERY] Drive reappeared after unexpected disconnect. Running e2fsck on mapper...")
		cmdFsck := exec.Command("e2fsck", "-p", "/dev/mapper/"+cfg.Drive.Mapper)
		outputFsck, fsckErr := cmdFsck.CombinedOutput()
		log.Printf("[RECOVERY] e2fsck output:\n%s\n", string(outputFsck))

		if fsckErr != nil {
			exitCode := -1
			if exitError, ok := fsckErr.(*exec.ExitError); ok {
				exitCode = exitError.ExitCode()
			}
			if exitCode >= 4 || exitCode < 0 {
				exec.Command("cryptsetup", "close", cfg.Drive.Mapper).Run()
				logger.Audit.Log("FILESYSTEM_CHECK_FAILED", "SYSTEM", fmt.Sprintf("exit_code=%d", exitCode))
				return fmt.Errorf("FILESYSTEM_CHECK_FAILED: e2fsck reported unrecoverable errors (exit code %d)", exitCode)
			}
			logger.Audit.Log("FILESYSTEM_REPAIRED", "SYSTEM", "SUCCESS")
		} else {
			logger.Audit.Log("FILESYSTEM_CHECK_PASSED", "SYSTEM", "SUCCESS")
		}
		disconnectedUnexpectedly = false
	}

	// 4. Ensure mount point directory exists
	if err := os.MkdirAll(cfg.Drive.MountPoint, 0755); err != nil {
		exec.Command("cryptsetup", "close", cfg.Drive.Mapper).Run()
		return fmt.Errorf("failed to create mount point directory: %v", err)
	}

	// 5. Mount device
	cmdMount := exec.Command("mount", "/dev/mapper/"+cfg.Drive.Mapper, cfg.Drive.MountPoint)
	outputMount, err := cmdMount.CombinedOutput()
	if err != nil {
		exec.Command("cryptsetup", "close", cfg.Drive.Mapper).Run()
		return fmt.Errorf("mount failed: %v (output: %s)", err, string(outputMount))
	}

	unlockTime = time.Now()
	unlockedBy = userRole
	lockReason = ""
	return nil
}

func LockDrive(cfg *config.Config, username, userRole string) error {
	mu.Lock()
	defer mu.Unlock()

	// Verify device exists (Section 8 check)
	if err := checkDevicePresence(cfg); err != nil {
		return err
	}

	if strings.ToLower(userRole) == "manager" {
		open, _ := auth.IsManagerGateOpen()
		if !open {
			logger.Audit.Log("ACTION_BLOCKED reason=single_manager_only", username, "FAILURE")
			return fmt.Errorf("Waiting for the other manager to log in")
		}
	}

	// Write safety mitigations (Section 3b)
	exec.Command("sync").Run()

	var busy bool
	var handles string
	for i := 0; i < 3; i++ {
		busy, handles = isMountPointBusy(cfg.Drive.MountPoint)
		if !busy {
			break
		}
		log.Printf("[LOCK] Mount point %s is busy (handles: %s). Waiting 1s (retry %d/3)...\n", cfg.Drive.MountPoint, handles, i+1)
		time.Sleep(1 * time.Second)
	}

	if busy {
		log.Printf("WARNING: [LOCK] Mount point %s is still busy: %s\n", cfg.Drive.MountPoint, handles)
		logger.Audit.Log("LOCK_FAIL_BUSY", "SYSTEM", fmt.Sprintf("handles=%s", handles))
		return fmt.Errorf("drive busy: open file handles on %s", cfg.Drive.MountPoint)
	}

	if IsMockMode() {
		log.Println("[MOCK] Simulating LUKS unmount and close operations...")
		mockUnlocked = false
		mockMounted = false
		unlockTime = time.Time{}
		unlockedBy = ""
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
	unlockedBy = ""
	return nil
}

func IsUnlocked(cfg *config.Config) bool {
	mu.Lock()
	defer mu.Unlock()
	return isUnlockedNoLock(cfg)
}

func isUnlockedNoLock(cfg *config.Config) bool {
	if IsMockMode() {
		return mockUnlocked
	}
	status := getDriveStatusNoLock(cfg)
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

			timeout := time.Duration(config.GetAutoLockTimeout()) * time.Second
			if time.Since(ut) >= timeout {
				log.Println("[AUTO-LOCK] Drive has been unlocked longer than timeout. Locking now...")
				err := LockDrive(cfg, "SYSTEM", "SYSTEM")
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

func StartDeviceWatcher(cfg *config.Config) {
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if IsMockMode() {
				mu.Lock()
				active := mockUnlocked || mockMounted
				exists := mockDeviceExists
				alreadyLogged := disconnectedUnexpectedly
				mu.Unlock()

				if active && !exists && !alreadyLogged {
					mu.Lock()
					disconnectedUnexpectedly = true
					mockUnlocked = false
					mockMounted = false
					unlockTime = time.Time{}
					unlockedBy = ""
					mu.Unlock()

					log.Printf("CRITICAL: [MOCK] UNEXPECTED_DEVICE_REMOVAL device=%s mapper_was_active=true\n", cfg.Drive.Device)
					logger.Audit.Log(fmt.Sprintf("UNEXPECTED_DEVICE_REMOVAL device=%s mapper_was_active=true", cfg.Drive.Device), "SYSTEM", "CRITICAL")
					log.Println("[MOCK] Cleaned up mapper state.")
				}
				continue
			}

			// Linux implementation
			mu.Lock()
			// Check if mapper is active
			mapperActive := false
			if _, err := os.Stat("/dev/mapper/" + cfg.Drive.Mapper); err == nil {
				mapperActive = true
			}

			// Check if physical device exists
			deviceExists := false
			if _, err := os.Stat(cfg.Drive.Device); err == nil {
				deviceExists = true
			}

			alreadyLogged := disconnectedUnexpectedly
			mu.Unlock()

			if mapperActive && !deviceExists && !alreadyLogged {
				mu.Lock()
				disconnectedUnexpectedly = true
				unlockedBy = ""
				mu.Unlock()

				log.Printf("CRITICAL: UNEXPECTED_DEVICE_REMOVAL device=%s mapper_was_active=true\n", cfg.Drive.Device)
				logger.Audit.Log(fmt.Sprintf("UNEXPECTED_DEVICE_REMOVAL device=%s mapper_was_active=true", cfg.Drive.Device), "SYSTEM", "CRITICAL")

				// Attempt best-effort cleanup (Section 3a)
				cmdUmount := exec.Command("umount", "-l", cfg.Drive.MountPoint)
				umountErr := cmdUmount.Run()
				log.Printf("[CLEANUP] Lazy umount outcome: %v\n", umountErr)
				logger.Audit.Log(fmt.Sprintf("LAZY_UMOUNT device=%s", cfg.Drive.Device), "SYSTEM", fmt.Sprintf("OUTCOME=%v", umountErr))

				cmdDm := exec.Command("dmsetup", "remove", cfg.Drive.Mapper)
				dmErr := cmdDm.Run()
				log.Printf("[CLEANUP] dmsetup remove outcome: %v\n", dmErr)
				logger.Audit.Log(fmt.Sprintf("DMSETUP_REMOVE mapper=%s", cfg.Drive.Mapper), "SYSTEM", fmt.Sprintf("OUTCOME=%v", dmErr))
			}
		}
	}()
}

func WriteFileWithFsync(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}

	return f.Sync()
}
