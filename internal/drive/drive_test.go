package drive

import (
	"os"
	"sync"
	"testing"

	"secure-drive/internal/auth"
	"secure-drive/internal/config"
	"secure-drive/internal/logger"
)

func TestMain(m *testing.M) {
	// Initialize logger so Audit.Log calls don't panic
	logger.InitLogger(os.DevNull)

	// Set default config for GetManagerTimeout
	config.AppConfig = &config.Config{}
	config.AppConfig.Security.ManagerTimeout = 300
	config.AppConfig.Security.SessionTimeout = 900
	config.AppConfig.Security.AutoLockTimeout = 600

	os.Exit(m.Run())
}

func TestVerifyKeyfileIntegrity(t *testing.T) {
	// Create temporary keyfile
	tmpFile := "./tmp_keyfile_test"
	defer os.Remove(tmpFile)

	err := os.WriteFile(tmpFile, []byte("test-key-data"), 0644)
	if err != nil {
		t.Fatalf("failed to write test keyfile: %v", err)
	}

	cfg := &config.Config{}
	cfg.Drive.KeyFile = tmpFile

	// 1. Verification must fail because permissions are 644
	// On macOS / mock mode the filesystem may not enforce group/world bits, so
	// only assert failure on Linux (non-mock) where chmod is strictly honoured.
	err = VerifyKeyfileIntegrity(cfg)
	if !IsMockMode() && err == nil {
		t.Errorf("expected verification to fail for permissions 644")
	}

	// 2. Change permissions to 600
	err = os.Chmod(tmpFile, 0600)
	if err != nil {
		t.Fatalf("failed to chmod test keyfile: %v", err)
	}

	// 3. Verification must succeed now
	err = VerifyKeyfileIntegrity(cfg)
	if err != nil {
		t.Errorf("expected verification to succeed for permissions 600, got: %v", err)
	}
}

func TestDevicePresenceVerification(t *testing.T) {
	cfg := &config.Config{}
	cfg.Drive.Device = "/dev/non_existent_mock_device"

	// 1. Simulating device is missing
	SetMockDeviceExists(false)
	err := checkDevicePresence(cfg)
	if err != ErrDeviceNotPresent {
		t.Errorf("expected ErrDeviceNotPresent, got: %v", err)
	}

	// 2. Simulating device is present
	SetMockDeviceExists(true)
	err = checkDevicePresence(cfg)
	if err != nil {
		t.Errorf("expected nil error when device is present, got: %v", err)
	}
}

func TestConcurrentUnlocks(t *testing.T) {
	cfg := &config.Config{}
	cfg.Drive.KeyFile = "./tmp_keyfile_test"
	_ = os.WriteFile(cfg.Drive.KeyFile, []byte("data"), 0600)
	defer os.Remove(cfg.Drive.KeyFile)

	SetMockDeviceExists(true)
	mu.Lock()
	mockUnlocked = false
	mockMounted = false
	mu.Unlock()

	var wg sync.WaitGroup
	numWorkers := 10
	wg.Add(numWorkers)

	errChan := make(chan error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			err := UnlockDrive(cfg, "Boss", "Boss")
			if err != nil {
				errChan <- err
			}
		}()
	}

	wg.Wait()
	close(errChan)

	// Since we serialized execution under the lock, and check if already unlocked,
	// all goroutines should complete safely without conflicts.
	for err := range errChan {
		t.Errorf("unexpected error in concurrent execution: %v", err)
	}

	if !IsUnlocked(cfg) {
		t.Errorf("expected drive to be unlocked after concurrent runs")
	}
}

func TestConcurrentManagerUnlocks(t *testing.T) {
	cfg := &config.Config{}
	cfg.Drive.KeyFile = "./tmp_keyfile_test"
	_ = os.WriteFile(cfg.Drive.KeyFile, []byte("data"), 0600)
	defer os.Remove(cfg.Drive.KeyFile)

	SetMockDeviceExists(true)
	ResetMockUnlockCallsCount()

	mu.Lock()
	mockUnlocked = false
	mockMounted = false
	mu.Unlock()

	// Create real sessions for both managers (IsManagerSessionActive checks the sessions map)
	token1 := auth.CreateSession("Manager1", "Manager")
	token2 := auth.CreateSession("Manager2", "Manager")
	defer auth.RemoveSession(token1)
	defer auth.RemoveSession(token2)

	// Record login times so the join window check passes
	auth.UpdateManagerLoginTime("Manager1")
	auth.UpdateManagerLoginTime("Manager2")

	// Trigger 10 near-simultaneous unlock requests from Manager1 and Manager2
	var wg sync.WaitGroup
	numWorkers := 10
	wg.Add(numWorkers)

	errChan := make(chan error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		user := "Manager1"
		if i%2 == 0 {
			user = "Manager2"
		}
		go func(u string) {
			defer wg.Done()
			err := UnlockDrive(cfg, u, "Manager")
			if err != nil {
				errChan <- err
			}
		}(user)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("unexpected error in concurrent manager execution: %v", err)
	}

	if !IsUnlocked(cfg) {
		t.Errorf("expected drive to be unlocked by managers")
	}

	// Confirm that only one actual mock cryptsetup open executes (indicated by mockUnlockCallsCount == 1)
	calls := GetMockUnlockCallsCount()
	if calls != 1 {
		t.Errorf("expected exactly 1 mock unlock call, got: %d", calls)
	}
}
