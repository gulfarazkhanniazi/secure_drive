package drive

import (
	"os"
	"sync"
	"testing"

	"secure-drive/internal/config"
)

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
	err = VerifyKeyfileIntegrity(cfg)
	if err == nil {
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
			err := UnlockDrive(cfg)
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
