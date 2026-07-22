package drive

import (
	"os"
	"testing"
	"time"

	"secure-drive/internal/config"
	"secure-drive/internal/logger"
)

func TestDetectPartitionName(t *testing.T) {
	tests := []struct {
		device   string
		expected string
	}{
		{"/dev/sdb", "/dev/sdb1"},
		{"/dev/sdc", "/dev/sdc1"},
		{"/dev/nvme0n1", "/dev/nvme0n1p1"},
		{"/dev/nvme1n1", "/dev/nvme1n1p1"},
		{"/dev/mmcblk0", "/dev/mmcblk0p1"},
	}

	for _, tt := range tests {
		got := DetectPartitionName(tt.device)
		if got != tt.expected {
			t.Errorf("DetectPartitionName(%q) = %q; want %q", tt.device, got, tt.expected)
		}
	}
}

func TestValidationRules(t *testing.T) {
	// Passphrase length
	if err := ValidatePassphraseStrength([]byte("short")); err == nil {
		t.Errorf("expected error for short passphrase (<12 chars)")
	}
	if err := ValidatePassphraseStrength([]byte("strongpassphrase123")); err != nil {
		t.Errorf("unexpected error for strong passphrase: %v", err)
	}

	// Device path sanitization
	if err := ValidateDevicePath("/dev/sdb"); err != nil {
		t.Errorf("unexpected error for valid path /dev/sdb: %v", err)
	}
	if err := ValidateDevicePath("/dev/nvme0n1"); err != nil {
		t.Errorf("unexpected error for valid path /dev/nvme0n1: %v", err)
	}
	if err := ValidateDevicePath("/dev/../etc/passwd"); err == nil {
		t.Errorf("expected error for path traversal /dev/../etc/passwd")
	}
	if err := ValidateDevicePath("; rm -rf /"); err == nil {
		t.Errorf("expected error for command injection attempt")
	}
}

func TestGetCandidateDrivesMock(t *testing.T) {
	cfg := &config.Config{}
	cfg.Drive.Device = "/dev/sda1"

	candidates, err := GetCandidateDrives(cfg)
	if err != nil {
		t.Fatalf("GetCandidateDrives failed in mock mode: %v", err)
	}

	if len(candidates) < 2 {
		t.Fatalf("expected at least 2 mock candidate drives, got %d", len(candidates))
	}

	// First candidate /dev/sdb should be empty
	if candidates[0].Name != "/dev/sdb" || !candidates[0].IsEmpty {
		t.Errorf("expected candidate /dev/sdb to be empty, got: %+v", candidates[0])
	}

	// Second candidate /dev/sdc should be non-empty
	if candidates[1].Name != "/dev/sdc" || candidates[1].IsEmpty {
		t.Errorf("expected candidate /dev/sdc to be not empty, got: %+v", candidates[1])
	}
}

func TestMockOnboardingPipelineSuccess(t *testing.T) {
	logger.InitLogger(os.DevNull)

	config.AppConfig = &config.Config{}
	config.AppConfig.Drive.Device = "/dev/sdb1"

	req := OnboardRequest{
		Device:             "/dev/sdb",
		ConfirmationDevice: "/dev/sdb",
		ConfirmedCheckbox:  true,
		Passphrase:         []byte("SuperSecretPassphrase123!"),
		PassphraseConfirm:  []byte("SuperSecretPassphrase123!"),
		MapperName:         "test-mapper",
		MountPoint:         "/mnt/test-secure",
	}

	err := RunOnboardingPipeline(config.AppConfig, req, "Boss")
	if err != nil {
		t.Fatalf("RunOnboardingPipeline failed: %v", err)
	}

	// Wait for async pipeline execution to complete in mock mode (14 steps * 100ms)
	time.Sleep(2 * time.Second)

	status := GetOnboardingStatus()
	if status.Status != "SUCCESS" {
		t.Errorf("expected status SUCCESS, got %s (err: %s)", status.Status, status.ErrorDetails)
	}

	if status.CurrentStep != 14 {
		t.Errorf("expected CurrentStep 14, got %d", status.CurrentStep)
	}

	if len(status.Steps) != 14 {
		t.Errorf("expected 14 step results, got %d", len(status.Steps))
	}

	if config.AppConfig.Drive.Device != "/dev/sdb1" {
		t.Errorf("expected config device /dev/sdb1, got %s", config.AppConfig.Drive.Device)
	}
}

func TestMockOnboardingPipelineRejections(t *testing.T) {
	logger.InitLogger(os.DevNull)
	cfg := &config.Config{}

	// 1. Device confirmation mismatch
	req1 := OnboardRequest{
		Device:             "/dev/sdb",
		ConfirmationDevice: "/dev/sdc",
		ConfirmedCheckbox:  true,
		Passphrase:         []byte("SuperSecretPassphrase123!"),
		PassphraseConfirm:  []byte("SuperSecretPassphrase123!"),
	}
	if err := RunOnboardingPipeline(cfg, req1, "Boss"); err == nil {
		t.Errorf("expected error when confirmation device path mismatches")
	}

	// 2. Unchecked checkbox
	req2 := OnboardRequest{
		Device:             "/dev/sdb",
		ConfirmationDevice: "/dev/sdb",
		ConfirmedCheckbox:  false,
		Passphrase:         []byte("SuperSecretPassphrase123!"),
		PassphraseConfirm:  []byte("SuperSecretPassphrase123!"),
	}
	if err := RunOnboardingPipeline(cfg, req2, "Boss"); err == nil {
		t.Errorf("expected error when confirmation checkbox is unchecked")
	}

	// 3. Short passphrase
	req3 := OnboardRequest{
		Device:             "/dev/sdb",
		ConfirmationDevice: "/dev/sdb",
		ConfirmedCheckbox:  true,
		Passphrase:         []byte("short"),
		PassphraseConfirm:  []byte("short"),
	}
	if err := RunOnboardingPipeline(cfg, req3, "Boss"); err == nil {
		t.Errorf("expected error when passphrase is shorter than 12 chars")
	}
}
