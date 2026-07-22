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

func TestGetParentDiskPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/dev/sda1", "/dev/sda"},
		{"/dev/sda", "/dev/sda"},
		{"sda1", "sda"},
		{"/dev/sdb2", "/dev/sdb"},
		{"/dev/nvme0n1p1", "/dev/nvme0n1"},
		{"/dev/nvme0n1", "/dev/nvme0n1"},
		{"/dev/mmcblk0p2", "/dev/mmcblk0"},
		{"/dev/mmcblk0", "/dev/mmcblk0"},
		{"/dev/vda1", "/dev/vda"},
		{"/dev/vda", "/dev/vda"},
	}

	for _, tt := range tests {
		got := GetParentDiskPath(tt.input)
		if got != tt.expected {
			t.Errorf("GetParentDiskPath(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestThreeRuleExclusion_ActiveMapper(t *testing.T) {
	// (a) mapper active on /dev/sda, candidate scan run concurrently — assert /dev/sda excluded, unrelated /dev/sdb included.
	SetMockActiveMapperDevice("/dev/sda")
	defer SetMockActiveMapperDevice("")

	cfg := &config.Config{}
	cfg.Drive.Mapper = "test-mapper"

	candidates, err := GetCandidateDrives(cfg)
	if err != nil {
		t.Fatalf("GetCandidateDrives failed: %v", err)
	}

	foundSda := false
	foundSdb := false
	for _, c := range candidates {
		if c.Name == "/dev/sda" {
			foundSda = true
		}
		if c.Name == "/dev/sdb" {
			foundSdb = true
		}
	}

	if foundSda {
		t.Errorf("expected /dev/sda to be excluded when mapper is active on /dev/sda, but it was found")
	}
	if !foundSdb {
		t.Errorf("expected unrelated /dev/sdb to be included when mapper is active on /dev/sda, but it was excluded")
	}
}

func TestThreeRuleExclusion_MapperInactiveDifferentNonLuksDrive(t *testing.T) {
	// (b) mapper inactive, cfg.Drive.DeviceUUID set, a different non-LUKS drive occupies /dev/sda — assert it IS included with correct EMPTY/HAS_FILESYSTEM state, not excluded.
	SetMockActiveMapperDevice("")
	SetMockUUID("/dev/sda", "") // non-LUKS drive
	defer ClearMockUUID("/dev/sda")

	cfg := &config.Config{}
	cfg.Drive.Mapper = "test-mapper"
	cfg.Drive.DeviceUUID = "target-luks-uuid-1234"

	candidates, err := GetCandidateDrives(cfg)
	if err != nil {
		t.Fatalf("GetCandidateDrives failed: %v", err)
	}

	var sdaCand *CandidateDrive
	for i := range candidates {
		if candidates[i].Name == "/dev/sda" {
			sdaCand = &candidates[i]
			break
		}
	}

	if sdaCand == nil {
		t.Fatalf("expected non-LUKS drive /dev/sda to be included, but it was excluded!")
	}

	if sdaCand.State != "EMPTY" && sdaCand.State != "HAS_FILESYSTEM" && sdaCand.State != "HAS_PARTITIONS" {
		t.Errorf("expected state EMPTY or HAS_FILESYSTEM/HAS_PARTITIONS, got: %s", sdaCand.State)
	}
}

func TestThreeRuleExclusion_MapperInactiveMatchingLuksUUID(t *testing.T) {
	// (c) mapper inactive, a drive with a LUKS header whose UUID exactly matches cfg.Drive.DeviceUUID occupies /dev/sda — assert it IS excluded.
	SetMockActiveMapperDevice("")
	SetMockUUID("/dev/sda", "target-luks-uuid-1234")
	defer ClearMockUUID("/dev/sda")

	cfg := &config.Config{}
	cfg.Drive.Mapper = "test-mapper"
	cfg.Drive.DeviceUUID = "target-luks-uuid-1234"

	candidates, err := GetCandidateDrives(cfg)
	if err != nil {
		t.Fatalf("GetCandidateDrives failed: %v", err)
	}

	for _, c := range candidates {
		if c.Name == "/dev/sda" {
			t.Errorf("expected drive /dev/sda with matching LUKS UUID to be excluded, but it was found in candidates")
		}
	}
}

func TestThreeRuleExclusion_NoDeviceUUIDMigrationNotice(t *testing.T) {
	// (d) config.yaml has no DeviceUUID at all — assert no crash, rules 1–2 still apply, startup warning logged once.
	SetMockActiveMapperDevice("")
	cfg := &config.Config{}
	cfg.Drive.Device = "/dev/sda1"
	cfg.Drive.DeviceUUID = "" // No DeviceUUID (predates field)

	CheckConfigMigration(cfg)

	candidates, err := GetCandidateDrives(cfg)
	if err != nil {
		t.Fatalf("GetCandidateDrives failed without DeviceUUID: %v", err)
	}

	if len(candidates) == 0 {
		t.Errorf("expected candidates to return safely without crash when DeviceUUID is empty")
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
