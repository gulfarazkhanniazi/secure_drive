package drive

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"secure-drive/internal/config"
	"secure-drive/internal/logger"
)

type StepResult struct {
	Step        int    `json:"step"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"` // SUCCESS | FAILURE
	Error       string `json:"error,omitempty"`
	DurationMs  int64  `json:"durationMs"`
}

type OnboardingStatus struct {
	IsRunning       bool         `json:"isRunning"`
	CurrentStep     int          `json:"currentStep"`
	TotalSteps      int          `json:"totalSteps"`
	StepDescription string       `json:"stepDescription"`
	Status          string       `json:"status"` // IDLE | IN_PROGRESS | SUCCESS | FAILED
	ErrorDetails    string       `json:"errorDetails,omitempty"`
	TargetDevice    string       `json:"targetDevice,omitempty"`
	PartitionDevice string       `json:"partitionDevice,omitempty"`
	MapperName      string       `json:"mapperName,omitempty"`
	MountPoint      string       `json:"mountPoint,omitempty"`
	StartedAt       time.Time    `json:"startedAt,omitempty"`
	CompletedAt     time.Time    `json:"completedAt,omitempty"`
	Steps           []StepResult `json:"steps"`
}

var (
	onboardMu     sync.Mutex
	currentStatus = OnboardingStatus{
		Status:     "IDLE",
		TotalSteps: 14,
	}
)

func GetOnboardingStatus() OnboardingStatus {
	onboardMu.Lock()
	defer onboardMu.Unlock()
	return currentStatus
}

type OnboardRequest struct {
	Device             string `json:"device"`
	Passphrase         []byte `json:"-"`
	PassphraseConfirm  []byte `json:"-"`
	MapperName         string `json:"mapperName"`
	MountPoint         string `json:"mountPoint"`
	ConfirmationDevice string `json:"confirmationDevice"`
	ConfirmedCheckbox  bool   `json:"confirmedCheckbox"`
}

// ZeroBytes safely overwrites a byte slice with zeros in memory
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ValidatePassphraseStrength enforces minimum length >= 12
func ValidatePassphraseStrength(pass []byte) error {
	if len(pass) < 12 {
		return fmt.Errorf("passphrase must be at least 12 characters long")
	}
	return nil
}

// ValidateDevicePath sanitizes device path strings
func ValidateDevicePath(dev string) error {
	matched, _ := regexp.MatchString(`^/dev/[a-zA-Z0-9_-]+$`, dev)
	if !matched {
		return fmt.Errorf("invalid device path format: %s", dev)
	}
	return nil
}

// RunOnboardingPipeline executes the 14-step LUKS onboarding pipeline
func RunOnboardingPipeline(cfg *config.Config, req OnboardRequest, user string) error {
	onboardMu.Lock()
	if currentStatus.IsRunning {
		onboardMu.Unlock()
		return fmt.Errorf("onboarding pipeline is already running")
	}

	// Defer zeroing passphrases in caller scope
	defer ZeroBytes(req.Passphrase)
	defer ZeroBytes(req.PassphraseConfirm)

	// Validate inputs
	if err := ValidateDevicePath(req.Device); err != nil {
		onboardMu.Unlock()
		return err
	}
	if req.ConfirmationDevice != req.Device {
		onboardMu.Unlock()
		return fmt.Errorf("confirmation device path (%s) does not match selected device (%s)", req.ConfirmationDevice, req.Device)
	}
	if !req.ConfirmedCheckbox {
		onboardMu.Unlock()
		return fmt.Errorf("destructive confirmation checkbox must be checked")
	}
	if !bytes.Equal(req.Passphrase, req.PassphraseConfirm) {
		onboardMu.Unlock()
		return fmt.Errorf("passphrases do not match")
	}
	if err := ValidatePassphraseStrength(req.Passphrase); err != nil {
		onboardMu.Unlock()
		return err
	}

	mapperName := strings.TrimSpace(req.MapperName)
	if mapperName == "" {
		mapperName = "secure-data"
	}
	mountPoint := strings.TrimSpace(req.MountPoint)
	if mountPoint == "" {
		mountPoint = "/mnt/secure"
	}

	// Copy passphrase into a worker byte slice that will be zeroed when worker finishes
	passphraseWorker := make([]byte, len(req.Passphrase))
	copy(passphraseWorker, req.Passphrase)

	currentStatus = OnboardingStatus{
		IsRunning:       true,
		CurrentStep:     0,
		TotalSteps:      14,
		StepDescription: "Starting setup pipeline...",
		Status:          "IN_PROGRESS",
		TargetDevice:    req.Device,
		MapperName:      mapperName,
		MountPoint:      mountPoint,
		StartedAt:       time.Now(),
		Steps:           make([]StepResult, 0, 14),
	}
	onboardMu.Unlock()

	logger.Audit.Log(fmt.Sprintf("DRIVE_ONBOARD_START device=%s user=%s", req.Device, user), user, "SUCCESS")

	go executePipeline(cfg, req.Device, passphraseWorker, mapperName, mountPoint, user)
	return nil
}

func updateStepProgress(step int, desc string, res *StepResult) {
	onboardMu.Lock()
	defer onboardMu.Unlock()
	currentStatus.CurrentStep = step
	currentStatus.StepDescription = desc
	if res != nil {
		currentStatus.Steps = append(currentStatus.Steps, *res)
	}
}

func failPipeline(step int, desc string, err error, output string, user string) {
	onboardMu.Lock()
	defer onboardMu.Unlock()
	currentStatus.IsRunning = false
	currentStatus.Status = "FAILED"
	currentStatus.CompletedAt = time.Now()

	errDetails := fmt.Sprintf("Step %d/14 (%s) failed: %v", step, desc, err)
	if output != "" {
		errDetails += fmt.Sprintf("\nCommand Output:\n%s", output)
	}
	currentStatus.ErrorDetails = errDetails

	res := StepResult{
		Step:        step,
		Name:        fmt.Sprintf("Step %d", step),
		Description: desc,
		Status:      "FAILURE",
		Error:       fmt.Sprintf("%v", err),
	}
	currentStatus.Steps = append(currentStatus.Steps, res)

	logger.Audit.Log(fmt.Sprintf("DRIVE_ONBOARD_FAIL step=%d desc=\"%s\" err=\"%v\"", step, desc, err), user, "FAILURE")
}

func executePipeline(cfg *config.Config, device string, passphrase []byte, mapperName, mountPoint, user string) {
	var partitionDev string

	defer func() {
		ZeroBytes(passphrase)
	}()

	if IsMockMode() {
		executeMockPipeline(cfg, device, mapperName, mountPoint, user)
		return
	}

	// Required binaries check
	requiredBinaries := []string{"wipefs", "parted", "cryptsetup", "mkfs.ext4", "mount", "umount", "dd", "blockdev", "findmnt"}
	for _, bin := range requiredBinaries {
		if _, err := exec.LookPath(bin); err != nil {
			failPipeline(1, "Pre-flight binary check", fmt.Errorf("required tool missing: %s", bin), "", user)
			return
		}
	}

	// -------------------------------------------------------------
	// STEP 1: Pre-flight Safety Re-verification (Root & Config Check)
	// -------------------------------------------------------------
	start := time.Now()
	updateStepProgress(1, "Step 1/14: Safety Pre-flight & Root Disk Defense-in-Depth Re-verification", nil)
	rootDisk, rootErr := GetRootParentDisk()
	if rootErr != nil {
		failPipeline(1, "Root disk check", rootErr, "", user)
		return
	}

	if rootDisk != "" && (device == rootDisk || strings.HasPrefix(device, rootDisk)) {
		failPipeline(1, "Root disk safety check", fmt.Errorf("CRITICAL SAFETY BLOCK: Target device %s is the system root disk (%s)", device, rootDisk), "", user)
		return
	}

	if cfg.Drive.Device != "" && (device == cfg.Drive.Device || strings.HasPrefix(cfg.Drive.Device, device)) {
		failPipeline(1, "Configured drive safety check", fmt.Errorf("CRITICAL SAFETY BLOCK: Target device %s is already configured in config.yaml", device), "", user)
		return
	}

	cmdSize := exec.Command("blockdev", "--getsize64", device)
	outSize, errSize := cmdSize.CombinedOutput()
	if errSize != nil {
		failPipeline(1, "Device size check", fmt.Errorf("failed to read blockdev size: %v", errSize), string(outSize), user)
		return
	}
	var sizeBytes int64
	fmt.Sscanf(strings.TrimSpace(string(outSize)), "%d", &sizeBytes)
	if sizeBytes < 1073741824 { // < 1GB
		failPipeline(1, "Device size check", fmt.Errorf("device size is too small (%d bytes, min 1GB required)", sizeBytes), "", user)
		return
	}
	updateStepProgress(1, "Step 1/14: Safety Pre-flight Passed", &StepResult{
		Step: 1, Name: "Pre-flight Verification", Description: "Safety check passed", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 2: Wipefs
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(2, "Step 2/14: Wiping Filesystem & Partition Signatures (wipefs)", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	cmdWipe := exec.CommandContext(ctx, "wipefs", "-a", device)
	outWipe, errWipe := cmdWipe.CombinedOutput()
	cancel()
	if errWipe != nil {
		failPipeline(2, "Wipe device signatures", errWipe, string(outWipe), user)
		return
	}
	updateStepProgress(2, "Step 2/14: Device Signatures Wiped", &StepResult{
		Step: 2, Name: "Wipe Signatures", Description: "Wiped partition/FS signatures", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 3: Parted GPT label
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(3, "Step 3/14: Creating GPT Partition Table (parted)", nil)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	cmdLabel := exec.CommandContext(ctx, "parted", device, "--script", "mklabel", "gpt")
	outLabel, errLabel := cmdLabel.CombinedOutput()
	cancel()
	if errLabel != nil {
		failPipeline(3, "Create GPT label", errLabel, string(outLabel), user)
		return
	}
	updateStepProgress(3, "Step 3/14: GPT Label Created", &StepResult{
		Step: 3, Name: "Create GPT Label", Description: "Created GPT partition table", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 4: Parted Primary Partition
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(4, "Step 4/14: Creating Primary Partition 0%-100%", nil)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	cmdPart := exec.CommandContext(ctx, "parted", device, "--script", "mkpart", "primary", "0%", "100%")
	outPart, errPart := cmdPart.CombinedOutput()
	cancel()
	if errPart != nil {
		failPipeline(4, "Create primary partition", errPart, string(outPart), user)
		return
	}
	exec.Command("partprobe", device).Run()
	exec.Command("udevadm", "settle").Run()
	time.Sleep(1 * time.Second)

	updateStepProgress(4, "Step 4/14: Primary Partition Created", &StepResult{
		Step: 4, Name: "Create Primary Partition", Description: "Created primary partition", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 5: Detect Partition Device Name
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(5, "Step 5/14: Detecting & Verifying Partition Device Path", nil)
	partitionDev = DetectPartitionName(device)

	partFound := false
	for i := 0; i < 10; i++ {
		if _, errStat := os.Stat(partitionDev); errStat == nil {
			partFound = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !partFound {
		failPipeline(5, "Detect partition path", fmt.Errorf("partition device file %s failed to appear after 5s", partitionDev), "", user)
		return
	}
	onboardMu.Lock()
	currentStatus.PartitionDevice = partitionDev
	onboardMu.Unlock()

	updateStepProgress(5, "Step 5/14: Partition Path Detected ("+partitionDev+")", &StepResult{
		Step: 5, Name: "Detect Partition", Description: "Verified partition " + partitionDev, Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 6: Cryptsetup luksFormat (Keyslot 0 - Passphrase via Stdin)
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(6, "Step 6/14: Formatting LUKS2 Encrypted Volume (Keyslot 0 Passphrase - This may take a moment)...", nil)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	cmdFormat := exec.CommandContext(ctx, "cryptsetup", "luksFormat", "--type", "luks2",
		"--cipher", "aes-xts-plain64", "--key-size", "512", "--hash", "sha256",
		"--pbkdf", "argon2id", "--iter-time", "4000", partitionDev, "--batch-mode")

	cmdFormat.Stdin = bytes.NewReader(passphrase)
	outFormat, errFormat := cmdFormat.CombinedOutput()
	cancel()
	if errFormat != nil {
		failPipeline(6, "LUKS Format", errFormat, string(outFormat), user)
		return
	}
	updateStepProgress(6, "Step 6/14: LUKS2 Volume Formatted (Keyslot 0 Active)", &StepResult{
		Step: 6, Name: "LUKS Format", Description: "Formatted LUKS2 encrypted container with passphrase", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 7: Generate Random Keyfile (Keyslot 1)
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(7, "Step 7/14: Generating High-Entropy Server Keyfile (/etc/secure-drive/keyfile)...", nil)

	keyfilePath := cfg.Drive.KeyFile
	if keyfilePath == "" {
		keyfilePath = "/etc/secure-drive/keyfile"
	}

	keyfileDir := filepath.Dir(keyfilePath)
	if errMk := os.MkdirAll(keyfileDir, 0700); errMk != nil {
		failPipeline(7, "Create keyfile directory", errMk, "", user)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Minute)
	cmdDD := exec.CommandContext(ctx, "dd", "if=/dev/urandom", "of="+keyfilePath, "bs=1024", "count=4")
	outDD, errDD := cmdDD.CombinedOutput()
	cancel()
	if errDD != nil {
		failPipeline(7, "Generate keyfile with dd", errDD, string(outDD), user)
		return
	}

	if errChmod := os.Chmod(keyfilePath, 0600); errChmod != nil {
		failPipeline(7, "Set keyfile permissions 600", errChmod, "", user)
		return
	}
	updateStepProgress(7, "Step 7/14: Keyfile Generated ("+keyfilePath+" 0600)", &StepResult{
		Step: 7, Name: "Generate Keyfile", Description: "Created random 4KB keyfile with 0600 perms", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 8: Cryptsetup luksAddKey (Keyslot 1 - Server Keyfile)
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(8, "Step 8/14: Enrolling Server Keyfile into LUKS Volume (Keyslot 1)...", nil)
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Minute)
	cmdAddKey := exec.CommandContext(ctx, "cryptsetup", "luksAddKey", partitionDev, keyfilePath, "--batch-mode")
	cmdAddKey.Stdin = bytes.NewReader(passphrase)
	outAddKey, errAddKey := cmdAddKey.CombinedOutput()
	cancel()
	if errAddKey != nil {
		failPipeline(8, "Add keyfile to LUKS volume", errAddKey, string(outAddKey), user)
		return
	}
	updateStepProgress(8, "Step 8/14: Server Keyfile Enrolled in Keyslot 1", &StepResult{
		Step: 8, Name: "Enroll Keyfile", Description: "Added server keyfile to LUKS volume", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 9: Cryptsetup Open (using Keyfile)
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(9, "Step 9/14: Opening LUKS Container via Server Keyfile...", nil)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	cmdOpen := exec.CommandContext(ctx, "cryptsetup", "open", partitionDev, mapperName, "--key-file", keyfilePath)
	outOpen, errOpen := cmdOpen.CombinedOutput()
	cancel()
	if errOpen != nil {
		failPipeline(9, "Open LUKS volume", errOpen, string(outOpen), user)
		return
	}
	updateStepProgress(9, "Step 9/14: LUKS Container Opened (/dev/mapper/"+mapperName+")", &StepResult{
		Step: 9, Name: "Open Container", Description: "Decrypted volume to /dev/mapper/" + mapperName, Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 10: mkfs.ext4
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(10, "Step 10/14: Creating ext4 Filesystem (This may take several minutes on large drives)...", nil)
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
	mapperPath := "/dev/mapper/" + mapperName
	cmdMkfs := exec.CommandContext(ctx, "mkfs.ext4", "-F", mapperPath)
	outMkfs, errMkfs := cmdMkfs.CombinedOutput()
	cancel()
	if errMkfs != nil {
		CleanupPartial(mapperName, "")
		failPipeline(10, "Format ext4 filesystem", errMkfs, string(outMkfs), user)
		return
	}
	updateStepProgress(10, "Step 10/14: ext4 Filesystem Formatted", &StepResult{
		Step: 10, Name: "Create Filesystem", Description: "Created ext4 filesystem on mapper", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 11: mkdir -p mountPoint
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(11, "Step 11/14: Creating Mount Directory ("+mountPoint+")...", nil)
	if errMk := os.MkdirAll(mountPoint, 0755); errMk != nil {
		CleanupPartial(mapperName, "")
		failPipeline(11, "Create mount point directory", errMk, "", user)
		return
	}
	updateStepProgress(11, "Step 11/14: Mount Directory Created", &StepResult{
		Step: 11, Name: "Create Mount Directory", Description: "Created directory " + mountPoint, Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 12: Mount Validation (Write/Read Test & Unmount)
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(12, "Step 12/14: Validating Mount & Filesystem Read/Write Capability...", nil)
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Minute)
	cmdMount := exec.CommandContext(ctx, "mount", mapperPath, mountPoint)
	outMount, errMount := cmdMount.CombinedOutput()
	cancel()
	if errMount != nil {
		CleanupPartial(mapperName, "")
		failPipeline(12, "Mount filesystem for testing", errMount, string(outMount), user)
		return
	}

	testFilePath := filepath.Join(mountPoint, ".onboard_test")
	testData := []byte("onboard-test-verification-pass")
	if errWrite := os.WriteFile(testFilePath, testData, 0600); errWrite != nil {
		exec.Command("umount", mountPoint).Run()
		CleanupPartial(mapperName, "")
		failPipeline(12, "Test file write validation", errWrite, "", user)
		return
	}
	readBack, errRead := os.ReadFile(testFilePath)
	os.Remove(testFilePath)

	if errRead != nil || !bytes.Equal(readBack, testData) {
		exec.Command("umount", mountPoint).Run()
		CleanupPartial(mapperName, "")
		failPipeline(12, "Test file readback validation", fmt.Errorf("readback data mismatch"), "", user)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Minute)
	cmdUmount := exec.CommandContext(ctx, "umount", mountPoint)
	outUmount, errUmount := cmdUmount.CombinedOutput()
	cancel()
	if errUmount != nil {
		CleanupPartial(mapperName, "")
		failPipeline(12, "Unmount test filesystem", errUmount, string(outUmount), user)
		return
	}
	updateStepProgress(12, "Step 12/14: Mount Read/Write Validation Passed", &StepResult{
		Step: 12, Name: "Validate Mount", Description: "Tested mount, write, readback, and umount", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 13: Cryptsetup Close
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(13, "Step 13/14: Closing LUKS Container...", nil)
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Minute)
	cmdClose := exec.CommandContext(ctx, "cryptsetup", "close", mapperName)
	outClose, errClose := cmdClose.CombinedOutput()
	cancel()
	if errClose != nil {
		failPipeline(13, "Close LUKS container", errClose, string(outClose), user)
		return
	}
	updateStepProgress(13, "Step 13/14: LUKS Container Closed", &StepResult{
		Step: 13, Name: "Close Container", Description: "Container closed safely", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	// -------------------------------------------------------------
	// STEP 14: Atomic Config Update & Audit Log
	// -------------------------------------------------------------
	start = time.Now()
	updateStepProgress(14, "Step 14/14: Updating Configuration (config.yaml)...", nil)

	if errCfg := config.UpdateDriveConfig(partitionDev, mapperName, mountPoint, keyfilePath); errCfg != nil {
		failPipeline(14, "Atomic config update", errCfg, "", user)
		return
	}

	updateStepProgress(14, "Step 14/14: Onboarding Complete!", &StepResult{
		Step: 14, Name: "Update Config", Description: "Atomic config update complete", Status: "SUCCESS", DurationMs: time.Since(start).Milliseconds(),
	})

	onboardMu.Lock()
	currentStatus.IsRunning = false
	currentStatus.Status = "SUCCESS"
	currentStatus.CompletedAt = time.Now()
	onboardMu.Unlock()

	logger.Audit.Log(fmt.Sprintf("DRIVE_ONBOARD_SUCCESS device=%s mapper=%s mountPoint=%s user=%s", partitionDev, mapperName, mountPoint, user), user, "SUCCESS")
}

func CleanupPartial(mapperName, mountPoint string) {
	if IsMockMode() {
		return
	}
	if mountPoint != "" {
		exec.Command("umount", "-l", mountPoint).Run()
	}
	if mapperName != "" {
		exec.Command("cryptsetup", "close", mapperName).Run()
	}
}

func executeMockPipeline(cfg *config.Config, device, mapperName, mountPoint, user string) {
	partitionDev := DetectPartitionName(device)
	stepDescs := []string{
		"Step 1/14: Safety Pre-flight Verification",
		"Step 2/14: Wiping Filesystem & Partition Signatures (wipefs)",
		"Step 3/14: Creating GPT Partition Table (parted)",
		"Step 4/14: Creating Primary Partition 0%-100%",
		"Step 5/14: Detecting & Verifying Partition Path (" + partitionDev + ")",
		"Step 6/14: Formatting LUKS2 Encrypted Volume (Keyslot 0 Passphrase)",
		"Step 7/14: Generating Random Server Keyfile",
		"Step 8/14: Enrolling Server Keyfile into LUKS Volume (Keyslot 1)",
		"Step 9/14: Opening LUKS Container via Keyfile",
		"Step 10/14: Creating ext4 Filesystem",
		"Step 11/14: Creating Mount Directory (" + mountPoint + ")",
		"Step 12/14: Validating Mount Read/Write Capability",
		"Step 13/14: Closing LUKS Container",
		"Step 14/14: Updating Configuration (config.yaml)",
	}

	for i := 1; i <= 14; i++ {
		time.Sleep(100 * time.Millisecond)
		start := time.Now()
		desc := stepDescs[i-1]
		updateStepProgress(i, desc, &StepResult{
			Step:        i,
			Name:        fmt.Sprintf("Step %d", i),
			Description: desc,
			Status:      "SUCCESS",
			DurationMs:  time.Since(start).Milliseconds(),
		})
	}

	keyFile := "./mock_keyfile"
	if cfg != nil && cfg.Drive.KeyFile != "" {
		keyFile = cfg.Drive.KeyFile
	}
	config.UpdateDriveConfig(partitionDev, mapperName, mountPoint, keyFile)

	SetMockDeviceExists(true)

	onboardMu.Lock()
	currentStatus.IsRunning = false
	currentStatus.Status = "SUCCESS"
	currentStatus.CompletedAt = time.Now()
	onboardMu.Unlock()

	logger.Audit.Log(fmt.Sprintf("DRIVE_ONBOARD_SUCCESS device=%s mapper=%s mountPoint=%s user=%s", partitionDev, mapperName, mountPoint, user), user, "SUCCESS")
}
