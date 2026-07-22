package drive

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"secure-drive/internal/config"
)

type CandidateDrive struct {
	Name          string `json:"name"`          // e.g. /dev/sdb
	Size          string `json:"size"`          // e.g. 100G
	SizeBytes     int64  `json:"sizeBytes"`     // e.g. 107374182400
	Model         string `json:"model"`         // e.g. VBOX HARDDISK
	Type          string `json:"type"`          // e.g. disk
	State         string `json:"state"`         // EMPTY, HAS_PARTITIONS, HAS_LUKS, HAS_FILESYSTEM
	IsEmpty       bool   `json:"isEmpty"`       // true if state == EMPTY
	Warning       string `json:"warning"`       // User-facing warning string
	HasPartitions bool   `json:"hasPartitions"`
	HasLUKS       bool   `json:"hasLUKS"`
	HasFS         bool   `json:"hasFS"`
}

type LsblkOutput struct {
	Blockdevices []LsblkDevice `json:"blockdevices"`
}

type LsblkDevice struct {
	Name       string        `json:"name"`
	Size       string        `json:"size"`
	Type       string        `json:"type"`
	Mountpoint *string       `json:"mountpoint"`
	Model      *string       `json:"model"`
	Fstype     *string       `json:"fstype"`
	Uuid       *string       `json:"uuid"`
	Children   []LsblkDevice `json:"children"`
}

// GetRootParentDisk identifies the physical parent disk of the current root filesystem /
func GetRootParentDisk() (string, error) {
	if IsMockMode() {
		return "/dev/vda", nil
	}

	// 1. Run findmnt to get source of /
	cmd := exec.Command("findmnt", "-no", "SOURCE", "/")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to detect root mount source: %v", err)
	}
	rootSource := strings.TrimSpace(string(out))

	// Resolve symlinks (e.g. /dev/mapper/xxx -> /dev/dm-0)
	resolved, err := filepath.EvalSymlinks(rootSource)
	if err == nil {
		rootSource = resolved
	}

	// 2. Trace parent disk using lsblk -p -s -n -o NAME,TYPE <rootSource>
	cmdParent := exec.Command("lsblk", "-p", "-s", "-n", "-o", "NAME,TYPE", rootSource)
	parentOut, parentErr := cmdParent.CombinedOutput()
	if parentErr == nil {
		lines := strings.Split(strings.TrimSpace(string(parentOut)), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "disk" {
				return fields[0], nil
			}
		}
	}

	// Fallback sysfs check: /sys/class/block/<dev>/partition
	baseDev := filepath.Base(rootSource)
	sysPath := fmt.Sprintf("/sys/class/block/%s/partition", baseDev)
	if _, statErr := os.Stat(sysPath); statErr == nil {
		parentName := stripPartitionSuffix(baseDev)
		return "/dev/" + parentName, nil
	}

	return rootSource, nil
}

func stripPartitionSuffix(dev string) string {
	if strings.Contains(dev, "nvme") || strings.Contains(dev, "mmcblk") {
		idx := strings.LastIndex(dev, "p")
		if idx > 0 {
			return dev[:idx]
		}
	}
	return strings.TrimRight(dev, "0123456789")
}

// GetCandidateDrives scans for block devices available for onboarding
func GetCandidateDrives(cfg *config.Config) ([]CandidateDrive, error) {
	if IsMockMode() {
		return getMockCandidateDrives(cfg), nil
	}

	rootDisk, err := GetRootParentDisk()
	if err != nil {
		log.Printf("[ONBOARD] Warning resolving root disk: %v", err)
	}

	cmd := exec.Command("lsblk", "-J", "-p", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,MODEL,FSTYPE,UUID")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("lsblk failed: %v (output: %s)", err, string(out))
	}

	var parsed LsblkOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse lsblk output: %v", err)
	}

	configuredDev := ""
	if cfg != nil {
		configuredDev = cfg.Drive.Device
	}

	var candidates []CandidateDrive
	for _, dev := range parsed.Blockdevices {
		if dev.Type != "disk" {
			continue
		}

		// Filter out loop, ram, zram devices
		if strings.HasPrefix(dev.Name, "/dev/loop") || strings.HasPrefix(dev.Name, "/dev/ram") || strings.HasPrefix(dev.Name, "/dev/zram") {
			continue
		}

		// Filter out root disk & root partition
		if rootDisk != "" && (dev.Name == rootDisk || strings.HasPrefix(dev.Name, rootDisk)) {
			continue
		}

		// Filter out currently configured drive
		if configuredDev != "" && (dev.Name == configuredDev || strings.HasPrefix(configuredDev, dev.Name)) {
			continue
		}

		cand := inspectCandidateDevice(dev)
		candidates = append(candidates, cand)
	}

	return candidates, nil
}

func inspectCandidateDevice(dev LsblkDevice) CandidateDrive {
	model := "Unknown"
	if dev.Model != nil && *dev.Model != "" {
		model = *dev.Model
	}

	cand := CandidateDrive{
		Name:  dev.Name,
		Size:  dev.Size,
		Model: model,
		Type:  dev.Type,
	}

	// Get size in bytes
	cmdSize := exec.Command("blockdev", "--getsize64", dev.Name)
	outSize, errSize := cmdSize.CombinedOutput()
	if errSize == nil {
		var sz int64
		fmt.Sscanf(strings.TrimSpace(string(outSize)), "%d", &sz)
		cand.SizeBytes = sz
	}

	// Inspect child partitions, fstype, luks
	hasPartitions := len(dev.Children) > 0
	hasFS := (dev.Fstype != nil && *dev.Fstype != "")

	// Check for LUKS header on device or children
	hasLUKS := (dev.Fstype != nil && *dev.Fstype == "crypto_LUKS")
	for _, child := range dev.Children {
		if child.Fstype != nil {
			if *child.Fstype == "crypto_LUKS" {
				hasLUKS = true
			}
			if *child.Fstype != "" {
				hasFS = true
			}
		}
	}

	if !hasLUKS {
		cmdLuks := exec.Command("cryptsetup", "luksDump", dev.Name)
		if err := cmdLuks.Run(); err == nil {
			hasLUKS = true
		}
	}

	cand.HasPartitions = hasPartitions
	cand.HasFS = hasFS
	cand.HasLUKS = hasLUKS

	if hasLUKS {
		cand.State = "HAS_LUKS"
		cand.IsEmpty = false
		cand.Warning = "NOT EMPTY — Contains an existing LUKS encrypted header. All data will be permanently destroyed."
	} else if hasFS {
		cand.State = "HAS_FILESYSTEM"
		cand.IsEmpty = false
		cand.Warning = "NOT EMPTY — Contains an active filesystem. All data will be permanently destroyed."
	} else if hasPartitions {
		cand.State = "HAS_PARTITIONS"
		cand.IsEmpty = false
		cand.Warning = "NOT EMPTY — Device has existing partitions. All data will be permanently destroyed."
	} else {
		cand.State = "EMPTY"
		cand.IsEmpty = true
		cand.Warning = ""
	}

	return cand
}

func getMockCandidateDrives(cfg *config.Config) []CandidateDrive {
	configuredDev := "/dev/sdb1"
	if cfg != nil && cfg.Drive.Device != "" {
		configuredDev = cfg.Drive.Device
	}

	candidates := []CandidateDrive{
		{
			Name:          "/dev/sdb",
			Size:          "100G",
			SizeBytes:     107374182400,
			Model:         "Mock VirtIO Data Disk",
			Type:          "disk",
			State:         "EMPTY",
			IsEmpty:       true,
			Warning:       "",
			HasPartitions: false,
			HasLUKS:       false,
			HasFS:         false,
		},
		{
			Name:          "/dev/sdc",
			Size:          "500G",
			SizeBytes:     536870912000,
			Model:         "Mock Storage Array",
			Type:          "disk",
			State:         "HAS_PARTITIONS",
			IsEmpty:       false,
			Warning:       "NOT EMPTY — Device has existing partitions. All data will be permanently destroyed.",
			HasPartitions: true,
			HasLUKS:       false,
			HasFS:         true,
		},
	}

	var filtered []CandidateDrive
	for _, c := range candidates {
		if c.Name != configuredDev && !strings.HasPrefix(configuredDev, c.Name) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// DetectPartitionName derives the child partition path for a drive (e.g. /dev/sdb -> /dev/sdb1, /dev/nvme0n1 -> /dev/nvme0n1p1)
func DetectPartitionName(device string) string {
	device = strings.TrimSpace(device)
	if strings.Contains(device, "nvme") || strings.Contains(device, "mmcblk") {
		return device + "p1"
	}
	return device + "1"
}
