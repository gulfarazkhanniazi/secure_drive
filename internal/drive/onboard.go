package drive

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

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

var (
	mockUUIDsMu sync.RWMutex
	mockUUIDs   = make(map[string]string)

	mockActiveMapperDeviceMu sync.RWMutex
	mockActiveMapperDevice   string

	migrationNoticeMu     sync.Mutex
	migrationNoticeLogged bool
)

func SetMockUUID(device, uuid string) {
	mockUUIDsMu.Lock()
	defer mockUUIDsMu.Unlock()
	mockUUIDs[device] = uuid
}

func ClearMockUUID(device string) {
	mockUUIDsMu.Lock()
	defer mockUUIDsMu.Unlock()
	delete(mockUUIDs, device)
}

func SetMockActiveMapperDevice(dev string) {
	mockActiveMapperDeviceMu.Lock()
	defer mockActiveMapperDeviceMu.Unlock()
	mockActiveMapperDevice = dev
}

func CheckConfigMigration(cfg *config.Config) {
	migrationNoticeMu.Lock()
	defer migrationNoticeMu.Unlock()
	if migrationNoticeLogged {
		return
	}
	migrationNoticeLogged = true

	if cfg != nil && cfg.Drive.DeviceUUID == "" && cfg.Drive.Device != "" {
		log.Printf("NOTICE: Drive configuration has no DeviceUUID stored. Rule 3 (Stored-UUID exclusion) will be skipped. Run 'cryptsetup luksUUID %s' and set 'deviceUUID' in config.yaml for full protection.", cfg.Drive.Device)
	}
}

func GetLuksUUID(device string) (string, error) {
	device = strings.TrimSpace(device)
	if device == "" {
		return "", fmt.Errorf("empty device")
	}

	mockUUIDsMu.RLock()
	val, ok := mockUUIDs[device]
	mockUUIDsMu.RUnlock()

	if ok {
		if val == "" {
			return "", fmt.Errorf("no mock uuid for %s", device)
		}
		return val, nil
	}

	if IsMockMode() {
		return "", fmt.Errorf("mock mode: no uuid for %s", device)
	}

	cmd := exec.Command("cryptsetup", "luksUUID", device)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	uuid := strings.TrimSpace(string(out))
	if uuid == "" {
		return "", fmt.Errorf("empty uuid returned for %s", device)
	}
	return uuid, nil
}

func GetCandidateLsblkLuksUUID(dev LsblkDevice) (string, error) {
	if dev.Fstype != nil && *dev.Fstype == "crypto_LUKS" && dev.Uuid != nil && *dev.Uuid != "" {
		return *dev.Uuid, nil
	}
	for _, child := range dev.Children {
		if child.Fstype != nil && *child.Fstype == "crypto_LUKS" && child.Uuid != nil && *child.Uuid != "" {
			return *child.Uuid, nil
		}
	}
	if uuid, err := GetLuksUUID(dev.Name); err == nil && uuid != "" {
		return uuid, nil
	}
	if uuid, err := GetLuksUUID(DetectPartitionName(dev.Name)); err == nil && uuid != "" {
		return uuid, nil
	}
	return "", fmt.Errorf("no LUKS UUID found for candidate %s", dev.Name)
}

func GetActiveMapperParentDisk(mapperName string) string {
	mapperName = strings.TrimSpace(mapperName)
	if mapperName == "" {
		return ""
	}

	mockActiveMapperDeviceMu.RLock()
	mockDev := mockActiveMapperDevice
	mockActiveMapperDeviceMu.RUnlock()

	if IsMockMode() {
		if mockDev != "" {
			return GetParentDiskPath(mockDev)
		}
		if mockUnlocked || mockMounted {
			return GetParentDiskPath("/dev/sdb")
		}
		return ""
	}

	cmd := exec.Command("cryptsetup", "status", mapperName)
	out, err := cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "device:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					return GetParentDiskPath(fields[1])
				}
			}
		}
	}

	cmdLsblk := exec.Command("lsblk", "-p", "-n", "-o", "PKNAME", "/dev/mapper/"+mapperName)
	if outLsblk, errLsblk := cmdLsblk.CombinedOutput(); errLsblk == nil {
		parent := strings.TrimSpace(string(outLsblk))
		if parent != "" {
			return GetParentDiskPath(parent)
		}
	}

	return ""
}

// GetParentDiskPath resolves a device or partition path to its parent physical disk path.
func GetParentDiskPath(devPath string) string {
	devPath = strings.TrimSpace(devPath)
	if devPath == "" {
		return ""
	}
	base := filepath.Base(devPath)

	var parentBase string
	if strings.Contains(base, "nvme") || strings.Contains(base, "mmcblk") {
		idx := strings.LastIndex(base, "p")
		if idx > 0 && idx < len(base)-1 {
			isAllDigits := true
			for _, ch := range base[idx+1:] {
				if ch < '0' || ch > '9' {
					isAllDigits = false
					break
				}
			}
			if isAllDigits {
				parentBase = base[:idx]
			} else {
				parentBase = base
			}
		} else {
			parentBase = base
		}
	} else {
		i := len(base)
		for i > 0 && base[i-1] >= '0' && base[i-1] <= '9' {
			i--
		}
		if i > 0 && i < len(base) {
			parentBase = base[:i]
		} else {
			parentBase = base
		}
	}

	if strings.HasPrefix(devPath, "/dev/") {
		return "/dev/" + parentBase
	}
	return parentBase
}

// GetRootParentDisk identifies the physical parent disk of the current root filesystem /
func GetRootParentDisk() (string, error) {
	if IsMockMode() {
		return "/dev/vda", nil
	}

	cmd := exec.Command("findmnt", "-no", "SOURCE", "/")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to detect root mount source: %v", err)
	}
	rootSource := strings.TrimSpace(string(out))

	resolved, err := filepath.EvalSymlinks(rootSource)
	if err == nil {
		rootSource = resolved
	}

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

	baseDev := filepath.Base(rootSource)
	sysPath := fmt.Sprintf("/sys/class/block/%s/partition", baseDev)
	if _, statErr := os.Stat(sysPath); statErr == nil {
		return GetParentDiskPath(rootSource), nil
	}

	return GetParentDiskPath(rootSource), nil
}

func stripPartitionSuffix(dev string) string {
	return GetParentDiskPath(dev)
}

// GetCandidateDrives scans for block devices available for onboarding
func GetCandidateDrives(cfg *config.Config) ([]CandidateDrive, error) {
	CheckConfigMigration(cfg)

	if IsMockMode() {
		return getMockCandidateDrives(cfg), nil
	}

	// Rule 1: Root disk parent path (exact match)
	rootDisk, err := GetRootParentDisk()
	if err != nil {
		log.Printf("[ONBOARD] Warning resolving root disk: %v", err)
	}
	rootParent := GetParentDiskPath(rootDisk)

	// Rule 2: Active mapper parent disk (exact match)
	mapperName := ""
	if cfg != nil {
		mapperName = cfg.Drive.Mapper
	}
	activeMapperDisk := GetActiveMapperParentDisk(mapperName)

	// Rule 3: Stored LUKS UUID (exact match)
	storedUUID := ""
	if cfg != nil {
		storedUUID = cfg.Drive.DeviceUUID
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

	var candidates []CandidateDrive
	for _, dev := range parsed.Blockdevices {
		if dev.Type != "disk" {
			continue
		}

		// Filter out loop, ram, zram devices
		if strings.HasPrefix(dev.Name, "/dev/loop") || strings.HasPrefix(dev.Name, "/dev/ram") || strings.HasPrefix(dev.Name, "/dev/zram") {
			continue
		}

		candParent := GetParentDiskPath(dev.Name)

		// Rule 1: Root disk exclusion (exact match on parent disk path)
		if rootParent != "" && candParent == rootParent {
			continue
		}

		// Rule 2: Active mapper exclusion (exact match on backing physical parent disk)
		if activeMapperDisk != "" && candParent == activeMapperDisk {
			continue
		}

		// Rule 3: Stored-UUID exclusion (exact match on LUKS UUID stored in config)
		if storedUUID != "" {
			candUUID, candErr := GetCandidateLsblkLuksUUID(dev)
			if candErr == nil && candUUID != "" && candUUID == storedUUID {
				continue
			}
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

	cmdSize := exec.Command("blockdev", "--getsize64", dev.Name)
	outSize, errSize := cmdSize.CombinedOutput()
	if errSize == nil {
		var sz int64
		fmt.Sscanf(strings.TrimSpace(string(outSize)), "%d", &sz)
		cand.SizeBytes = sz
	}

	hasPartitions := len(dev.Children) > 0
	hasFS := (dev.Fstype != nil && *dev.Fstype != "")

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
	CheckConfigMigration(cfg)

	// Rule 1: Root disk parent path (mock = /dev/vda)
	rootParent := "/dev/vda"

	// Rule 2: Active mapper parent disk
	mapperName := ""
	if cfg != nil {
		mapperName = cfg.Drive.Mapper
	}
	activeMapperDisk := GetActiveMapperParentDisk(mapperName)

	// Rule 3: Stored LUKS UUID
	storedUUID := ""
	if cfg != nil {
		storedUUID = cfg.Drive.DeviceUUID
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

	mockUUIDsMu.RLock()
	sdaUUID, sdaMockExists := mockUUIDs["/dev/sda"]
	if !sdaMockExists {
		sdaUUID, sdaMockExists = mockUUIDs["/dev/sda1"]
	}
	mockUUIDsMu.RUnlock()

	mockActiveMapperDeviceMu.RLock()
	mockMapperDev := mockActiveMapperDevice
	mockActiveMapperDeviceMu.RUnlock()

	if sdaMockExists || mockMapperDev == "/dev/sda" || mockMapperDev == "/dev/sda1" {
		state := "HAS_LUKS"
		isEmpty := false
		warning := "NOT EMPTY — Contains an existing LUKS encrypted header. All data will be permanently destroyed."
		hasLUKS := true
		hasFS := false

		if sdaUUID == "" && sdaMockExists { // non-LUKS drive in mock
			state = "EMPTY"
			isEmpty = true
			warning = ""
			hasLUKS = false
		}

		candidates = append([]CandidateDrive{
			{
				Name:          "/dev/sda",
				Size:          "250G",
				SizeBytes:     268435456000,
				Model:         "Mock SATA Drive",
				Type:          "disk",
				State:         state,
				IsEmpty:       isEmpty,
				Warning:       warning,
				HasPartitions: true,
				HasLUKS:       hasLUKS,
				HasFS:         hasFS,
			},
		}, candidates...)
	}

	var filtered []CandidateDrive
	for _, c := range candidates {
		candParent := GetParentDiskPath(c.Name)

		// Rule 1: Root disk exclusion
		if rootParent != "" && candParent == rootParent {
			continue
		}

		// Rule 2: Active mapper exclusion
		if activeMapperDisk != "" && candParent == activeMapperDisk {
			continue
		}

		// Rule 3: Stored-UUID exclusion
		if storedUUID != "" {
			candUUID, candErr := GetLuksUUID(c.Name)
			if candErr != nil {
				candUUID, candErr = GetLuksUUID(DetectPartitionName(c.Name))
			}
			if candErr == nil && candUUID != "" && candUUID == storedUUID {
				continue
			}
		}

		filtered = append(filtered, c)
	}

	return filtered
}

// DetectPartitionName derives the child partition path for a drive
func DetectPartitionName(device string) string {
	device = strings.TrimSpace(device)
	if strings.Contains(device, "nvme") || strings.Contains(device, "mmcblk") {
		return device + "p1"
	}
	return device + "1"
}
