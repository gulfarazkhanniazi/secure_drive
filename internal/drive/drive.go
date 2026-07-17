package drive

import (
	"os"
	"os/exec"
	"strings"

	"secure-drive/internal/config"
)

type DriveStatus struct {
	DeviceExists bool
	MapperOpen   bool
	Mounted      bool
}

func GetDriveStatus(cfg *config.Config) DriveStatus {
	if IsMockMode() {
		mu.Lock()
		defer mu.Unlock()
		return DriveStatus{
			DeviceExists: true,
			MapperOpen:   mockUnlocked,
			Mounted:      mockMounted,
		}
	}

	status := DriveStatus{}

	// Check device exists
	if _, err := os.Stat(cfg.Drive.Device); err == nil {
		status.DeviceExists = true
	}

	// Check mapper exists
	if _, err := os.Stat("/dev/mapper/" + cfg.Drive.Mapper); err == nil {
		status.MapperOpen = true
	}

	// Check mount status
	cmd := exec.Command("mount")
	output, err := cmd.Output()

	if err == nil {
		if strings.Contains(string(output), cfg.Drive.MountPoint) {
			status.Mounted = true
		}
	}

	return status
}
