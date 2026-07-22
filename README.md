# Secure Drive Controller

A production-ready, Go-based service designed to securely manage access to LUKS-encrypted block devices on Linux servers. The service provides MFA-controlled decryption, mount lifecycle automation using TOTP authorization, and automated drive onboarding directly from the web dashboard.

---

## Key Features

1. **Automated Drive Onboarding (B1–B5)**:
   - **Candidate Discovery**: Automatically scans server block devices (`lsblk -J`), detecting state (`EMPTY`, `HAS_PARTITIONS`, `HAS_LUKS`, `HAS_FILESYSTEM`).
   - **Root Disk Safety Resolution**: Programmatically resolves the system root mount (`findmnt -no SOURCE /`), traces parent physical disks, and excludes both the root disk and currently configured drives.
   - **Boss-Only Authorization**: Onboarding is restricted exclusively to the `Boss` role. Any unauthorized request returns `403 Forbidden` and logs `UNAUTHORIZED_ONBOARD_ATTEMPT`.
   - **Destructive Confirmation Modal**: Interactive modal requiring explicit checkbox confirmation, exact device path entry (e.g. `/dev/sdb`), and strong recovery passphrase entry (min 12 chars).
   - **14-Step Setup Pipeline**: Executes `wipefs`, `parted` GPT, LUKS2 formatting (Keyslot 0 passphrase), 4KB random keyfile generation (Keyslot 1), `cryptsetup open`, `mkfs.ext4`, mount read/write test, `cryptsetup close`, and atomic `config.yaml` update.
   - **Passphrase Memory Safety**: Passphrases are piped directly to `cryptsetup` via `cmd.Stdin` pipes and immediately zeroed out in memory using `runtime.KeepAlive`. Passphrases are never logged or stored on disk.
   - **Live Progress & Failure Reporting**: Real-time progress bar (Step 1/14 to 14/14), step status messages, and exact step error reporting with automatic non-destructive cleanup (`CleanupPartial`).

2. **Independent Manager Sessions with Live AND-Gate**:
   - **Manager1 and Manager2 log in independently** on their own devices using their own TOTP codes.
   - A live, continuously-evaluated server-side AND-gate controls all drive operations: both manager sessions must be active and their logins must have occurred within the `managerTimeout` window.
   - If either manager logs out or their session expires while the drive is unlocked, the drive is **locked immediately**.

3. **Boss Role Independence**:
   - Boss logs in with a single TOTP code for instant, independent drive operations and onboarding privileges.

4. **Real-Time Manager Presence Dashboard**:
   - Live presence state for Manager1 and Manager2 (`Active`, `Not logged in`, `Session expired`) and join window countdown.

5. **Platform-Independent Mock Mode**:
   - Full mock mode support (`MOCK_MODE=true` or running on macOS/Windows) simulates drive discovery and 14-step onboarding execution for safe development and unit testing.

---

## Directory Structure

```
secure_drive/
├── cmd/
│   └── secure-drive/
│       └── main.go                  # Main service entry point
├── internal/
│   ├── config/
│   │   └── config.go                # Atomic configuration updates & schema
│   ├── logger/
│   │   ├── logger.go                # Log initialization
│   │   └── audit.go                 # Structured audit trail parser
│   ├── auth/
│   │   ├── auth.go                  # Independent session management & live AND-gate engine
│   │   ├── auth_test.go             # Tests: TOTP, sessions, AND-gate, join window, lockout
│   │   ├── totp.go                  # TOTP cryptographic verifications
│   │   ├── users.go                 # User profile load and storage
│   │   └── setup.go                 # Startup user profile initialization
│   ├── drive/
│   │   ├── luks.go                  # LUKS/mount lifecycle (AND-gate enforcement, mock mode)
│   │   ├── drive.go                 # Device status check queries
│   │   ├── onboard.go               # Candidate drive discovery & root disk safety resolver
│   │   ├── pipeline.go              # 14-step LUKS onboarding pipeline & status tracker
│   │   ├── drive_test.go            # Tests: keyfile, device presence, concurrent unlocks
│   │   └── onboard_test.go          # Tests: candidate filtering, safety checks, mock pipeline
│   └── server/
│       ├── server.go                # HTTP handlers, API routes, presence watcher
│       └── templates/
│           ├── index.html           # Glassmorphic real-time dashboard (onboarding UI + modal)
│           └── logs.html            # Dark-themed audit log viewer
├── config.yaml                      # Global daemon parameters
├── users.json                       # Persistent credential secrets
├── secure-drive.service             # Systemd service unit template
└── README.md                        # Documentation
```

---

## Automated Drive Onboarding Pipeline Architecture

### Design Decision: Dual Keyslots
- **Keyslot 0 (User Passphrase)**: Created during Step 6 (`cryptsetup luksFormat`). Passed via stdin pipe. Provides a human-memorable recovery method if physical server access is needed.
- **Keyslot 1 (Server Keyfile)**: Created during Step 8 (`cryptsetup luksAddKey`). High-entropy 4KB keyfile at `/etc/secure-drive/keyfile` (permissions `0600`). Used by the server for automated unlocking.

### Pipeline Steps (1 to 14)

| Step | Description | Command / Action | Timeout |
|---|---|---|---|
| 1 | Safety Pre-flight | `GetRootParentDisk()` check, `config.yaml` check, `blockdev --getsize64` | 30s |
| 2 | Wipe Signatures | `wipefs -a <device>` | 2 min |
| 3 | Create Partition Table | `parted <device> --script mklabel gpt` | 2 min |
| 4 | Create Primary Partition | `parted <device> --script mkpart primary 0% 100%` + `udevadm settle` | 2 min |
| 5 | Detect Partition Path | Auto-detects `/dev/sdb1` vs `/dev/nvme0n1p1` with settle loop | 10s |
| 6 | LUKS2 Formatting | `cryptsetup luksFormat --type luks2 ...` (Passphrase via stdin) | 5 min |
| 7 | Generate Server Keyfile | `dd if=/dev/urandom of=/etc/secure-drive/keyfile bs=1024 count=4` + `chmod 600` | 1 min |
| 8 | Enroll Keyfile | `cryptsetup luksAddKey <partition> <keyfile>` (Passphrase via stdin) | 3 min |
| 9 | Open Container | `cryptsetup open <partition> <mapperName> --key-file <keyfile>` | 2 min |
| 10 | Format ext4 Filesystem | `mkfs.ext4 -F /dev/mapper/<mapperName>` | 10 min |
| 11 | Create Mount Directory | `mkdir -p <mountPoint>` | 30s |
| 12 | Mount Validation | `mount` -> write test file -> readback -> `umount` | 1 min |
| 13 | Close Container | `cryptsetup close <mapperName>` | 1 min |
| 14 | Update Configuration | Atomic write `config.yaml.tmp` -> rename to `config.yaml` | 30s |

---

## API Reference

### Drive Onboarding Endpoints (Boss-Only)

- **`GET /api/drives/candidates`**:
  Returns list of candidate block devices excluding system root disk and currently configured drive.
  *Response*: `{"candidates": [{"name": "/dev/sdb", "size": "100G", "model": "Data Disk", "isEmpty": true, "state": "EMPTY"}]}`

- **`POST /api/drives/onboard`**:
  Starts the 14-step onboarding pipeline asynchronously.
  *Payload*: `{"device": "/dev/sdb", "confirmationDevice": "/dev/sdb", "confirmedCheckbox": true, "passphrase": "StrongPassword123!", "passphraseConfirm": "StrongPassword123!", "mapperName": "secure-data", "mountPoint": "/mnt/secure"}`

- **`GET /api/drives/onboard/status`**:
  Returns real-time status of current or last onboarding run.
  *Response*: `{"isRunning": false, "currentStep": 14, "totalSteps": 14, "status": "SUCCESS", "steps": [...]}`

---

## Running Automated Tests

```bash
go test -v ./...
```

Tests cover:
- Candidate drive detection and root disk safety exclusion
- Partition path naming (`/dev/sdb1` vs `/dev/nvme0n1p1`)
- Input sanitization (device paths & passphrase length >= 12)
- End-to-end 14-step mock mode pipeline execution
- Rejection of invalid confirmation device paths / unchecked confirmation
- TOTP verification and rate-limiting
- Independent manager sessions & live AND-gate logic
- Keyfile permission checks & concurrent unlock safety

---

## Audit Events Reference

| Event | Description |
|---|---|
| `DRIVE_ONBOARD_START` | Onboarding pipeline initiated by Boss |
| `DRIVE_ONBOARD_SUCCESS` | Onboarding completed successfully |
| `DRIVE_ONBOARD_FAIL` | Pipeline failed at specific step with error details |
| `UNAUTHORIZED_ONBOARD_ATTEMPT` | Non-Boss user attempted drive onboarding |
| `MANAGER1_SESSION_STARTED` | Manager1 session established |
| `MANAGER2_SESSION_STARTED` | Manager2 session established |
| `DUAL_MANAGER_GATE_OPEN` | AND-gate opened (both managers active) |
| `DUAL_MANAGER_GATE_CLOSED` | AND-gate closed |
| `DRIVE_UNLOCK` | Encrypted drive opened and mounted |
| `DRIVE_LOCK` | Encrypted drive unmounted and container closed |
