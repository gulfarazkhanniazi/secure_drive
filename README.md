# Secure Drive Controller

A production-ready, Go-based service designed to securely manage access to a single LUKS-encrypted block device on Linux servers. The service provides MFA-controlled decryption and mount lifecycle automation using TOTP authorization.

---

## Key Features

1. **Robust Multi-Factor Authorization Rules**:
   - **Boss Identity**: Can unlock and mount the drive instantly using a valid TOTP code.
   - **Managers (Manager 1 + Manager 2)**: Neither manager can unlock alone. Both managers must co-sign (authenticate via TOTP) within a configurable timeout window to decrypt and mount the drive.
2. **Dynamic In-Memory QR Codes**: Eliminates filesystem write permissions and local PNG garbage. QR codes are generated dynamically in-memory, base64-encoded, and rendered as inline Data URIs inside the browser setup tab.
3. **Embedded UI Assets (`go:embed`)**: Compiles dashboard HTML files directly into the Go executable, creating a 100% self-contained binary that can be deployed anywhere without asset-copying steps.
4. **Daemon Auto-Lock Timer**: An active background daemon continuously checks the mount duration, automatically unmounting and closing the LUKS container when the auto-lock timeout is reached.
5. **Platform-Independent Mock Mode**: Automatically fallback to memory-simulated drive operations when running on macOS/Windows, allowing developers to fully test the web interfaces and state machines locally.

---

## Directory Structure

```
secure_drive/
├── cmd/
│   └── secure-drive/
│       └── main.go                  # Main service entry point
├── internal/
│   ├── config/
│   │   └── config.go                # Configuration parsing and schema definitions
│   ├── logger/
│   │   ├── logger.go                # Log initialization
│   │   └── audit.go                 # Structured audit trail parser
│   ├── auth/
│   │   ├── auth.go                  # Session & dual co-signing state engine
│   │   ├── totp.go                  # TOTP cryptographic verifications
│   │   ├── users.go                 # User profile load and storage
│   │   └── setup.go                 # Startup user profile initialization
│   ├── drive/
│   │   ├── luks.go                  # LUKS and mounting (with simulated Mock Mode)
│   │   └── drive.go                 # Device status check queries
│   └── server/
│       ├── server.go                # HTTP handlers and dynamically generated QR codes
│       └── templates/
│           ├── index.html           # Glassmorphic, real-time update dashboard
│           └── logs.html            # Dark-themed audit log viewer
├── config.yaml                      # Global daemon parameters
├── users.json                       # Persistent credential secrets
├── secure-drive.service             # Systemd service unit template
└── README.md                        # Documentation
```

---

## Running Locally (Mac / Development)

To run the application locally on macOS or in development environments where physical LUKS block devices are not present, use **Mock Mode**:

1. **Run the server**:
   ```bash
   MOCK_MODE=true go run cmd/secure-drive/main.go
   ```
2. **Access the web dashboard**:
   Open [http://localhost:8080](http://localhost:8080) in your web browser.
3. **TOTP Authenticator Setup**:
   - Log in using one of the users listed in the section below.
   - Go to the **Authenticator Setup** tab.
   - Scan the QR code shown for your user using a TOTP application (Google Authenticator, Microsoft Authenticator, 2FAS, Authy, etc.).
4. **Test the Unlocking Actions**:
   - Log in as the **Boss** and click the **Unlock** button. Notice that the drive status shifts to `UNLOCKED` instantly, and the auto-lock countdown bar ticks down.
   - Log out, log in as **Manager 1**, and click **Register Co-Signature**. The approval is registered. Then log out, log in as **Manager 2** within 300 seconds, and register approval. The drive unlocks!

---

## Default User Accounts

During the initial run, the application auto-populates `users.json` with random TOTP secrets. Below are the default accounts:

* **Boss** (Role: `Boss`) - Full Unlocking Authority
* **Manager1** (Role: `Manager`) - Co-Signer
* **Manager2** (Role: `Manager`) - Co-Signer

*Note: You can scan their QR codes directly from the "Authenticator Setup" tab inside the dashboard once authenticated.*

---

## Running Automated Tests

Run the test suite covering TOTP verification, session storage, and the manager approval timeout window:

```bash
go test -v ./...
```

---

## Production Linux Deployment

To deploy the Secure Drive Controller as a systemd background service on your Linux server:

### Step 1: Compile the binary for Linux
On your development machine, compile the code targeting Linux architectures:
```bash
GOOS=linux GOARCH=amd64 go build -o secure-drive cmd/secure-drive/main.go
```

### Step 2: Install files on the target server
Copy the compiled binary, configuration files, and `users.json` to the target server:
```bash
# 1. Copy the binary to bin
sudo cp secure-drive /usr/local/bin/

# 2. Create the configuration directory
sudo mkdir -p /etc/secure-drive

# 3. Copy configuration and user files (ensure the service can read/write users.json)
sudo cp config.yaml users.json /etc/secure-drive/
```

### Step 3: Set up LUKS Block Device Keyfile
Configure the keyfile to automatically unlock the drive (defined in `config.yaml` as `/etc/secure-drive/keyfile`):
```bash
# 1. Generate a secure key file
sudo mkdir -p /etc/secure-drive/
sudo dd if=/dev/urandom of=/etc/secure-drive/keyfile bs=1024 count=4
sudo chmod 600 /etc/secure-drive/keyfile

# 2. Add the keyfile to your LUKS device (e.g. /dev/sdb1)
sudo cryptsetup luksAddKey /dev/sdb1 /etc/secure-drive/keyfile
```

### Step 4: Install and Enable the Service
```bash
# 1. Copy the service unit file
sudo cp secure-drive.service /etc/systemd/system/

# 2. Reload the systemd daemon
sudo systemctl daemon-reload

# 3. Enable and start the service
sudo systemctl enable secure-drive
sudo systemctl start secure-drive

# 4. Check the service status and logs
sudo systemctl status secure-drive
sudo journalctl -u secure-drive -f
```

---

## Enhanced Security Features & Run-Time Configuration

### 1. Dual-Manager Login Co-Signing Flow
Managers (Manager 1 and Manager 2) co-sign directly on the **Login Page** before any session is created. 
- Either manager can enter their TOTP first.
- The system remembers the first manager's verification (for up to the configured Manager Timeout, e.g. 5 minutes) and displays a pending status showing the remaining time.
- The second manager can then verify their TOTP. Once both are verified, the session is created under the identity `Managers`.
- No co-signing actions are needed post-login on the dashboard.

### 2. Runtime Timeout Settings
Authenticated users with unlock privileges can adjust security timeouts dynamically from the dashboard:
- **Auto-Lock Timeout**: Range of `60` seconds (1 min) to `3600` seconds (1 hour). Prevents unauthorized access after the drive is left unattended.
- **Session Idle Timeout**: Range of `60` seconds (1 min) to `86400` seconds (24 hours). Expired sessions require a fresh login (including TOTP validation).
- Settings updates are written **atomically** to `config.yaml` using a temporary write-and-rename mechanism protected by a mutex, surviving daemon restarts.
- Auto-lock daemon and HTTP sessions check these values dynamically at runtime.

### 3. Unclean Disconnect Safety & Recovery
If the physical storage drive is forcibly removed while decrypted and mounted:
- **Watcher Daemon**: A background thread polls every 3 seconds checking the presence of the block device. If the device disappears while the LUKS mapper is active, it logs a `CRITICAL` event: `UNEXPECTED_DEVICE_REMOVAL`.
- **Ejection Cleanup**: The watcher runs a best-effort recovery: executing lazy unmount (`umount -l`) and clearing mapper tables (`dmsetup remove`), transitioning state to `DISCONNECTED_UNEXPECTEDLY` to warn operators.
- **FS Checker (e2fsck)**: When the device is reconnected and unlocking is initiated, the system runs `e2fsck -p` on the mapper device. If unrecoverable filesystem errors are detected (exit code >= 4), mounting is blocked, reporting `FILESYSTEM_CHECK_FAILED`. On clean check/repair, it proceeds to mount and logs `FILESYSTEM_CHECK_PASSED` / `FILESYSTEM_REPAIRED`.
- **Fsync & Lock Syncing**: The service executes `fsync()` on its file handles after writes. Prior to any lock action, it executes system `sync` and checks for open file handles on the mount point (using `fuser -m`). If busy, it retries 3 times before failing the lock attempt with a clear error instead of forcing it.

> [!WARNING]
> **Filesystem Risk Disclosure**: While LUKS sector writes are atomic and mitigations like `fsync` and `sync` significantly reduce corruption windows, forced hardware ejections during active operations cannot guarantee zero data loss at the ext4/filesystem journal layer. This is an inherent physical storage limitation.

### 4. Concurrency Safety
All functions mutating or checking drive status share a package-level mutex (`mu`). Concurrent lock/unlock requests queue safely behind the mutex, verifying status under lock to avoid duplicate `cryptsetup open` or mount calls.

### 5. TOTP Rate Limiting
- The system tracks consecutive failed TOTP attempts per user in memory.
- After **5 consecutive failures** within a 5-minute rolling window, the user is locked out for a **15-minute cooldown** period.
- Lockout triggers are logged as: `USER_LOCKED_OUT user=<username> reason=too_many_failed_totp_attempts`.
- Successful logins reset the failure counter.

### 6. Keyfile Integrity Check
On application startup, before serving any web requests, the system checks the keyfile from `config.yaml`:
- The keyfile must exist.
- Permissions must be exactly `600` (or stricter, i.e., group/world must have no permissions).
- Owner must be root or the user running the application.
- If these checks fail, the application logs a `CRITICAL` error and refuses to start.

### 7. Audit Log Tamper Resistance
After every log write and at startup, the system sets the audit log to append-only: `chattr +a audit.log`.

> [!NOTE]
> **Tamper Resistance limitations**: Setting `+a` requires an ext4-compatible filesystem supporting filesystem attributes. While this raises the bar against accidental truncation or less-privileged compromise, it is a defense-in-depth measure; a fully compromised root process can still clear the attribute and alter logs.

### 8. Multiple Boss Accounts Check
If `users.json` defines more than one account with the role `Boss`, the application logs a startup warning:
`WARNING: multiple Boss-role accounts detected — each can unlock the drive independently without co-signing`.
This flags changes to the security architecture from a single trusted identity to a multi-boss instant-unlock model.
