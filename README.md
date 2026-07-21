# Secure Drive Controller

A production-ready, Go-based service designed to securely manage access to a single LUKS-encrypted block device on Linux servers. The service provides MFA-controlled decryption and mount lifecycle automation using TOTP authorization.

---

## Key Features

1. **Independent Manager Sessions with Live AND-Gate**:
   - **Manager1 and Manager2 each log in independently** on their own devices using their own TOTP codes — there is no shared co-signing page.
   - Each successful login creates an independent, cookie-based session — exactly like Boss's session.
   - A live, continuously-evaluated server-side AND-gate controls all drive operations: both manager sessions must be active and their logins must have occurred within the `managerTimeout` window.
   - If either manager logs out or their session expires while the drive is unlocked, the drive is **locked immediately** (not at the next timeout cycle).

2. **Boss Role Unchanged**:
   - Boss logs in with a single TOTP code and gets instant, independent drive access. The AND-gate applies only to the Manager pair.

3. **Real-Time Manager Presence Dashboard**:
   - Every dashboard shows the live presence state of both managers (`Active`, `Not logged in`, or `Session expired`) via the existing 1-second polling endpoint.
   - A live join window countdown shows how long the first manager has to wait for the second (`Waiting for Manager2 — 4:12 remaining`).

4. **Dynamic In-Memory QR Codes**: QR codes are generated dynamically in-memory and rendered as inline Data URIs — no filesystem writes.

5. **Embedded UI Assets (`go:embed`)**: Dashboard HTML is compiled into the binary — fully self-contained, no asset-copying needed.

6. **Daemon Auto-Lock Timer**: Background daemon automatically locks the drive after the auto-lock timeout elapses.

7. **Platform-Independent Mock Mode**: Falls back to memory-simulated drive operations on macOS/Windows for local development.

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
│   │   ├── auth.go                  # Independent session management & live AND-gate engine
│   │   ├── auth_test.go             # Tests: TOTP, sessions, AND-gate, join window, lockout
│   │   ├── totp.go                  # TOTP cryptographic verifications
│   │   ├── users.go                 # User profile load and storage
│   │   └── setup.go                 # Startup user profile initialization
│   ├── drive/
│   │   ├── luks.go                  # LUKS/mount lifecycle (AND-gate enforcement, mock mode)
│   │   ├── drive.go                 # Device status check queries
│   │   └── drive_test.go            # Tests: keyfile, device presence, concurrent unlocks
│   └── server/
│       ├── server.go                # HTTP handlers, presence watcher, QR codes
│       └── templates/
│           ├── index.html           # Glassmorphic real-time dashboard (presence + countdown)
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
   - Log in using any of the users listed below.
   - Go to the **Authenticator Setup** tab.
   - Scan the QR code shown for your user using a TOTP application (Google Authenticator, Authy, 2FAS, etc.).

4. **Test the New Unlocking Flow**:
   - **Boss**: Log in as Boss — instant drive access with no co-signing required.
   - **Managers (new independent flow)**:
     - Open two browser tabs or two different browsers/devices.
     - Log in as **Manager1** in one. The dashboard will show "Waiting for Manager2 — 4:59 remaining."
     - Log in as **Manager2** in the other within the `managerTimeout` window.
     - Both dashboards now show the AND-gate open (both managers Active).
     - Either manager can click **Unlock** or **Lock**.
     - Log out one manager — the drive locks immediately and the dashboard shows the reason.

---

## Default User Accounts

During the initial run, the application auto-populates `users.json` with random TOTP secrets. Below are the default accounts:

* **Boss** (Role: `Boss`) — Full Unlocking Authority (instant single-identity)
* **Manager1** (Role: `Manager`) — Independent session; AND-gate required for drive operations
* **Manager2** (Role: `Manager`) — Independent session; AND-gate required for drive operations

*Note: Scan QR codes from the "Authenticator Setup" tab inside the dashboard once authenticated.*

---

## Running Automated Tests

```bash
go test -v ./...
```

Tests cover:
- TOTP code generation and verification
- Independent session management (create, validate, expire, remove)
- AND-gate: open when both managers active and within join window
- AND-gate: closed on logout, session expiry, or window timeout
- Join window: closes and re-arms on fresh re-authentication
- TOTP rate-limiting and lockout
- Keyfile permission checks
- Device presence verification
- Concurrent unlock requests (Boss and Managers) — confirms exactly one actual mount call under the mutex

---

## Production Linux Deployment

To deploy the Secure Drive Controller as a systemd background service on your Linux server:

### Step 1: Compile the binary for Linux
```bash
GOOS=linux GOARCH=amd64 go build -o secure-drive cmd/secure-drive/main.go
```

### Step 2: Install files on the target server
```bash
sudo cp secure-drive /usr/local/bin/
sudo mkdir -p /etc/secure-drive
sudo cp config.yaml users.json /etc/secure-drive/
```

### Step 3: Set up LUKS Block Device Keyfile
```bash
sudo mkdir -p /etc/secure-drive/
sudo dd if=/dev/urandom of=/etc/secure-drive/keyfile bs=1024 count=4
sudo chmod 600 /etc/secure-drive/keyfile
sudo cryptsetup luksAddKey /dev/sdb1 /etc/secure-drive/keyfile
```

### Step 4: Install and Enable the Service
```bash
sudo cp secure-drive.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable secure-drive
sudo systemctl start secure-drive
sudo systemctl status secure-drive
sudo journalctl -u secure-drive -f
```

---

## Enhanced Security Features & Run-Time Configuration

### 1. Independent Manager Sessions with Live AND-Gate (A1–A6)

Managers log in individually with their own TOTP on the standard `/login` page. A successful login creates an independent browser session and records the login timestamp.

- **A1 — Separate logins**: Each manager authenticates independently. No manager ever enters the other's credentials.
- **A2 — Live AND-gate**: Every drive operation (lock, unlock) checks in real-time that both manager sessions are active and within the `managerTimeout` join window. The gate is checked atomically under the package-level mutex — check-and-act is never a separate race.
- **A3 — Join window**: When the first manager logs in, a `managerTimeout`-second countdown begins. The countdown is re-armed every time a manager (re-)authenticates. Both managers' dashboards show the live countdown.
- **A4 — Emergency lock on gate closure**: If either manager logs out or their session expires while the drive is unlocked (by managers), the drive is locked immediately. The lock reason is stored and displayed in real-time on both dashboards.
- **A5 — Concurrent safety**: All lock/unlock/gate checks occur under the existing shared `mu` mutex. Concurrent requests are serialised; only one mount call is ever executed.
- **A6 — Live presence visibility**: `/api/status` returns `manager1Presence`, `manager2Presence`, `managerCountdownTimeLeft`, and `lockReason`. Both managers' dashboards update every second.

### 2. Runtime Timeout Settings
Authenticated users can adjust security timeouts dynamically:
- **Auto-Lock Timeout**: 60–3600 seconds.
- **Session Idle Timeout**: 60–86400 seconds.
- Settings are written atomically to `config.yaml` via a temp-write-and-rename protected by a mutex.

### 3. Unclean Disconnect Safety & Recovery
If the physical drive is forcibly removed while decrypted and mounted:
- **Watcher Daemon** polls every 3 seconds. On unexpected removal, logs `CRITICAL: UNEXPECTED_DEVICE_REMOVAL`.
- **Ejection Cleanup**: lazy umount + dmsetup remove, transitions state to `DISCONNECTED_UNEXPECTEDLY`.
- **FS Checker (e2fsck)**: On reconnection, runs `e2fsck -p`. On unrecoverable errors, blocks mount and reports `FILESYSTEM_CHECK_FAILED`.

### 4. Concurrency Safety
All state mutations (drive status, manager gate checks, lock/unlock) share a package-level mutex (`mu`). Concurrent requests safely serialise behind it.

### 5. TOTP Rate Limiting
After **5 consecutive TOTP failures** in a 5-minute window, a user is locked out for **15 minutes**. Successful logins reset the counter.

### 6. Keyfile Integrity Check
On startup, the keyfile is verified to exist, have permissions `600` or stricter, and be owned by root or the running user. Failure aborts startup.

### 7. Audit Log Tamper Resistance
The audit log is set append-only via `chattr +a` after every write (effective on ext4 Linux). This raises the bar against accidental truncation; a fully compromised root can still clear the attribute.

> [!NOTE]
> **Tamper Resistance limitation**: `chattr +a` requires ext4 support and only adds defense-in-depth — it does not replace a proper log-forwarding pipeline.

### 8. Multiple Boss Accounts Check
If `users.json` contains more than one `Boss`-role account, the service logs a startup warning. Each Boss can unlock the drive independently; this flags any unexpected escalation.

---

## Audit Events Reference

| Event | Meaning |
|---|---|
| `MANAGER1_SESSION_STARTED` | Manager1 logged in, session created |
| `MANAGER2_SESSION_STARTED` | Manager2 logged in, session created |
| `DUAL_MANAGER_GATE_OPEN` | Both sessions active and within join window |
| `DUAL_MANAGER_GATE_CLOSED` | Gate dropped below two active sessions |
| `DUAL_MANAGER_GATE_CLOSED action=auto_lock_triggered reason=<…>` | Drive locked immediately due to gate closure |
| `ACTION_BLOCKED reason=single_manager_only` | Drive operation rejected — only one manager active |
| `SESSION_EXPIRED` | A manager's session timed out |
| `LOGIN_SUCCESS` | Successful login for any user |
| `LOGIN_FAIL` | Failed login attempt |
| `USER_LOCKED_OUT` | TOTP rate-limit triggered |
| `LOGOUT` | Explicit logout |
| `DRIVE_UNLOCK` | Drive decrypted and mounted |
| `DRIVE_LOCK` | Drive unmounted and LUKS container closed |
| `AUTO_LOCK` | Drive locked by the auto-lock daemon |
| `UNEXPECTED_DEVICE_REMOVAL` | Physical drive removed while mounted |
