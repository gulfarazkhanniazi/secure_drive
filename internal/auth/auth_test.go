package auth

import (
	"os"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"secure-drive/internal/config"
	"secure-drive/internal/logger"
)

func TestMain(m *testing.M) {
	// Initialize logger so Audit.Log calls don't panic
	logger.InitLogger(os.DevNull)

	// Set default config for GetManagerTimeout and GetSessionTimeout
	config.AppConfig = &config.Config{}
	config.AppConfig.Security.ManagerTimeout = 300
	config.AppConfig.Security.SessionTimeout = 900
	config.AppConfig.Security.AutoLockTimeout = 600

	os.Exit(m.Run())
}

func TestTOTPVerification(t *testing.T) {
	// Generate a secret
	secret, err := GenerateSecret("TestUser", "SecureDrive")
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	// Generate current code
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	// Verify code
	if !VerifyCode(secret, code) {
		t.Errorf("VerifyCode failed to validate a correct TOTP code")
	}

	// Verify invalid code
	if VerifyCode(secret, "000000") {
		t.Errorf("VerifyCode accepted an invalid TOTP code")
	}
}

func TestSessionManagement(t *testing.T) {
	token := CreateSession("Boss", "Boss")
	if token == "" {
		t.Fatalf("CreateSession returned empty token")
	}

	sess, ok := ValidateSessionToken(token)
	if !ok || sess.Username != "Boss" || sess.Role != "Boss" {
		t.Errorf("ValidateSessionToken failed to validate session")
	}

	RemoveSession(token)
	_, ok = ValidateSessionToken(token)
	if ok {
		t.Errorf("ValidateSessionToken succeeded for a removed session")
	}
}

func TestManagerAuthorizationEngine(t *testing.T) {
	// Clean sessions and logins
	sessionsMu.Lock()
	sessions = make(map[string]*Session)
	sessionsMu.Unlock()

	managerLoginsMu.Lock()
	managerLogins = make(map[string]time.Time)
	managerLoginsMu.Unlock()

	lastSessionStateMu.Lock()
	lastSessionState = make(map[string]string)
	lastSessionStateMu.Unlock()

	// 1. Initially, gate should be closed
	open, reason := IsManagerGateOpen()
	if open {
		t.Errorf("gate should be closed initially")
	}
	if reason != "neither_manager_active" {
		t.Errorf("expected neither_manager_active, got %s", reason)
	}

	// 2. Log in Manager1
	token1 := CreateSession("Manager1", "Manager")
	UpdateManagerLoginTime("Manager1")

	// Gate should still be closed, waiting for Manager2
	open, reason = IsManagerGateOpen()
	if open {
		t.Errorf("gate should be closed with only Manager1 active")
	}
	if reason != "manager2_not_logged_in" {
		t.Errorf("expected manager2_not_logged_in, got %s", reason)
	}

	// 3. Log in Manager2
	token2 := CreateSession("Manager2", "Manager")
	UpdateManagerLoginTime("Manager2")

	// Gate should now be open
	open, reason = IsManagerGateOpen()
	if !open {
		t.Errorf("gate should be open with both active: %s", reason)
	}

	// 4. Test countdown time left
	// Since both are active, countdown should be 0
	left := GetManagerCountdownTimeLeft()
	if left != 0 {
		t.Errorf("expected countdown time left to be 0 when both are active, got %d", left)
	}

	// 5. Test logout of Manager1 closes the gate
	RecordLogoutReason("Manager1")
	RemoveSession(token1)

	open, reason = IsManagerGateOpen()
	if open {
		t.Errorf("gate should be closed after Manager1 logs out")
	}
	if reason != "manager1_logout" {
		t.Errorf("expected manager1_logout, got %s", reason)
	}

	// Cleanup Manager2 too
	RecordLogoutReason("Manager2")
	RemoveSession(token2)
}

func TestManagerJoinWindowTimeout(t *testing.T) {
	// Clean sessions and logins
	sessionsMu.Lock()
	sessions = make(map[string]*Session)
	sessionsMu.Unlock()

	managerLoginsMu.Lock()
	managerLogins = make(map[string]time.Time)
	managerLoginsMu.Unlock()

	// 1. Log in Manager1
	token1 := CreateSession("Manager1", "Manager")
	UpdateManagerLoginTime("Manager1")

	// Set Manager1's login time to 400 seconds ago (exceeding 300s timeout)
	managerLoginsMu.Lock()
	managerLogins["manager1"] = time.Now().Add(-400 * time.Second)
	managerLoginsMu.Unlock()

	// 2. Log in Manager2 now
	token2 := CreateSession("Manager2", "Manager")
	UpdateManagerLoginTime("Manager2")

	// Gate should be closed due to window expiration
	open, reason := IsManagerGateOpen()
	if open {
		t.Errorf("gate should be closed due to window expiration")
	}
	if reason != "window_expired" {
		t.Errorf("expected window_expired, got %s", reason)
	}

	// 3. Re-authenticate Manager1
	UpdateManagerLoginTime("Manager1")

	// Gate should open now
	open, reason = IsManagerGateOpen()
	if !open {
		t.Errorf("gate should be open after Manager1 re-authenticates, got: %s", reason)
	}

	// Cleanup
	RemoveSession(token1)
	RemoveSession(token2)
}

func TestTOTPLockout(t *testing.T) {
	username := "TestRateLimitUser"
	
	// Reset any existing state
	ResetFailedAttempts(username)
	
	// 1. Should not be locked out initially
	locked, _ := CheckLockout(username)
	if locked {
		t.Fatalf("user was locked out initially")
	}
	
	// 2. Perform 4 failed attempts
	for i := 0; i < 4; i++ {
		lockoutTriggered := RecordFailedAttempt(username)
		if lockoutTriggered {
			t.Fatalf("lockout triggered prematurely at attempt %d", i+1)
		}
	}
	
	// Still not locked out
	locked, _ = CheckLockout(username)
	if locked {
		t.Fatalf("user was locked out after only 4 attempts")
	}
	
	// 3. 5th failed attempt triggers lockout
	lockoutTriggered := RecordFailedAttempt(username)
	if !lockoutTriggered {
		t.Fatalf("lockout not triggered at 5th attempt")
	}
	
	// Verify lockout state is active
	locked, duration := CheckLockout(username)
	if !locked {
		t.Fatalf("CheckLockout returned false, expected true")
	}
	if duration <= 14*time.Minute {
		t.Errorf("expected lockout duration to be around 15 minutes, got %v", duration)
	}
	
	// 4. Reset/Success resets failed attempts
	ResetFailedAttempts(username)
	locked, _ = CheckLockout(username)
	if locked {
		t.Errorf("lockout was not cleared after reset")
	}
}

