package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

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
	timeout := 2 // 2 seconds

	// Reset approvals
	ClearManagerApprovals()

	// 1. Manager 1 approves
	unlocked, msg, err := RecordApproval("Manager1", timeout)
	if err != nil {
		t.Fatalf("RecordApproval failed: %v", err)
	}
	if unlocked {
		t.Errorf("RecordApproval unlocked the drive with only one manager")
	}
	if msg == "" {
		t.Errorf("Expected status message from RecordApproval")
	}

	// 2. Manager 2 approves within timeout
	unlocked, _, err = RecordApproval("Manager2", timeout)
	if err != nil {
		t.Fatalf("RecordApproval failed: %v", err)
	}
	if !unlocked {
		t.Errorf("RecordApproval failed to unlock with both managers approved")
	}

	// 3. Test timeout: Manager 1 approves, wait 3 seconds, Manager 2 approves
	ClearManagerApprovals()
	unlocked, _, _ = RecordApproval("Manager1", timeout)
	if unlocked {
		t.Errorf("Unlock triggered prematurely")
	}

	time.Sleep(3 * time.Second)

	unlocked, _, _ = RecordApproval("Manager2", timeout)
	if unlocked {
		t.Errorf("Drive unlocked after approval timeout had expired")
	}
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

