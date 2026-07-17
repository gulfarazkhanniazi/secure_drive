package auth

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Session struct {
	Token     string
	Username  string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

var (
	sessionsMu sync.RWMutex
	sessions   = make(map[string]*Session)

	approvalMu sync.Mutex
	approvals  = make(map[string]time.Time) // lowercase username -> approval time
)

func generateRandomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func CreateSession(username, role string) string {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	token := generateRandomToken()
	now := time.Now()
	sessions[token] = &Session{
		Token:     token,
		Username:  username,
		Role:      role,
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}
	return token
}

func ValidateSessionToken(token string) (*Session, bool) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	sess, exists := sessions[token]
	if !exists {
		return nil, false
	}

	if time.Now().After(sess.ExpiresAt) {
		delete(sessions, token)
		return nil, false
	}

	// Slide expiration
	sess.ExpiresAt = time.Now().Add(30 * time.Minute)
	return sess, true
}

func RemoveSession(token string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	delete(sessions, token)
}

func GetUser(username string) (User, bool) {
	u := strings.ToLower(username)
	if u == "boss" {
		return AppUsers.Boss, true
	} else if u == "manager1" {
		return AppUsers.Manager1, true
	} else if u == "manager2" {
		return AppUsers.Manager2, true
	}
	return User{}, false
}

type ApprovalsStatus struct {
	Manager1Approved bool
	Manager1TimeLeft int
	Manager2Approved bool
	Manager2TimeLeft int
}

func GetApprovalsStatus(timeoutSec int) ApprovalsStatus {
	approvalMu.Lock()
	defer approvalMu.Unlock()

	status := ApprovalsStatus{}
	now := time.Now()
	timeout := time.Duration(timeoutSec) * time.Second

	if t, ok := approvals["manager1"]; ok {
		elapsed := now.Sub(t)
		if elapsed < timeout {
			status.Manager1Approved = true
			status.Manager1TimeLeft = int((timeout - elapsed).Seconds())
		} else {
			delete(approvals, "manager1")
		}
	}

	if t, ok := approvals["manager2"]; ok {
		elapsed := now.Sub(t)
		if elapsed < timeout {
			status.Manager2Approved = true
			status.Manager2TimeLeft = int((timeout - elapsed).Seconds())
		} else {
			delete(approvals, "manager2")
		}
	}

	return status
}

func ClearManagerApprovals() {
	approvalMu.Lock()
	defer approvalMu.Unlock()
	approvals = make(map[string]time.Time)
}

func RecordApproval(username string, timeoutSec int) (bool, string, error) {
	approvalMu.Lock()
	defer approvalMu.Unlock()

	userKey := strings.ToLower(username)
	if userKey != "manager1" && userKey != "manager2" {
		return false, "", fmt.Errorf("invalid user for manager approval: %s", username)
	}

	otherKey := "manager2"
	if userKey == "manager2" {
		otherKey = "manager1"
	}

	now := time.Now()
	timeout := time.Duration(timeoutSec) * time.Second

	// Check other manager approval
	if t, ok := approvals[otherKey]; ok && now.Sub(t) < timeout {
		approvals = make(map[string]time.Time) // Reset
		return true, fmt.Sprintf("Both %s and %s approved. Unlocking drive.", otherKey, userKey), nil
	}

	approvals[userKey] = now
	timeLeft := int(timeout.Seconds())
	return false, fmt.Sprintf("%s approved. Waiting for %s within %d seconds.", username, otherKey, timeLeft), nil
}
