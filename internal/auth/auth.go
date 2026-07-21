package auth

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"

	"secure-drive/internal/config"
	"secure-drive/internal/logger"
)

type Session struct {
	Token     string
	Username  string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type UserLoginState struct {
	FailedAttempts []time.Time
	LockedUntil    time.Time
}

var (
	sessionsMu sync.RWMutex
	sessions   = make(map[string]*Session)

	managerLoginsMu sync.Mutex
	managerLogins   = make(map[string]time.Time) // lowercase username -> last successful login time

	lastSessionStateMu sync.Mutex
	lastSessionState   = make(map[string]string) // lowercase username -> "active" | "logged_out" | "expired"

	logoutReasonMu sync.Mutex
	lastLogoutUser = ""
	lastLogoutTime time.Time

	GateOpenMu sync.Mutex
	IsGateOpen = false

	lockoutMu    sync.Mutex
	userLockouts = make(map[string]*UserLoginState)
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
	timeout := time.Duration(config.GetSessionTimeout()) * time.Second
	sessions[token] = &Session{
		Token:     token,
		Username:  username,
		Role:      role,
		CreatedAt: now,
		ExpiresAt: now.Add(timeout),
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
		logger.Audit.Log("SESSION_EXPIRED", sess.Username, "SUCCESS")
		delete(sessions, token)
		return nil, false
	}

	// Slide expiration
	timeout := time.Duration(config.GetSessionTimeout()) * time.Second
	sess.ExpiresAt = time.Now().Add(timeout)
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

func UpdateManagerLoginTime(username string) {
	managerLoginsMu.Lock()
	managerLogins[strings.ToLower(username)] = time.Now()
	managerLoginsMu.Unlock()

	lastSessionStateMu.Lock()
	lastSessionState[strings.ToLower(username)] = "active"
	lastSessionStateMu.Unlock()
}

func RecordLogoutReason(username string) {
	logoutReasonMu.Lock()
	lastLogoutUser = strings.ToLower(username)
	lastLogoutTime = time.Now()
	logoutReasonMu.Unlock()

	lastSessionStateMu.Lock()
	lastSessionState[strings.ToLower(username)] = "logged_out"
	lastSessionStateMu.Unlock()
}

func GetLastLogout(username string) bool {
	logoutReasonMu.Lock()
	defer logoutReasonMu.Unlock()
	if lastLogoutUser == strings.ToLower(username) && time.Since(lastLogoutTime) < 5*time.Second {
		return true
	}
	return false
}

func IsManagerSessionActive(username string) (bool, time.Time) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	active := false
	var maxExpiry time.Time
	userKey := strings.ToLower(username)
	for token, sess := range sessions {
		if strings.ToLower(sess.Username) == userKey {
			if time.Now().Before(sess.ExpiresAt) {
				active = true
				if sess.ExpiresAt.After(maxExpiry) {
					maxExpiry = sess.ExpiresAt
				}
			} else {
				// Clean up expired session
				logger.Audit.Log("SESSION_EXPIRED", sess.Username, "SUCCESS")
				delete(sessions, token)

				lastSessionStateMu.Lock()
				if lastSessionState[userKey] == "active" {
					lastSessionState[userKey] = "expired"
				}
				lastSessionStateMu.Unlock()
			}
		}
	}
	return active, maxExpiry
}

func IsManagerGateOpen() (bool, string) {
	m1Active, _ := IsManagerSessionActive("manager1")
	m2Active, _ := IsManagerSessionActive("manager2")

	if !m1Active && !m2Active {
		return false, "neither_manager_active"
	}

	if !m1Active {
		lastSessionStateMu.Lock()
		state := lastSessionState["manager1"]
		lastSessionStateMu.Unlock()
		if state == "logged_out" {
			return false, "manager1_logout"
		} else if state == "expired" {
			return false, "manager1_session_expired"
		}
		return false, "manager1_not_logged_in"
	}

	if !m2Active {
		lastSessionStateMu.Lock()
		state := lastSessionState["manager2"]
		lastSessionStateMu.Unlock()
		if state == "logged_out" {
			return false, "manager2_logout"
		} else if state == "expired" {
			return false, "manager2_session_expired"
		}
		return false, "manager2_not_logged_in"
	}

	// Both are active. Now check the login window.
	managerLoginsMu.Lock()
	t1 := managerLogins["manager1"]
	t2 := managerLogins["manager2"]
	managerLoginsMu.Unlock()

	timeout := time.Duration(config.GetManagerTimeout()) * time.Second
	diff := t1.Sub(t2)
	if diff < 0 {
		diff = -diff
	}

	if diff > timeout {
		return false, "window_expired"
	}

	return true, ""
}

func GetManagerCountdownTimeLeft() int {
	m1Active, _ := IsManagerSessionActive("manager1")
	m2Active, _ := IsManagerSessionActive("manager2")

	if m1Active == m2Active {
		// If both are active or neither is active, no active countdown
		return 0
	}

	managerLoginsMu.Lock()
	t1 := managerLogins["manager1"]
	t2 := managerLogins["manager2"]
	managerLoginsMu.Unlock()

	var start time.Time
	if m1Active {
		start = t1
	} else {
		start = t2
	}

	if start.IsZero() {
		return 0
	}

	timeout := time.Duration(config.GetManagerTimeout()) * time.Second
	elapsed := time.Since(start)
	if elapsed >= timeout {
		return 0
	}
	return int((timeout - elapsed).Seconds())
}

func GetManagerPresence(username string) string {
	active, _ := IsManagerSessionActive(username)
	if active {
		return "Active"
	}

	lastSessionStateMu.Lock()
	state := lastSessionState[strings.ToLower(username)]
	lastSessionStateMu.Unlock()

	if state == "expired" {
		return "Session expired"
	}
	return "Not logged in"
}

func CheckLockout(username string) (bool, time.Duration) {
	lockoutMu.Lock()
	defer lockoutMu.Unlock()

	userKey := strings.ToLower(username)
	state, exists := userLockouts[userKey]
	if !exists {
		return false, 0
	}

	if time.Now().Before(state.LockedUntil) {
		return true, time.Until(state.LockedUntil)
	}

	return false, 0
}

func RecordFailedAttempt(username string) bool {
	lockoutMu.Lock()
	defer lockoutMu.Unlock()

	userKey := strings.ToLower(username)
	state, exists := userLockouts[userKey]
	if !exists {
		state = &UserLoginState{}
		userLockouts[userKey] = state
	}

	now := time.Now()
	state.FailedAttempts = append(state.FailedAttempts, now)

	// Clean up attempts older than 5 minutes
	cutoff := now.Add(-5 * time.Minute)
	var validAttempts []time.Time
	for _, t := range state.FailedAttempts {
		if t.After(cutoff) {
			validAttempts = append(validAttempts, t)
		}
	}
	state.FailedAttempts = validAttempts

	if len(state.FailedAttempts) >= 5 {
		state.LockedUntil = now.Add(15 * time.Minute)
		return true // Lockout triggered
	}
	return false
}

func ResetFailedAttempts(username string) {
	lockoutMu.Lock()
	defer lockoutMu.Unlock()

	userKey := strings.ToLower(username)
	delete(userLockouts, userKey)
}

