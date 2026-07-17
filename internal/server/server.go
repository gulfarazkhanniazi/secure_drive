package server

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"secure-drive/internal/auth"
	"secure-drive/internal/config"
	"secure-drive/internal/drive"
	"secure-drive/internal/logger"
)

//go:embed templates/*
var templatesFS embed.FS

type DashboardData struct {
	Title            string
	Status           string
	Device           string
	Mapper           string
	MountPoint       string
	LoggedIn         bool
	Username         string
	Role             string
	Manager1Approved bool
	Manager1TimeLeft int
	Manager2Approved bool
	Manager2TimeLeft int
	AutoLockTimeLeft int
	BossQR           string
	Manager1QR       string
	Manager2QR       string
	Error            string
	Success          string
	Logs             []logger.AuditEntry
}

var tmpl *template.Template

func getSessionUser(r *http.Request) (*auth.Session, bool) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil, false
	}
	return auth.ValidateSessionToken(cookie.Value)
}

func getQRCodeBase64(url string) (string, error) {
	png, err := qrcode.Encode(url, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

func StartServer(cfg *config.Config) {
	var err error

	// Parse templates from embedded FS
	tmpl, err = template.ParseFS(templatesFS, "templates/index.html", "templates/logs.html")
	if err != nil {
		log.Fatalf("Template parsing failed: %v", err)
	}

	// Main Dashboard handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		sess, ok := getSessionUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		statusStr := "LOCKED"
		if drive.IsUnlocked(cfg) {
			statusStr = "UNLOCKED"
		}

		// Calculate auto-lock remaining time
		autoLockTimeLeft := 0
		if drive.IsUnlocked(cfg) {
			ut := drive.GetUnlockTime()
			if !ut.IsZero() {
				elapsed := time.Since(ut)
				totalTimeout := time.Duration(cfg.Security.AutoLockTimeout) * time.Second
				if elapsed < totalTimeout {
					autoLockTimeLeft = int((totalTimeout - elapsed).Seconds())
				}
			}
		}

		// Get manager approvals
		appr := auth.GetApprovalsStatus(cfg.Security.ManagerTimeout)

		// Generate Base64 QR codes dynamically
		bossURL := auth.GenerateOTPURL(auth.AppUsers.Boss.Secret, auth.AppUsers.Boss.Account, auth.AppUsers.Boss.Issuer)
		bossQR, _ := getQRCodeBase64(bossURL)

		m1URL := auth.GenerateOTPURL(auth.AppUsers.Manager1.Secret, auth.AppUsers.Manager1.Account, auth.AppUsers.Manager1.Issuer)
		m1QR, _ := getQRCodeBase64(m1URL)

		m2URL := auth.GenerateOTPURL(auth.AppUsers.Manager2.Secret, auth.AppUsers.Manager2.Account, auth.AppUsers.Manager2.Issuer)
		m2QR, _ := getQRCodeBase64(m2URL)

		// Read audit logs for display
		logs, _ := logger.ReadAuditLog(cfg.Logging.File)
		if len(logs) > 20 {
			logs = logs[:20]
		}

		data := DashboardData{
			Title:            "Secure Drive Controller",
			Status:           statusStr,
			Device:           cfg.Drive.Device,
			Mapper:           cfg.Drive.Mapper,
			MountPoint:       cfg.Drive.MountPoint,
			LoggedIn:         true,
			Username:         sess.Username,
			Role:             sess.Role,
			Manager1Approved: appr.Manager1Approved,
			Manager1TimeLeft: appr.Manager1TimeLeft,
			Manager2Approved: appr.Manager2Approved,
			Manager2TimeLeft: appr.Manager2TimeLeft,
			AutoLockTimeLeft: autoLockTimeLeft,
			BossQR:           bossQR,
			Manager1QR:       m1QR,
			Manager2QR:       m2QR,
			Error:            r.URL.Query().Get("error"),
			Success:          r.URL.Query().Get("success"),
			Logs:             logs,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
			log.Printf("Template execute error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// Login GET & POST handlers
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := getSessionUser(r); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodGet {
			data := DashboardData{
				Title:    "Login - Secure Drive Controller",
				LoggedIn: false,
				Error:    r.URL.Query().Get("error"),
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Redirect(w, r, "/login?error=Invalid+form+submission", http.StatusSeeOther)
				return
			}

			username := r.FormValue("username")
			code := r.FormValue("code")

			user, exists := auth.GetUser(username)
			if !exists {
				logger.Audit.Log("LOGIN_FAIL", username, "UNKNOWN_USER")
				http.Redirect(w, r, "/login?error=Invalid+username+or+code", http.StatusSeeOther)
				return
			}

			if !auth.VerifyCode(user.Secret, code) {
				logger.Audit.Log("LOGIN_FAIL", username, "BAD_TOTP")
				http.Redirect(w, r, fmt.Sprintf("/login?error=Authentication+failed+for+%s", username), http.StatusSeeOther)
				return
			}

			// Successful Login
			token := auth.CreateSession(username, user.Role)
			cookie := &http.Cookie{
				Name:     "session_token",
				Value:    token,
				Expires:  time.Now().Add(30 * time.Minute),
				HttpOnly: true,
				Path:     "/",
			}
			http.SetCookie(w, cookie)

			logger.Audit.Log("LOGIN_SUCCESS", username, "SUCCESS")
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	})

	// Logout handler
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err == nil {
			auth.RemoveSession(cookie.Value)
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    "",
				Expires:  time.Unix(0, 0),
				MaxAge:   -1,
				HttpOnly: true,
				Path:     "/",
			})
			logger.Audit.Log("LOGOUT", "USER", "SUCCESS")
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	// Unlock handler (Boss only)
	http.HandleFunc("/unlock", func(w http.ResponseWriter, r *http.Request) {
		sess, ok := getSessionUser(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if strings.ToLower(sess.Username) != "boss" {
			logger.Audit.Log("UNAUTHORIZED_UNLOCK_ATTEMPT", sess.Username, "FAILURE")
			http.Redirect(w, r, "/?error=Only+the+Boss+can+unlock+directly", http.StatusSeeOther)
			return
		}

		if drive.IsUnlocked(cfg) {
			http.Redirect(w, r, "/?success=Drive+is+already+unlocked", http.StatusSeeOther)
			return
		}

		err := drive.UnlockDrive(cfg)
		if err != nil {
			log.Printf("Error unlocking drive: %v", err)
			logger.Audit.Log("DRIVE_UNLOCK", "Boss", "FAILURE")
			http.Redirect(w, r, fmt.Sprintf("/?error=Failed+to+unlock+drive:+%v", err), http.StatusSeeOther)
			return
		}

		logger.Audit.Log("DRIVE_UNLOCK", "Boss", "SUCCESS")
		auth.ClearManagerApprovals()
		http.Redirect(w, r, "/?success=Drive+unlocked+successfully+by+Boss", http.StatusSeeOther)
	})

	// Authorize handler (Managers only)
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		sess, ok := getSessionUser(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		usernameLower := strings.ToLower(sess.Username)
		if usernameLower != "manager1" && usernameLower != "manager2" {
			logger.Audit.Log("UNAUTHORIZED_APPROVAL_ATTEMPT", sess.Username, "FAILURE")
			http.Redirect(w, r, "/?error=Only+managers+can+authorize+unlocks", http.StatusSeeOther)
			return
		}

		if drive.IsUnlocked(cfg) {
			http.Redirect(w, r, "/?success=Drive+is+already+unlocked", http.StatusSeeOther)
			return
		}

		unlocked, msg, err := auth.RecordApproval(sess.Username, cfg.Security.ManagerTimeout)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/?error=%v", err), http.StatusSeeOther)
			return
		}

		logger.Audit.Log("MANAGER_APPROVAL", sess.Username, "SUCCESS")

		if unlocked {
			err := drive.UnlockDrive(cfg)
			if err != nil {
				log.Printf("Dual managers approved but drive unlock failed: %v", err)
				logger.Audit.Log("DRIVE_UNLOCK", "Manager1+Manager2", "FAILURE")
				http.Redirect(w, r, fmt.Sprintf("/?error=Managers+approved+but+unlock+failed:+%v", err), http.StatusSeeOther)
				return
			}
			logger.Audit.Log("DRIVE_UNLOCK", "Manager1+Manager2", "SUCCESS")
			http.Redirect(w, r, "/?success=Drive+unlocked+successfully+by+Dual+Manager+Approvals", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/?success=%s", msg), http.StatusSeeOther)
	})

	// Lock handler (All authenticated users)
	http.HandleFunc("/lock", func(w http.ResponseWriter, r *http.Request) {
		sess, ok := getSessionUser(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !drive.IsUnlocked(cfg) {
			http.Redirect(w, r, "/?success=Drive+is+already+locked", http.StatusSeeOther)
			return
		}

		err := drive.LockDrive(cfg)
		if err != nil {
			log.Printf("Error locking drive: %v", err)
			logger.Audit.Log("DRIVE_LOCK", sess.Username, "FAILURE")
			http.Redirect(w, r, fmt.Sprintf("/?error=Failed+to+lock+drive:+%v", err), http.StatusSeeOther)
			return
		}

		logger.Audit.Log("DRIVE_LOCK", sess.Username, "SUCCESS")
		http.Redirect(w, r, "/?success=Drive+locked+successfully", http.StatusSeeOther)
	})

	// JSON Status API
	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		sess, ok := getSessionUser(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
			return
		}

		statusStr := "LOCKED"
		unlocked := drive.IsUnlocked(cfg)
		if unlocked {
			statusStr = "UNLOCKED"
		}

		autoLockTimeLeft := 0
		if unlocked {
			ut := drive.GetUnlockTime()
			if !ut.IsZero() {
				elapsed := time.Since(ut)
				totalTimeout := time.Duration(cfg.Security.AutoLockTimeout) * time.Second
				if elapsed < totalTimeout {
					autoLockTimeLeft = int((totalTimeout - elapsed).Seconds())
				}
			}
		}

		appr := auth.GetApprovalsStatus(cfg.Security.ManagerTimeout)

		response := map[string]interface{}{
			"status":           statusStr,
			"device":           cfg.Drive.Device,
			"mapper":           cfg.Drive.Mapper,
			"mountPoint":       cfg.Drive.MountPoint,
			"manager1Approved": appr.Manager1Approved,
			"manager1TimeLeft": appr.Manager1TimeLeft,
			"manager2Approved": appr.Manager2Approved,
			"manager2TimeLeft": appr.Manager2TimeLeft,
			"autoLockTimeLeft": autoLockTimeLeft,
			"currentUser":      sess.Username,
			"currentRole":      sess.Role,
			"autoLockTimeout":  cfg.Security.AutoLockTimeout,
			"managerTimeout":   cfg.Security.ManagerTimeout,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Serving logs template on /logs
	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := getSessionUser(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		logs, err := logger.ReadAuditLog(cfg.Logging.File)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err = tmpl.ExecuteTemplate(w, "logs.html", logs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Printf("Server running on :%d", cfg.Server.Port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", cfg.Server.Port), nil)
	if err != nil {
		log.Fatalf("Server startup failed: %v", err)
	}
}
