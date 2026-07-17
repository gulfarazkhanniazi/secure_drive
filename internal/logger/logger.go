package logger

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

type Logger struct {
	File string
}

var Audit *Logger

func InitLogger(path string) {
	Audit = &Logger{
		File: path,
	}
	// Try to apply append-only attribute at startup
	Audit.makeAppendOnly()
}

func (l *Logger) makeAppendOnly() {
	// Execute chattr +a to set append-only attribute.
	// On non-Linux/ext4 environments this will fail, which we ignore.
	_ = exec.Command("chattr", "+a", l.File).Run()
}

func (l *Logger) Log(action, user, status string) error {
	file, err := os.OpenFile(
		l.File,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return err
	}
	defer file.Close()

	entry := fmt.Sprintf(
		"[%s] USER=%s ACTION=%s STATUS=%s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		user,
		action,
		status,
	)

	_, err = file.WriteString(entry)
	if err != nil {
		return err
	}

	// Apply append-only attribute again
	l.makeAppendOnly()
	return nil
}

