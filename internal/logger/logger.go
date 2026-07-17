package logger

import (
	"fmt"
	"os"
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
	return err
}
