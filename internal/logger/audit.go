package logger

import (
	"bufio"
	"os"
	"regexp"
)

type AuditEntry struct {
	Timestamp string
	User      string
	Action    string
	Status    string
	Raw       string
}

var logPattern = regexp.MustCompile(`^\[(.*?)\] USER=(.*?) ACTION=(.*?) STATUS=(.*?)$`)

func ReadAuditLog(path string) ([]AuditEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var logs []AuditEntry
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		matches := logPattern.FindStringSubmatch(line)
		if len(matches) == 5 {
			logs = append(logs, AuditEntry{
				Timestamp: matches[1],
				User:      matches[2],
				Action:    matches[3],
				Status:    matches[4],
				Raw:       line,
			})
		} else {
			logs = append(logs, AuditEntry{
				Raw: line,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Reverse the logs so that newest logs are on top
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	return logs, nil
}
