package detectors

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sentra/internal/alert"
	"strings"
	"sync"
)

var mu sync.Mutex
var detectedUserCreationRegex = regexp.MustCompile(`useradd\[\d+\]: new user: name=(\w+), UID=\d+`)
var detectedUserElevationRegex = regexp.MustCompile(`usermod\[\d+\]: add (\w+) to group`)

func MonitorUserPrivilege(alerts chan<- string) error {
	mu.Lock()
	defer mu.Unlock()

	var logFile = "/var/log/auth.log"

	file, err := os.Open(logFile)
	if err != nil {
		return fmt.Errorf("Can't open the file: %v", err)
	}

	file.Seek(0, 2)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			continue
		}

		line = strings.ToLower(line)

		if strings.Contains(line, "useradd") || strings.Contains(line, "adduser") {
			var username string
			user := &username
			matches := detectedUserCreationRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				*user = matches[1]
			}
			msg := "[!] New user creation detected: " + username
			alerts <- msg
			alert.SendSSHServiceAlert(line, msg, "user_creation", "high")

		}

		if strings.Contains(line, "usermod") || strings.Contains(line, "gpasswd") && (strings.Contains(line, "sudo") || strings.Contains(line, "root")) {
			msg := "[!] User granted sudo/root privileges: " + line
			alerts <- msg
			alert.SendSSHServiceAlert(line, msg, "user_privilege_escalation", "high")
		}
	}
}
