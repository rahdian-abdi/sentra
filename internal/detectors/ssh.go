package detectors

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"sentra/internal/alert"
)

var (
	failedLoginRegex    = regexp.MustCompile(`Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)`)
	successLoginRegex   = regexp.MustCompile(`Accepted (password|publickey) for (\S+) from ([\d\.]+) port \d+ ssh2`)
	bruteForceThreshold = 5
	bruteForceWindow    = 1 * time.Minute
)

type attemptInfo struct {
	count     int
	firstSeen time.Time
}

var (
	muFail   sync.Mutex
	attempts = make(map[string]*attemptInfo)
)

var (
	muSuccess sync.Mutex
	knownIPs  = make(map[string]struct{})
)

func MonitorSSHLog(alerts chan<- string) error {
	var logFile = "/var/log/auth.log"
	file, err := os.Open(logFile)
	if err != nil {
		return fmt.Errorf("cannot open log file: %v", err)
	}

	file.Seek(0, 2)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err == nil && strings.Contains(line, "Failed password") {
			matches := failedLoginRegex.FindStringSubmatch(line)
			if len(matches) >= 4 {
				ip := matches[3]
				handleFailedAttempt(ip, line, alerts)
			}
		} else if err == nil && strings.Contains(line, "Accepted password") {
			matches := successLoginRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				username := matches[2]
				ip := matches[3]
				handleSuccessLogin(username, ip, line, alerts)
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func handleFailedAttempt(ip string, line string, alerts chan<- string) {
	muFail.Lock()
	defer muFail.Unlock()

	now := time.Now()
	info, exist := attempts[ip]

	if !exist || now.Sub(info.firstSeen) > bruteForceWindow {
		attempts[ip] = &attemptInfo{count: 1, firstSeen: now}
	} else {
		info.count++
		if info.count >= bruteForceThreshold {
			msg := fmt.Sprintf("SSH brute force detected from IP: %s with %d failed attempts", ip, info.count)
			alert.SendServiceAlert(line, msg, "brute_force_attempt", "high")
			alerts <- msg
			delete(attempts, ip)
		}
	}
}

func handleSuccessLogin(username string, ip string, line string, alerts chan<- string) {
	muSuccess.Lock()
	defer muSuccess.Unlock()

	if _, exists := knownIPs[ip]; !exists {
		alertMsg := fmt.Sprintf("New successful SSH login from IP %s (user: %s) at %s", ip, username, time.Now().Format(time.RFC3339))
		alert.SendServiceAlert(line, alertMsg, "success_login", "high")
		alerts <- alertMsg
	} else {
		alertMsg := fmt.Sprintf("Repeated successful login from known IP %s (user: %s)", ip, username)
		alert.SendServiceAlert(line, alertMsg, "repeated_success_login", "low")
		alerts <- alertMsg
	}
}
