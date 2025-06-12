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

var (
	muSU                   sync.Mutex
	detectSuElevationRegex = regexp.MustCompile(`su: \(to (\w+)\) (\w+) on pts/\d+`)
)

func MonitorSUElevation(alerts chan<- string) error {
	muSU.Lock()
	defer muSU.Unlock()

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

		if strings.Contains(line, "su:") {

			matches := detectSuElevationRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				userTo := matches[1]
				userFrom := matches[2]
				msg := fmt.Sprintf("[!] User '%s' attempted to switch to '%s' using su", userFrom, userTo)
				alerts <- msg
				alert.SendServiceAlert(line, msg, "user_elevation", "medium")
			}
		}

	}

}
