package detectors

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sentra/internal/alert"
	"strings"
	"sync"
	"time"
)

var muCron sync.Mutex
var detectedNewCronRegex = regexp.MustCompile(`cron\[\d+\]: \((\w+)\) cmd \((.*)\)`)

func MonitorCronJob(alerts chan<- string) error {
	muCron.Lock()
	defer muCron.Unlock()

	var cronFile = "/var/log/syslog"
	file, err := os.Open(cronFile)
	if err != nil {
		return fmt.Errorf("Can't open the file: %v", err)
	}

	file.Seek(0, 2)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		line = strings.ToLower(line)
		if strings.Contains(line, "cron") {
			matches := detectedNewCronRegex.FindStringSubmatch(line)
			if len(matches) > 2 {
				username := matches[1]
				jobs := matches[2]
				msg := fmt.Sprintf("[!] User '%s' creating new job: '%s'", username, jobs)
				alerts <- msg
				alert.SendSSHServiceAlert(line, msg, "cron_added", "medium")
			}
		}
	}
}
