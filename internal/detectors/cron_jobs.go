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

var muCron sync.Mutex
var detectedNewCronRegex = regexp.MustCompile(`hostname cron\[\d+\]: \((\w+\)) cmd \((\.*)\)`)

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
			continue
		}

		line = strings.ToLower(line)
		if strings.Contains(line, "cron") {
			var username string
			var jobs string
			user := &username
			job := &jobs
			matches := detectedNewCronRegex.FindStringSubmatch(line)
			if len(matches) > 2 {
				*user = matches[1]
				*job = matches[2]
				msg := fmt.Sprintf("[!] User '%s' creating new job: '%s'", *user, *job)
				alerts <- msg
				alert.SendSSHServiceAlert(line, msg, "cron_added", "medium")
			}
		}
	}
}
