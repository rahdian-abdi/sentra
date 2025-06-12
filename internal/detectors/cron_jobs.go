package detectors

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"sentra/internal/alert"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
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
				alert.SendServiceAlert(line, msg, "cron_added", "medium")
			}
		}
	}
}

func MonitorUserCron(alerts chan<- string) error {
	path := "/var/spool/cron/crontab"

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %v", err)
	}
	defer watcher.Close()

	err = watcher.Add(path)
	if err != nil {
		return fmt.Errorf("failed to add path to watcher: %v", err)
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			if event.Op&fsnotify.Create == fsnotify.Create ||
				event.Op&fsnotify.Write == fsnotify.Write ||
				event.Op&fsnotify.Rename == fsnotify.Rename {

				username := getUsernameFromPath(event.Name)
				msg := fmt.Sprintf("[!] New or modified user cron job detected: %s", event.Name)
				alerts <- msg
				alert.SendServiceAlert(event.Name, msg, "user_cron_added", "high")

				log.Println(msg, "| User:", username)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Println("watcher error:", err)
		}
	}
}

func getUsernameFromPath(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return "unknown"
	}
	return fi.Name()
}
