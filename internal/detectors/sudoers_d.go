package detectors

import (
	"os"
	"path/filepath"
	"sentra/internal/alert"
	"time"
)

var (
	sudoersDState = make(map[string]time.Time)
)

func MonitorSudoersD(alerts chan<- string) error {
	dir := "/etc/sudoers.d"

	for {
		files, err := filepath.Glob(filepath.Join(dir, "*"))
		if err != nil {
			msg := "[!] Error reading /etc/sudoers.d"
			alerts <- msg
			continue
		}

		current := make(map[string]time.Time)

		for _, file := range files {
			info, err := os.Stat(file)

			if err == nil {
				current[file] = info.ModTime()
				if _, ok := sudoersDState[file]; !ok {
					alerts <- "[!] New sudoers file: " + file
					msg := "New sudoers file created"
					alert.SendServiceAlert(file, msg, "added_sudoers_files", "high")
				}

				if oldTime, ok := sudoersDState[file]; ok && !current[file].Equal(oldTime) {
					alerts <- "[!] Modified sudoers file: " + file
					msg := "Sudoers file modified"
					alert.SendServiceAlert(file, msg, "modified_sudoers_file", "high")
				}
			}

		}

		for oldFile := range sudoersDState {
			if _, ok := current[oldFile]; !ok {
				alerts <- "[!] Deleted sudoers file: " + oldFile
				msg := "Sudoers file deleted"
				alert.SendServiceAlert(oldFile, msg, "modified_sudoers_file", "high")
			}
		}

		sudoersDState = current
		time.Sleep(5 * time.Second)
	}
}
