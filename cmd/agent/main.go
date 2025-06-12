package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sentra/internal/ai"
	"sentra/internal/alert"
	"sentra/internal/detectors"
	"strings"
)

func main() {
	alertUrl := flag.String("url", "", "Webhook or alert URL for sending alerts")
	aiActive := flag.String("botmode", "deactive", "Activate the AI Model for Analisys. Options: active or inactive")
	flag.Parse()

	mode := strings.ToLower(*aiActive)
	if mode != "active" && mode != "inactive" {
		fmt.Println("[-] Invalid botmode. Use 'active' or 'inactive'.")
		os.Exit(1)
	}

	aiModeActive := (mode == "active")

	if *alertUrl == "" {
		log.Fatal("[-] Alert URL must be provided using -url flag")
	}
	alert.SetAlertURL(*alertUrl)

	alerts := make(chan string)

	go func() {
		err := detectors.MonitorSSHLog(alerts)
		fmt.Println("Error: ", err)
		if err != nil {
			log.Fatal()
		}
	}()

	go func() {
		err := detectors.MonitorSudoersD(alerts)
		fmt.Println("Error: ", err)
		if err != nil {
			log.Fatal()
		}
	}()

	go func() {
		err := detectors.MonitorUserPrivilege(alerts)
		fmt.Println("Error: ", err)
		if err != nil {
			log.Fatal()
		}
	}()

	go func() {
		err := detectors.MonitorSUElevation(alerts)
		fmt.Println("Error: ", err)
		if err != nil {
			log.Fatal()
		}
	}()

	go func() {
		err := detectors.MonitorCronJob(alerts)
		fmt.Println("Error: ", err)
		if err != nil {
			log.Fatal()
		}
	}()

	go func() {
		err := detectors.MonitorUserCron(alerts)
		fmt.Println("Error: ", err)
		if err != nil {
			log.Fatal()
		}
	}()

	for alerting := range alerts {
		log.Println("[ALERT]", alerting)

		if aiModeActive {
			analysis, err := ai.AnalyzeAlert(alerting)
			if err != nil {
				log.Println("AI analysis failed:", err)
			} else {
				log.Println("[AI]", analysis)
			}
			alert.SendAIAnalysis(analysis)
		}
	}
}
