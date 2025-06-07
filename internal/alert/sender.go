package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Alert struct {
	Hostname    string `json:"hostname"`
	Timestamp   string `json:"timestamp"`
	AlertType   string `json:"alert_type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	RawLog      string `json:"raw_log"`
}

type AlertAI struct {
	AiAnalyst string `json:"ai_analyst"`
}

var alertURL string

func SetAlertURL(url string) {
	alertURL = url
}

func SendSSHServiceAlert(log string, description string, alert_type string, severity string) {
	hostname, _ := os.Hostname()

	alert := Alert{
		Hostname:    hostname,
		Timestamp:   time.Now().Format(time.RFC3339),
		AlertType:   alert_type,
		Severity:    severity,
		Description: description,
		RawLog:      log,
	}

	payload, _ := json.Marshal(alert)

	resp, err := http.Post(alertURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		fmt.Println("[!] Error sending alert", err)
		return
	}
	defer resp.Body.Close()
}

func SendAIAnalysis(message string) {
	payload := AlertAI{
		AiAnalyst: message,
	}

	dataSend, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", alertURL, bytes.NewBuffer(dataSend))
	if err != nil {
		fmt.Println("[!] Error parsing alert", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("[!] Error sending alert", err)
	}
	defer resp.Body.Close()
}
