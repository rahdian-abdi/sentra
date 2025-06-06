
---
# 🤖 Sentra: AI-Powered Threat Detection Agent

**Sentra** is a modular security agent, written in **Go** providing unified security monitoring for both Linux and Windows servers, regardless of their location. It performs real-time log analysis and sends alerts to a central ingestion server.

When enabled, the agent can leverage the **OpenAI API** to provide intelligent, contextual analysis on alerts, acting as a preliminary AI security analyst to help you identify threats faster.

---

## Architecture Overview

The Sentra project consists of two main components:
1.  **The Agent (`sentra`):** A Go binary that runs on a target machine, monitors for threats, and sends alerts.
2.  **The Ingestion Server:** A web server that listens for incoming alerts from one or more agents. You can build your own, or use the example Flask server provided in this repository.

---

## Key Features

* ✅ **Real-Time Log Monitoring**: Actively watches critical system logs for events defined in a flexible ruleset.
* 🧠 **Optional AI Analysis**: Can be configured to enrich alerts via the OpenAI API, adding context and reducing investigation time.
* 🔧 **Flexible Configuration**: Uses command-line flags to easily configure behavior, such as toggling AI mode and setting the alert destination.
* ☁️ **Cloud-Ready**: Lightweight and container-friendly, built to run on any Linux virtual machine (AWS, GCP, Azure, etc.).

---

## Tech Stack

* **Agent**: **Go** (Golang)
* **AI Integration**: **OpenAI API**
* **Example Ingestion Server**: **Python & Flask**

---

## Getting Started

Follow these instructions to get a local copy up and running for development and testing.

### Prerequisites

* Go `1.21` or later
* An OpenAI API Key (if using `-botmode active`)
* Python 3.x and Flask (to run the example ingestion server)

### Configuration & Setup

1.  **Clone the Repository**
    ```sh
    git clone https://github.com/rahdian-abdi/sentra.git
    cd sentra
    ```
2.  **Set the Environment Variable (for AI Mode)**

    If you plan to use the AI analysis feature, you must set your OpenAI API key as an environment variable.
    ```sh
    export OPENAI_API_KEY="your_secret_api_key_here"
    ```
    **Note:** This sets the variable for your current terminal session only. To make it permanent, add the line to your shell's startup file (e.g., `~/.bashrc`, `~/.zshrc`).

3.  **Build the Agent**

    Compile the agent from the source code, example from linux:
    ```sh
    GOOS="linux" GOARCH="amd64" go build -o sentra
    ```

---

## Usage

The agent is configured at runtime using command-line flags.

| Flag | Description | Accepted Values | Default |
| :--- | :--- | :--- | :--- |
| **`-botmode`** | Toggles the AI analysis feature. If `active`, an OpenAI API key must be set as an environment variable. | `active`, `inactive` | `inactive` |
| **`-url`** | The full URL of the ingestion server endpoint where alerts will be sent. | A valid HTTP URL | `(Required)` |

### Example

```sh
# Run the agent with AI analysis enabled, sending alerts to a local server
./sentra -botmode active -url http://127.0.0.1:8081/ingest

# Run the agent without AI analysis, sending to a remote server
./sentra -botmode inactive -url http://192.168.1.6:8081/ingest
```

---

## Example Ingestion Server (Flask)

You need a server to receive the alerts sent by the agent. Here is a simple example using Python and Flask.

1.  **Install Flask:**
    ```sh
    pip install Flask
    ```
2.  **Create `receiver.py`:**
    ```python
    from flask import Flask, request, jsonify

    app = Flask(__name__)

    @app.route('/ingest', methods=['POST'])
    def ingest_alert():
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400

        alert_data = request.get_json()
        
        # Process the alert here (e.g., print to console, save to DB, etc.)
        print("Received alert:")
        print(jsonify(alert_data).get_data(as_text=True))
        
        return jsonify({"status": "success", "message": "Alert received"}), 200

    if __name__ == '__main__':
        # Listens on 0.0.0.0 to be accessible from other machines on the network
        app.run(host='0.0.0.0', port=8081, debug=True)

    ```
3.  **Run the Server:**
    Open a *new terminal* and run the Flask app. This server will now be listening for alerts from your agent.
    ```sh
    python receiver.py
    ```

---

## Roadmap

* **Windows Support**: Expand agent capabilities to monitor Windows-based VMs.
* **Richer Detection Rules**: Develop a more comprehensive library of default detection rules.
* **Output Integrations**: Add support for sending alerts from the receiver to platforms like Slack or a SIEM.
* **Secure Communication**: Implement mTLS for secure agent-to-server communication.
