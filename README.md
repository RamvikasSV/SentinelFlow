# SentinelFlow 🛡️

**SentinelFlow** is an asynchronous, event-driven multi-agent incident response system designed to detect, classify, investigate, and mitigate server threats in real-time. It reduces threat resolution times (MTTR) from hours to seconds by employing a crew of specialized autonomous agents.

The project features a premium cyberpunk-themed **Cyber Command Center** dashboard equipped with collapsible panels, a ChatGPT-like operator console, and Windows Snap-style layout configurations.

---

## 🚀 Key Features

* **Multi-Agent Orchestration**: Seven specialized agents collaborating asynchronously (Log Scanner, Threat Classifier, Forensic Investigator, Response Agent, Coordinator, Watchdog, and Forensic Notifier).
* **Decoupled Architecture**: Built around an in-memory Pub/Sub Event Broker that keeps agents isolated, ensuring threat spikes never block log tailing.
* **Flexible Target Adapters**: Runs in **Simulation Mode** (for quick local demos) or **Live SSH Mode** (remotely securing a real Linux VPS or local WSL2 container).
* **Multi-User Notification Registry**: Admin interface to dynamically register, list, and delete multiple email contacts. Resolves to persistent registry storage (`registered_users.json`).
* **Automated PDF Reports**: Generates a styled forensic PDF summary (using `reportlab`) enriched with geolocation mapping and automatically emails it via SMTP SSL.
* **Smart Alert Debouncing**: Intelligent 30-second deduplication cache preventing SMTP email alert storms during rapid log spikes.
* **Real-time Watchdog**: Passive filesystem observer scanning Windows/Linux hotspots for malware indicators.
* **Cyber Command Center**: Pinned three-column grid layouts with collapsible sidebars, embedded ChatGPT console, live flowchart node state animations, and scrollable markdown tables.

---

## 📊 System Architecture

```mermaid
graph TD
    %% Define components
    subgraph "Target Host (Simulated or Real Linux via SSH)"
        Logs[(Log Files: auth.log, access.log)]
        OSState[OS State: Processes, File Modifications, Sockets]
        Firewall[Firewall: iptables / ufw]
    end

    subgraph "Cyber Agent Pipeline (Python Asyncio)"
        Broker[Event Broker: Async Pub/Sub Queue]
        Scanner[Log Scanner Agent]
        Classifier[Threat Classifier Agent]
        Forensics[Forensic Investigator Agent]
        Response[Response Agent]
        Coordinator[Crew Coordinator Agent]
    end

    subgraph "Cyber Command Center (Web UI)"
        Dashboard[Real-time Web Dashboard]
        ChatInterface[ChatGPT-style Operator Chat]
    end

    %% Data Streams
    Logs -->|Tails in real-time| Scanner
    Scanner -->|Anomaly Event| Broker
    Broker -->|Dispatches Anomaly| Classifier
    Classifier -->|LLM Threat Analysis| Broker
    Broker -->|Dispatches High-Severity Incident| Forensics
    Forensics -->|Queries OS State| OSState
    Forensics -->|Forensic Evidence| Broker
    Broker -->|Dispatches Evidence| Response
    Response -->|Applies Block / Kills Process| Firewall & OSState
    Response -->|Mitigation Status| Broker
    
    %% Web Communication
    Broker <-->|WebSockets / SSE| Dashboard
    ChatInterface <-->|WebSocket Chat| Coordinator
    Coordinator <-->|Controls/Queries| Broker
```

---

## 🛠️ The Agent Crew

1. **📟 Log Scanner Agent**: Tails access and authentication logs in real-time, instantly raising alerts when signatures match brute-force or injection anomalies.
2. **🧠 Threat Classifier Agent**: Utilizes Google Gemini LLM API (enforcing strict Pydantic schemas) to analyze attack vectors, grading threat severity and confidence.
3. **🕵️‍♂️ Forensic Investigator Agent**: Connects via SSH to query active system socket states, file changes, and running process statistics.
4. **🚫 Response Agent**: Automatically enforces firewall drops (`ufw deny`), kills malicious process PIDs, and quarantines web shells.
5. **🛡️ Watchdog Filesystem Agent**: Actively monitors malware hotspots (directories and registries) on the host machine.
6. **📧 Forensic Notifier Agent**: Compiles forensic findings, attaches a generated PDF report, and emails it to all registered admins.
7. **🤖 Crew Coordinator Agent**: Bridges the administrator directly to the agent queue via a chat console, executing commands (e.g. *status*, *unblock <IP>*, *show processes*) written in natural language.

---

## 📦 Getting Started

### 1. Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/RamvikasSV/SentinelFlow.git
   cd SentinelFlow
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate   # Windows
   source venv/bin/activate  # macOS/Linux
   ```
3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### 2. Configure Environment `.env`
Create a `.env` file in the root directory:
```ini
SYSTEM_MODE=simulation          # 'simulation' or 'ssh'
GEMINI_API_KEY=your_gemini_api_key_here

# Required only if SYSTEM_MODE=ssh
SSH_HOST=127.0.0.1
SSH_PORT=22
SSH_USERNAME=your_username
SSH_PASSWORD=your_password
SSH_KEY_PATH=
```

### 3. Run the Platform
1. Launch the FastAPI server:
   ```bash
   uvicorn backend.main:app --host 127.0.0.1 --port 8000
   ```
2. Open your web browser and navigate to:
   [http://localhost:8000](http://localhost:8000)

---

## 📂 Documentation

Detailed setup guides, testing scenarios, and design specifications are stored inside the `/docs` folder:
* **[Step-by-Step Developer Guide & Handbook](docs/DEVELOPER_GUIDE.md)**: Simple, domain-friendly guide explaining all cybersecurity concepts, folder maps, and presenting the project.
* **[Technical Architecture & Build Guide](docs/PROJECT_GUIDE.md)**: Deep dive into Pub/Sub patterns, structured schemas, and adapter rationale.
* **[User Setup & Walkthrough Guide](docs/walkthrough.md)**: Includes manual test steps for simulations (SSH brute force, web shell upload) and how to configure a **local WSL2 sandbox** without a credit card.
