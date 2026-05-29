# Walkthrough Guide: Cyber Agent Command Center

We have successfully built the **Cyber Agent Multi-Agent Incident Response System**. 
Every component in the architecture (Log Scanner, Threat Classifier, Forensic Investigator, Response Agent, and Crew Coordinator) has been implemented and tested.

This walkthrough outlines how to launch the application, run attacks, chat with the agents, configure live server mode, and reviews our successful automated test run.

---

## 1. Local Setup & Launch Instructions

To launch the platform locally on your Windows machine, follow these steps:

### Step 1: Activate the Virtual Environment
Open a PowerShell terminal in the project directory (`d:\Ramvikas S V\projects\cyber agent`) and run:
```powershell
.\venv\Scripts\activate
```

### Step 2: Set your Gemini API Key (Optional but Recommended)
Open the `.env` file in the project root and replace `YOUR_GEMINI_API_KEY_HERE` with your actual Google AI Studio Gemini API Key.
*Note: If you do not provide a key, the agents will automatically detect this and fall back to the built-in local heuristics engine so that all features still run perfectly.*

### Step 3: Run the FastAPI Server
Launch the backend server using Uvicorn:
```powershell
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
You should see:
```text
==================================================
Cyber Agent Incident Response System successfully armed!
Server Adapter Mode: SIMULATION
Access the UI at: http://localhost:8000
==================================================
```

### Step 4: Open the Cyber Command Center Dashboard
Open your web browser and navigate to:
[http://localhost:8000](http://localhost:8000)

You will be greeted by the dark-themed **Cyber Command Center** featuring a customizable grid layout powered by a **Windows Snap-Assist Flyout**:
- **Header Layouts Selector (`📐 LAYOUTS`)**: Clicking this opens a visual snap assistant flyout resembling Windows Snap Assist. You can click on any of the 6 layout presets:
  1. **Standard (3-Col)**: Left logs, middle shiftable workspace, right chat console.
  2. **Logs & Chat**: 50/50 split showing only logs and chat.
  3. **Console & Chat**: Workspace and chat console (logs hidden).
  4. **Logs & Console**: Logs and middle workspace (chat hidden).
  5. **IDE Stack**: Logs full-height left, right side splits Chat on top and Workspace on bottom.
  6. **Quadrant**: Top-left logs, top-right chat, and bottom workspace spanning full screen width.
- **Interactive Collapsible Sidebars**: Click `◀` (logs) or `▶` (chat) in the panel headers to collapse side panels to 0 width smoothly. Vertical restore bars will appear on the screen edges to expand them back.

All background WebSockets, event stream tracking, and automatic mitigations continue updating in the background across all layouts.

---

## 2. Testing Attack Scenarios (Manual Walkthrough)

In **Simulation Mode** (the default), you can trigger three realistic cyber attacks by clicking the buttons in the **Attack Simulation Console** (left pane):

### Attack Vector 1: SSH Brute Force
1. Click **SSH Brute Force**.
2. **Log Stream (Left)**: Instantly scrolls, showing rapid failed password attempts from a simulated malicious external IP (e.g., `185.220.101.87`).
3. **Agent flowchart (Middle)**:
   - The **Scanner Node** flashes cyan and forwards alerts to the Classifier.
   - The **Classifier Node** flashes purple as it groups the alerts and evaluates the sliding window count. 
   - The **Forensics Node** runs a system process scan.
   - The **Response Node** flashes red and applies a firewall drop.
4. **Firewall Blocks (Right)**: The attacker's IP appears in the **Active Firewall Blocks** list.
5. **System Log Stream**: Shows `iptables[firewall]: BLOCKED traffic from 185.220.101.87`.

### Attack Vector 2: Web Shell Upload & Reverse Shell
1. Click **Web Shell Upload**.
2. **Log Stream (Left)**: Displays HTTP Nginx requests showing query scans and a POST request to `/upload.php?action=upload`.
3. **Classifier Agent**: Classifies this as a high-severity `Web Exploit`.
4. **Forensic Agent**: Scans modified files and running processes. It flags `/var/www/html/backdoor.php` as a newly uploaded file and notices a reverse shell process running as `www-data` (`/bin/sh -c sh -i >& /dev/tcp/...`).
5. **Response Agent**:
   - Blocks the attacker's IP.
   - Terminates the malicious process ID (killing the reverse shell).
   - Deletes/quarantines `backdoor.php` from the filesystem.
6. **Host Inspector (Bottom)**: Watch the process table and active connections clear the malicious lines.

### Attack Vector 3: Local Sudo Hijack
1. Click **Local Sudo Hijack**.
2. **Log Stream**: Logs a local user `alice` trying to install a malicious binary using unauthorized root privileges (`sudo: command not allowed`).
3. **Classifier Agent**: Categorizes this as a critical `Privilege Escalation` threat.
4. **Response Agent**: Flags `/etc/sudoers` modifications for manual admin audit and alerts the operator.

---

## 3. ChatGPT-style Command Console UI/UX Polish

The **Chat Command Console** (right pane) has been polished for a premium ChatGPT-like experience:
- **Glowing Quick Suggestion Chips**: Clicking the **Status**, **Processes**, **Blocked**, or **Forensics** chips instantly populates the terminal input and sends the command.
- **Pulsing Agent Typing Indicator**: Shows the `CREW_COORDINATOR` agent's thinking animation with three pulsing dots while queries are processed, clearing automatically when response data arrives.
- **Terminal Prompt Line**: Styled like a developer console with a neon-cyan prompt outline.

You can speak directly to the **Crew Coordinator Agent** in natural language or click the chips to trigger commands:
* **"status"** or clicking **Status**: Returns the current health of the agent crew, mode (Simulation/SSH), and active firewall drops.
* **"show processes"** or clicking **Processes**: Retrieves the top active host processes and prints them inside a neat markdown table directly in the chat window.
* **"show blocked"** or clicking **Blocked**: Retrieves the registry list of blocked IPs.
* **"unblock 185.220.101.87"**: Removes the IP from the blocklist.
* **"block 8.8.8.8"**: Manually triggers the Response Agent to deny incoming traffic from that IP.
* **"run forensic scan"** or clicking **Forensics**: Dispatches the Forensic Investigator Agent to run an on-demand scan.

---

## 4. Deploying on a Real Production Server (Live VPS Mode)

To protect or run tests on a real Linux server (e.g., an Ubuntu VPS on AWS, DigitalOcean, or Azure), or to test it locally for free without a credit card using WSL2, choose one of the options below:

### Option A: Using a Cloud VPS (DigitalOcean / AWS / GCP)
*Best if you have a cloud account and want to test remote server connection.*

#### 1. Prerequisites (What you need)
- **A Linux VPS**: An Ubuntu 20.04/22.04 server with a public IP address.
- **SSH Credentials**: Host IP address, port (default `22`), root or admin username, and a password or private SSH key file (`.pem`).
- **Sudo Privileges**: The user account you connect with must have sudo access to execute firewall rules and process controls.

#### 2. Setup Guide
1. **Prepare the VPS**: Log into the VPS via SSH and install the Nginx package:
   ```bash
   sudo apt update
   sudo apt install -y nginx
   ```
2. **Configure UFW Firewall**: Allow ports BEFORE activating to prevent lockouts:
   ```bash
   sudo ufw allow 22/tcp    # Allows SSH connections (CRITICAL!)
   sudo ufw allow 80/tcp    # Allows HTTP web traffic
   sudo ufw --force enable  # Enables firewall
   ```
3. **Update `.env`**: Fill in your VPS server details:
   ```ini
   SYSTEM_MODE=ssh
   SSH_HOST=your_vps_ip_here
   SSH_PORT=22
   SSH_USERNAME=root
   SSH_PASSWORD=your_vps_password
   SSH_KEY_PATH=
   ```

---

### Option B: Local WSL2 Sandbox (Free, No Credit Card Required)
*Best if you want to test live SSH mode locally on your Windows 11 machine without signing up for cloud services.*

#### 1. Setup WSL2 Linux Environment
1. Open Windows PowerShell as Administrator and run:
   ```powershell
   wsl --install
   ```
2. Once the installation completes, **restart your computer**.
3. Upon reboot, a Linux window will open. Create a **Username** (e.g. `devuser`) and **Password** (e.g. `mypassword`).

#### 2. Install SSH Server and Nginx
In your WSL Linux window, run:
```bash
sudo apt update
sudo apt install -y openssh-server nginx
```

#### 3. Enable Password Authentication
1. Open the SSH daemon configuration file:
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```
2. Scroll down and find the line `PasswordAuthentication no` (or `#PasswordAuthentication yes`).
3. Change it to:
   ```text
   PasswordAuthentication yes
   ```
4. Save and exit (Press `Ctrl + O` then `Enter`, then `Ctrl + X`).
5. Start the SSH service:
   ```bash
   sudo service ssh start
   ```

#### 4. Configure `.env`
Update your local `.env` file to connect to your local WSL environment:
```ini
SYSTEM_MODE=ssh
SSH_HOST=127.0.0.1
SSH_PORT=22
SSH_USERNAME=devuser        # <-- Put your WSL username here
SSH_PASSWORD=mypassword     # <-- Put your WSL password here
SSH_KEY_PATH=
```

---

### 5. Critical Warnings & Safety Rules

> [!WARNING]
> **Self-Lockout Danger**: When running in `ssh` mode, the Response Agent applies real UFW/iptables rules. **Never trigger SSH brute-force attack simulations pointing to your own public IP address**; otherwise, the firewall will block your own network, locking you out of the server. 
> * If you get locked out of your cloud VPS, log in via your provider's Recovery Web Console and run `sudo ufw disable`.

> [!CAUTION]
> **Cloud Billing Costs**: Cloud instances like DigitalOcean Droplets are billed by the hour as long as they exist. Once you are finished testing, make sure to click **Destroy** next to your Droplet inside the web portal to stop all billing charges.

---

## 5. Automated Verification Test Logs

We verified the agent pipeline using our integration test script (`test_pipeline.py`). The script successfully ran the end-to-end SSH brute force mitigation flow in a headless testing environment:

```text
D:\Ramvikas S V\projects\cyber agent> .\venv\Scripts\python backend\test_pipeline.py
[TEST] Starting End-to-End Incident Response Integration Test...
[TEST] All agents started. Injected standard noise...
[TEST] Triggering SSH Brute Force Attack simulation...
   [Agent Thought - log_scanner]: Log Scanner Agent active. Tailing /var/log/auth.log and /var/log/nginx/access.log...
   [Agent Thought - threat_classifier]: Threat Classifier Agent active. Listening for log alerts...
   [Agent Thought - forensics_investigator]: Forensic Investigator Agent active. Ready to run system scans...
   [Agent Thought - response_agent]: Response Agent active. Monitoring forensic evidence for action playbooks...
[TEST] Captured pipeline stage: LOG_ALERT
   [Agent Thought - log_scanner]: Anomaly flagged: Suspicious SSH login failure for user 'admin' from 185.220.101.87. Triggering Threat Classifier.
   [Agent Thought - threat_classifier]: Analyzing threat profile for IP: 185.220.101.87. Active alerts in 60s window: 1
[TEST] Captured pipeline stage: THREAT_CLASSIFICATION
   [Agent Thought - threat_classifier]: Classification complete for 185.220.101.87: Category=Reconnaissance, Severity=MEDIUM. Dispatching Forensic Investigator Agent.
   [Agent Thought - forensics_investigator]: Initiating live forensics on target server for IP: 185.220.101.87. Category: Reconnaissance.
[TEST] Captured pipeline stage: LOG_ALERT
   [Agent Thought - log_scanner]: Anomaly flagged: Suspicious SSH login failure for user 'ubnt' from 185.220.101.87. Triggering Threat Classifier.
   [Agent Thought - threat_classifier]: Analyzing threat profile for IP: 185.220.101.87. Active alerts in 60s window: 2
[TEST] Captured pipeline stage: THREAT_CLASSIFICATION
   [Agent Thought - threat_classifier]: Classification complete for 185.220.101.87: Category=Reconnaissance, Severity=MEDIUM. Dispatching Forensic Investigator Agent.
   [Agent Thought - forensics_investigator]: Initiating live forensics on target server for IP: 185.220.101.87. Category: Reconnaissance.
   [Agent Thought - forensics_investigator]: Forensics completed. Sockets=0, Processes=0, Files=0. Routing evidence to Response Agent.
[TEST] Captured pipeline stage: FORENSIC_INVESTIGATION
   [Agent Thought - response_agent]: Remediation playbook triggered for 185.220.101.87. Evaluating mitigation steps...
[TEST] Captured pipeline stage: LOG_ALERT
   [Agent Thought - log_scanner]: Anomaly flagged: Suspicious SSH login failure for user 'test' from 185.220.101.87. Triggering Threat Classifier.
   [Agent Thought - threat_classifier]: Analyzing threat profile for IP: 185.220.101.87. Active alerts in 60s window: 3
[TEST] Captured pipeline stage: THREAT_CLASSIFICATION
   [Agent Thought - threat_classifier]: Classification complete for 185.220.101.87: Category=SSH Brute Force, Severity=HIGH. Dispatching Forensic Investigator Agent.
   [Agent Thought - forensics_investigator]: Initiating live forensics on target server for IP: 185.220.101.87. Category: SSH Brute Force.
   [Agent Thought - forensics_investigator]: Forensics completed. Sockets=0, Processes=0, Files=0. Routing evidence to Response Agent.
[TEST] Captured pipeline stage: FORENSIC_INVESTIGATION
   [Agent Thought - response_agent]: Mitigations completed with status: SUCCESS. Actions count: 1. System integrity re-established. Generating report.
[TEST] Captured pipeline stage: REMEDIATION
[TEST] Success: End-to-end incident response pipeline completed successfully!

--- Final Test Audit Report ---
Log Alerts Created:      Yes
Threats Classified:      Yes
Forensics Run:           Yes
Remediation Triggered:   Yes
Blocked IPs in Firewall: ['185.220.101.87']

[TEST] INTEGRATION TEST PASSED!
```
